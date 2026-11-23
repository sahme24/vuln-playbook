"""Apply playbook/triage-rules.yaml to grouped findings.

Two stages (see the comments at the top of triage-rules.yaml):

  recon   python scripts/triage.py --stage recon
          Splits grouped.json into findings to open as issues
          (to_open.json) and findings excluded before the board
          (excluded.json, with the rule that fired).

  verify  python scripts/triage.py --stage verify --plugin-id 900104
          Uses the enrichment files for one finding and writes the verdict,
          the rule that fired, its confidence and the evidence list to
          engagement/output/triage/<plugin_id>.json.

How a verdict is reached:
  1. build_*_facts() reduces the finding plus its enrichment data to a small
     dict of plain facts (kev: true, banner_only: false, ...).
  2. evaluate() walks the rules in file order and returns the first rule
     whose conditions all hold for those facts.
Keeping the facts separate from the rules means each rule is a simple
lookup, and the facts themselves can be checked in tests.

Triage never guesses: missing enrichment data raises ValueError ("run the
enrichers first") instead of being treated as "not in KEV" or similar.
"""

import argparse
import json
import os
import re
from datetime import date

import yaml

import group_findings
import scope

STAGES = ["recon", "verify"]
ACTIONS = {
    "recon": ["exclude"],
    "verify": ["verified", "false-positive", "accepted-risk", "appendix", "needs-human"],
}
CONFIDENCE_LEVELS = ["high", "medium", "low"]
VENDOR_STATUSES = ["fixed", "not-affected", "affected", "unknown"]

# Condition name -> the kind of value it takes.
CONDITION_TYPES = {
    "severity_in": "int_list",
    "plugin_id_in": "int_list",
    "has_cve": "bool",
    "kev": "bool",
    "banner_only": "bool",
    "backport_distro": "bool",
    "vendor_status": "vendor_status",
    "accepted_risk": "bool",
}
# At recon time no enrichment has run yet, so only these can be known.
RECON_CONDITIONS = ["severity_in", "plugin_id_in", "has_cve"]

RULE_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]*")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
ENRICHMENT_SOURCES = ["nvd", "kev", "epss", "vendor"]
TENABLE_PLUGIN_URL = "https://www.tenable.com/plugins/nessus/"


# --- loading and validating the rules file ----------------------------------

def validate_string_list(value, field_name):
    if type(value) is not list or len(value) == 0:
        raise ValueError(field_name + " must be a non-empty list of strings")
    for item in value:
        if type(item) is not str or item.strip() == "":
            raise ValueError(field_name + " must contain only non-empty strings")


def validate_condition(rule_name, condition, value):
    if condition not in CONDITION_TYPES:
        raise ValueError(
            "rule " + rule_name + ": unknown condition " + repr(condition)
            + "; expected one of: " + ", ".join(CONDITION_TYPES)
        )
    kind = CONDITION_TYPES[condition]
    if kind == "bool":
        if type(value) is not bool:
            raise ValueError("rule " + rule_name + ": " + condition + " must be true or false")
    elif kind == "int_list":
        if type(value) is not list or len(value) == 0:
            raise ValueError("rule " + rule_name + ": " + condition + " must be a non-empty list")
        for item in value:
            if type(item) is not int:
                raise ValueError("rule " + rule_name + ": " + condition + " must list integers")
    elif kind == "vendor_status":
        if value not in VENDOR_STATUSES:
            raise ValueError(
                "rule " + rule_name + ": vendor_status must be one of " + ", ".join(VENDOR_STATUSES)
            )


def validate_rule(rule, position, seen_names):
    if type(rule) is not dict:
        raise ValueError("rule #" + str(position) + " must be a mapping")
    for field in ["name", "stage", "action", "confidence", "reason", "when"]:
        if field not in rule:
            raise ValueError("rule #" + str(position) + " is missing '" + field + "'")

    name = rule["name"]
    if type(name) is not str or RULE_NAME_PATTERN.fullmatch(name) is None:
        raise ValueError("rule #" + str(position) + ": name must be snake_case, got " + repr(name))
    if name in seen_names:
        raise ValueError("rule name " + name + " is used twice; names must be unique")
    if rule["stage"] not in STAGES:
        raise ValueError("rule " + name + ": stage must be 'recon' or 'verify'")
    if rule["action"] not in ACTIONS[rule["stage"]]:
        raise ValueError(
            "rule " + name + ": action " + repr(rule["action"]) + " is not allowed in stage "
            + rule["stage"] + " (allowed: " + ", ".join(ACTIONS[rule["stage"]]) + ")"
        )
    if rule["confidence"] not in CONFIDENCE_LEVELS:
        raise ValueError("rule " + name + ": confidence must be high, medium or low")
    if type(rule["reason"]) is not str or rule["reason"].strip() == "":
        raise ValueError("rule " + name + ": reason must be a non-empty string")
    if type(rule["when"]) is not dict:
        raise ValueError("rule " + name + ": 'when' must be a mapping (use {} for always)")

    for condition in rule["when"]:
        validate_condition(name, condition, rule["when"][condition])
        if rule["stage"] == "recon" and condition not in RECON_CONDITIONS:
            raise ValueError(
                "rule " + name + ": condition " + condition + " needs enrichment data, "
                "which does not exist yet at the recon stage"
            )

    # Code-level guard for "never mark a KEV CVE a false positive without
    # a human": a false-positive rule must explicitly exclude KEV findings.
    if rule["action"] == "false-positive":
        if "kev" not in rule["when"] or rule["when"]["kev"] is not False:
            raise ValueError(
                "rule " + name + ": a false-positive rule must include 'kev: false', so a "
                "KEV-listed CVE can never be dismissed without a human"
            )


def validate_rules(data):
    """Check the whole rules file. Raises ValueError on the first problem."""
    if type(data) is not dict:
        raise ValueError("triage rules file must be a YAML mapping")
    for field in ["banner_phrases", "backport_distros", "rules"]:
        if field not in data:
            raise ValueError("triage rules file is missing '" + field + "'")
    validate_string_list(data["banner_phrases"], "banner_phrases")
    validate_string_list(data["backport_distros"], "backport_distros")
    if type(data["rules"]) is not list or len(data["rules"]) == 0:
        raise ValueError("'rules' must be a non-empty list")

    seen_names = []
    last_verify_rule = None
    position = 0
    for rule in data["rules"]:
        validate_rule(rule, position, seen_names)
        seen_names.append(rule["name"])
        if rule["stage"] == "verify":
            last_verify_rule = rule
        position = position + 1

    # Every finding must get a verdict: the final verify rule is a catch-all.
    if last_verify_rule is None:
        raise ValueError("there must be at least one verify-stage rule")
    if len(last_verify_rule["when"]) != 0:
        raise ValueError(
            "the last verify rule (" + last_verify_rule["name"] + ") must have an empty 'when' "
            "so that every finding gets a verdict"
        )
    return True


def load_rules(path):
    if type(path) is not str or not os.path.isfile(path):
        raise ValueError("triage rules file not found: " + repr(path))
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    validate_rules(data)
    return data


# --- accepted risks ----------------------------------------------------------

def parse_expiry(value, position):
    """Accept "2027-06-30" (string) or a YAML date object. None means no expiry."""
    if value is None:
        return None
    if type(value) is date:
        return value
    if type(value) is str:
        try:
            return date.fromisoformat(value)
        except ValueError:
            raise ValueError("accepted_risks #" + str(position) + ": expires must be YYYY-MM-DD")
    raise ValueError("accepted_risks #" + str(position) + ": expires must be a date like 2027-06-30")


def load_accepted_risks(engagement):
    """Validate engagement.yaml's accepted_risks list and return it, with
    each `expires` converted to a date (or None)."""
    if type(engagement) is not dict or "accepted_risks" not in engagement:
        raise ValueError("engagement.yaml has no accepted_risks list (write 'accepted_risks: []' if none)")
    entries = engagement["accepted_risks"]
    if type(entries) is not list:
        raise ValueError("accepted_risks must be a list (use [] for none)")

    validated = []
    position = 0
    for entry in entries:
        if type(entry) is not dict:
            raise ValueError("accepted_risks #" + str(position) + " must be a mapping")
        has_plugin = "plugin_id" in entry
        has_cve = "cve" in entry
        if has_plugin == has_cve:
            raise ValueError("accepted_risks #" + str(position) + " must name exactly one of plugin_id or cve")
        if has_plugin and type(entry["plugin_id"]) is not int:
            raise ValueError("accepted_risks #" + str(position) + ": plugin_id must be an integer")
        if has_cve and (type(entry["cve"]) is not str or CVE_PATTERN.fullmatch(entry["cve"]) is None):
            raise ValueError("accepted_risks #" + str(position) + ": cve must look like CVE-2021-44228")
        for field in ["accepted_by", "reference"]:
            if field not in entry or type(entry[field]) is not str or entry[field].strip() == "":
                raise ValueError("accepted_risks #" + str(position) + ": '" + field + "' is required")

        plugin_id = None
        cve = None
        if has_plugin:
            plugin_id = entry["plugin_id"]
        else:
            cve = entry["cve"]
        validated.append({
            "plugin_id": plugin_id,
            "cve": cve,
            "accepted_by": entry["accepted_by"],
            "reference": entry["reference"],
            "expires": parse_expiry(entry.get("expires"), position),
            "reason": entry.get("reason"),
        })
        position = position + 1
    return validated


def matching_acceptances(group, accepted_risks, today):
    """Return the accepted-risk entries that cover this finding today.
    An entry past its expiry date no longer applies."""
    if type(today) is not date:
        raise ValueError("today must be a datetime.date")
    matches = []
    for entry in accepted_risks:
        if entry["expires"] is not None and today > entry["expires"]:
            continue
        if entry["plugin_id"] is not None and entry["plugin_id"] == group["plugin_id"]:
            matches.append(entry)
        elif entry["cve"] is not None and entry["cve"] in group["cves"]:
            matches.append(entry)
    return matches


# --- facts --------------------------------------------------------------------

def is_banner_only(group, banner_phrases):
    if group["description"] is None:
        return False
    description = group["description"].lower()
    for phrase in banner_phrases:
        if phrase.lower() in description:
            return True
    return False


def is_backport_distro(group, backport_distros):
    """True if ANY affected host runs a backporting distribution."""
    for entry in group["affected"]:
        if entry["operating_system"] is None:
            continue
        os_name = entry["operating_system"].lower()
        for distro in backport_distros:
            if distro.lower() in os_name:
                return True
    return False


def combine_vendor_status(cves, vendor_records):
    """Combine per-CVE vendor statuses into one status for the finding.

    The finding is vulnerable if ANY of its CVEs is, so:
      any CVE "affected"               -> "affected"
      else any CVE "fixed"             -> "fixed"
      else EVERY CVE "not-affected"    -> "not-affected"
      else                             -> "unknown"
    "not-affected" needs every CVE covered. One CVE with no data is enough
    to stop it, because "not affected" can lead to a false-positive verdict.
    """
    if len(cves) == 0 or len(vendor_records) == 0:
        return "unknown"
    statuses_by_cve = {}
    for cve in cves:
        statuses_by_cve[cve] = []
    for record in vendor_records:
        if record["cve"] in statuses_by_cve:
            statuses_by_cve[record["cve"]].append(record["status"])

    any_affected = False
    any_fixed = False
    all_not_affected = True
    for cve in cves:
        statuses = statuses_by_cve[cve]
        if "affected" in statuses:
            any_affected = True
        if "fixed" in statuses:
            any_fixed = True
        if len(statuses) == 0:
            all_not_affected = False
        for status in statuses:
            if status != "not-affected":
                all_not_affected = False

    if any_affected:
        return "affected"
    if any_fixed:
        return "fixed"
    if all_not_affected:
        return "not-affected"
    return "unknown"


def build_recon_facts(group):
    return {
        "plugin_id": group["plugin_id"],
        "severity": group["severity"],
        "has_cve": len(group["cves"]) > 0,
    }


def build_verify_facts(group, enrichment, rules_data, acceptances):
    """Reduce one finding and its enrichment data to the facts the rules test."""
    for source in ENRICHMENT_SOURCES:
        if source not in enrichment:
            raise ValueError("enrichment data is missing '" + source + "'; run enrich_" + source + ".py first")

    kev_cves = []
    for cve in group["cves"]:
        if cve not in enrichment["kev"]:
            raise ValueError("no KEV result for " + cve + "; run enrich_kev.py for this finding first")
        if enrichment["kev"][cve]["in_kev"] is True:
            kev_cves.append(cve)

    return {
        "plugin_id": group["plugin_id"],
        "severity": group["severity"],
        "has_cve": len(group["cves"]) > 0,
        "kev": len(kev_cves) > 0,
        "kev_cves": kev_cves,
        "banner_only": is_banner_only(group, rules_data["banner_phrases"]),
        "backport_distro": is_backport_distro(group, rules_data["backport_distros"]),
        "vendor_status": combine_vendor_status(group["cves"], enrichment["vendor"]["records"]),
        "accepted_risk": len(acceptances) > 0,
    }


# --- evaluation ---------------------------------------------------------------

def rule_matches(rule, facts):
    """True if every condition in the rule's `when` holds for the facts."""
    for condition in rule["when"]:
        expected = rule["when"][condition]
        if condition == "severity_in":
            if facts["severity"] not in expected:
                return False
        elif condition == "plugin_id_in":
            if facts["plugin_id"] not in expected:
                return False
        else:
            if condition not in facts:
                raise ValueError("fact " + condition + " is not available at this stage")
            if facts[condition] != expected:
                return False
    return True


def evaluate(stage, facts, rules_data):
    """Return the first matching rule of this stage as
    {"verdict", "rule", "confidence", "reason"}.

    At the verify stage the catch-all rule guarantees a match. At the recon
    stage no match means the finding is opened as an issue (verdict "open").
    """
    if stage not in STAGES:
        raise ValueError("stage must be 'recon' or 'verify'")
    for rule in rules_data["rules"]:
        if rule["stage"] != stage:
            continue
        if rule_matches(rule, facts):
            return {
                "verdict": rule["action"],
                "rule": rule["name"],
                "confidence": rule["confidence"],
                "reason": rule["reason"],
            }
    if stage == "recon":
        return {"verdict": "open", "rule": None, "confidence": None, "reason": None}
    raise ValueError("no verify rule matched; the rules file must end with a catch-all rule")


def build_evidence(group, enrichment, acceptances):
    """Collect the evidence items behind a verdict, as structured data.

    Each item has a source and a URL (when one exists) plus the facts taken
    from that source. The verifier turns these into the Evidence lines of its
    handoff block.
    """
    evidence = [{
        "source": "tenable",
        "url": TENABLE_PLUGIN_URL + str(group["plugin_id"]),
        "plugin_id": group["plugin_id"],
        "plugin_type": group["plugin_type"],
    }]
    for cve in group["cves"]:
        nvd = enrichment["nvd"].get(cve)
        if nvd is not None:
            evidence.append({
                "source": "nvd", "cve": cve, "url": nvd["nvd_url"],
                "found": nvd["found"],
                "cvss3_score": nvd.get("cvss3_score"),
                "cvss3_severity": nvd.get("cvss3_severity"),
                "cvss3_vector": nvd.get("cvss3_vector"),
            })
        kev = enrichment["kev"].get(cve)
        if kev is not None and kev["in_kev"] is True:
            evidence.append({
                "source": "kev", "cve": cve, "url": kev.get("catalog_url"),
                "date_added": kev.get("date_added"), "due_date": kev.get("due_date"),
                "known_ransomware_use": kev.get("known_ransomware_use"),
            })
        epss = enrichment["epss"].get(cve)
        if epss is not None and epss["found"] is True:
            evidence.append({
                "source": "epss", "cve": cve, "url": None,
                "epss": epss["epss"], "percentile": epss["percentile"], "date": epss["date"],
            })
    for record in enrichment["vendor"]["records"]:
        evidence.append({
            "source": "vendor_" + record["vendor"], "cve": record["cve"], "url": record["url"],
            "release": record["release"], "package": record["package"],
            "status": record["status"], "fixed_version": record["fixed_version"],
            "details": record["details"], "lookup_error": record["lookup_error"],
        })
    for entry in acceptances:
        expires = None
        if entry["expires"] is not None:
            expires = entry["expires"].isoformat()
        evidence.append({
            "source": "accepted_risk", "url": None,
            "reference": entry["reference"], "accepted_by": entry["accepted_by"],
            "expires": expires, "reason": entry["reason"],
        })
    return evidence


def triage_recon(groups, rules_data):
    """Split groups into {"to_open": [groups], "excluded": [summaries]}."""
    if type(groups) is not list:
        raise ValueError("groups must be a list")
    to_open = []
    excluded = []
    for group in groups:
        result = evaluate("recon", build_recon_facts(group), rules_data)
        if result["verdict"] == "exclude":
            excluded.append({
                "plugin_id": group["plugin_id"],
                "plugin_name": group["plugin_name"],
                "severity": group["severity"],
                "host_count": group["host_count"],
                "rule": result["rule"],
                "reason": result["reason"],
            })
        else:
            to_open.append(group)
    return {"to_open": to_open, "excluded": excluded}


def triage_verify(group, enrichment, rules_data, accepted_risks, today):
    """Return the verdict for one finding, with its facts and evidence."""
    acceptances = matching_acceptances(group, accepted_risks, today)
    facts = build_verify_facts(group, enrichment, rules_data, acceptances)
    result = evaluate("verify", facts, rules_data)
    return {
        "plugin_id": group["plugin_id"],
        "plugin_name": group["plugin_name"],
        "stage": "verify",
        "verdict": result["verdict"],
        "rule": result["rule"],
        "confidence": result["confidence"],
        "reason": result["reason"],
        "facts": facts,
        "evidence": build_evidence(group, enrichment, acceptances),
    }


def load_enrichment(output_dir, plugin_id):
    """Read the four enrichment files written for one finding."""
    folder = os.path.join(output_dir, "enrichment", str(plugin_id))
    enrichment = {}
    for source in ENRICHMENT_SOURCES:
        path = os.path.join(folder, source + ".json")
        if not os.path.isfile(path):
            raise ValueError(
                "missing " + path + "; run enrich_" + source + ".py --plugin-id " + str(plugin_id) + " first"
            )
        with open(path, "r", encoding="utf-8") as handle:
            enrichment[source] = json.load(handle)
    return enrichment


def write_json(path, data):
    folder = os.path.dirname(path)
    if folder != "":
        os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Apply triage-rules.yaml to grouped findings.")
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--plugin-id", type=int, default=None, help="required for --stage verify")
    parser.add_argument("--grouped", default="engagement/output/grouped.json")
    parser.add_argument("--rules", default="playbook/triage-rules.yaml")
    parser.add_argument("--engagement", default="engagement.yaml")
    parser.add_argument("--output-dir", default="engagement/output")
    args = parser.parse_args()

    rules_data = load_rules(args.rules)

    if args.stage == "recon":
        groups = group_findings.load_groups(args.grouped, None)
        result = triage_recon(groups, rules_data)
        write_json(os.path.join(args.output_dir, "to_open.json"), {"groups": result["to_open"]})
        write_json(os.path.join(args.output_dir, "excluded.json"), {"excluded": result["excluded"]})
        print(
            "Recon triage: " + str(len(result["to_open"])) + " to open as issues, "
            + str(len(result["excluded"])) + " excluded"
        )
        return

    if args.plugin_id is None:
        raise ValueError("--stage verify needs --plugin-id")
    engagement = scope.load_engagement(args.engagement)
    accepted_risks = load_accepted_risks(engagement)
    group = group_findings.load_groups(args.grouped, args.plugin_id)[0]
    enrichment = load_enrichment(args.output_dir, args.plugin_id)
    result = triage_verify(group, enrichment, rules_data, accepted_risks, date.today())
    output_path = os.path.join(args.output_dir, "triage", str(args.plugin_id) + ".json")
    write_json(output_path, result)
    print("Plugin " + str(args.plugin_id) + ": " + result["verdict"] + " (rule " + result["rule"] + ")")


if __name__ == "__main__":
    main()
