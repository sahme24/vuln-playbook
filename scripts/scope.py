"""Scope enforcement for every scan script.

The rules of engagement say we may only touch hosts the client authorized.
Writing that in a prompt is not enough, because a prompt can be misread or
ignored. This module puts the rule in code: every scan script loads the scope
from engagement.yaml and calls check_in_scope() (single IP) or
check_network_in_scope() (CIDR range) before it runs anything. Both raise
ValueError for a target that is not allowed, so a scan cannot start by mistake.

A target is in scope only if:
    1. it falls inside at least one `include` entry, AND
    2. it does not fall inside any `exclude` entry.

Scope entries must be IP addresses or CIDR ranges (IPv4 or IPv6). Hostnames
are rejected on purpose: a hostname can resolve to a different address
tomorrow, so it cannot be checked against an authorization once and trusted.

The engagement window is checked here too (check_in_window), because "only
scan inside the window" is the same kind of hard rule as scope.

validate_engagement() checks a whole engagement file the moment it is
written (the intake prompt runs it), so mistakes are caught before anyone
approves the scope, not halfway through a scan.

CLI usage:
    python scripts/scope.py --engagement engagement.yaml --validate
    python scripts/scope.py --engagement engagement.yaml --target 192.0.2.10
    python scripts/scope.py --engagement engagement.yaml --target 192.0.2.0/28 --dry-run
"""

import argparse
import ipaddress
import json
import os
from datetime import datetime, timezone

import yaml

# Top-level sections every engagement.yaml must have. Checking them up front
# gives a clear error instead of a confusing KeyError deep inside a script.
REQUIRED_SECTIONS = ["engagement", "scope", "scanning", "reporting", "approval"]

# Allowed values for the choice fields of engagement.yaml. NMAP_PROFILES must
# match the PROFILES table in nmap_discovery.py (a test checks this). It is
# repeated here because nmap_discovery imports this module, so importing it
# back would be circular.
NMAP_PROFILES = ["standard", "quiet"]
AUDIENCES = ["technical", "executive", "both"]
FRAMEWORKS = ["none", "NIST 800-53", "CIS", "PCI DSS", "ISO 27001"]
SLA_SEVERITIES = ["critical", "high", "medium"]


def load_engagement(path):
    """Read engagement.yaml and return it as a dict.

    Only the top-level shape is checked here. Each section is validated by
    the function that uses it (build_scope for `scope`, check_in_window for
    the window fields), so the error message can name the exact field.
    """
    if type(path) is not str or path == "":
        raise ValueError("engagement path must be a non-empty string")
    if not os.path.isfile(path):
        raise ValueError("engagement file not found: " + path)

    with open(path, "r", encoding="utf-8") as handle:
        # safe_load only builds plain Python types (dict, list, str, ...).
        # yaml.load could construct arbitrary objects from tags in the file.
        data = yaml.safe_load(handle)

    if type(data) is not dict:
        raise ValueError("engagement file must contain a YAML mapping at the top level: " + path)
    for section in REQUIRED_SECTIONS:
        if section not in data:
            raise ValueError("engagement file is missing the '" + section + "' section: " + path)
        if type(data[section]) is not dict:
            raise ValueError("'" + section + "' in the engagement file must be a mapping")
    return data


def parse_scope_entry(entry):
    """Turn one scope entry ("192.0.2.0/24" or "192.0.2.10") into an ip_network.

    A single IP becomes a one-address network (/32 for IPv4, /128 for IPv6),
    so include/exclude logic only has to deal with one type.
    """
    if type(entry) is not str:
        raise ValueError(
            "scope entry must be a string, got " + type(entry).__name__ + ": " + repr(entry)
        )
    text = entry.strip()
    if text == "":
        raise ValueError("scope entry is empty")

    try:
        # strict=True rejects entries like "192.0.2.5/24", where the address
        # has host bits set. That is almost always a typo (did the user mean
        # the /24 network or the single host?), so we refuse to guess.
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as error:
        raise ValueError(
            "scope entry is not a valid IP address or CIDR range: "
            + repr(entry) + " (" + str(error) + ")"
        )
    return network


def parse_ip(value):
    """Parse a single IP address string. Raises ValueError for anything else,
    including hostnames and CIDR ranges."""
    if type(value) is not str:
        raise ValueError(
            "IP address must be a string, got " + type(value).__name__ + ": " + repr(value)
        )
    text = value.strip()
    if text == "":
        raise ValueError("IP address is empty")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError("not a valid IP address (hostnames are not accepted): " + repr(value))
    return address


def build_scope(engagement):
    """Read the `scope` section of a loaded engagement and return
    {"include": [ip_network, ...], "exclude": [ip_network, ...]}.

    `include` must have at least one entry. An empty include list would mean
    "nothing is authorized", and that is almost certainly a mistake in the file,
    not a real engagement. `exclude` may be empty.
    """
    if type(engagement) is not dict or "scope" not in engagement:
        raise ValueError("engagement must be a dict with a 'scope' section (use load_engagement)")
    section = engagement["scope"]
    if type(section) is not dict:
        raise ValueError("'scope' must be a mapping with 'include' and 'exclude' lists")

    for key in ["include", "exclude"]:
        if key not in section:
            raise ValueError("scope is missing the '" + key + "' list")
        # YAML turns an empty "exclude:" line into None, not []. Treat that as
        # a mistake too: the schema says these are lists, so write [].
        if type(section[key]) is not list:
            raise ValueError("scope '" + key + "' must be a list (use [] for none)")

    if len(section["include"]) == 0:
        raise ValueError("scope 'include' is empty, so nothing is authorized for testing")

    include = []
    for entry in section["include"]:
        include.append(parse_scope_entry(entry))

    exclude = []
    for entry in section["exclude"]:
        exclude.append(parse_scope_entry(entry))

    return {"include": include, "exclude": exclude}


def validate_scope(scope):
    """Make sure a scope dict has the shape build_scope() produces.

    The check functions below call this so that passing in the raw YAML
    section by mistake fails loudly instead of comparing strings to networks.
    """
    if type(scope) is not dict:
        raise ValueError("scope must be the dict returned by build_scope()")
    for key in ["include", "exclude"]:
        if key not in scope or type(scope[key]) is not list:
            raise ValueError("scope must have '" + key + "' as a list (use build_scope())")
        for network in scope[key]:
            network_type = type(network)
            if network_type is not ipaddress.IPv4Network and network_type is not ipaddress.IPv6Network:
                raise ValueError("scope '" + key + "' must contain ip_network objects (use build_scope())")


def check_in_scope(ip_text, scope):
    """Return True if ip_text is in scope. Raise ValueError otherwise.

    The error message says which rule failed (not in any include range, or
    matched an exclude entry), so the caller can report it accurately.
    """
    validate_scope(scope)
    address = parse_ip(ip_text)

    inside_include = False
    for network in scope["include"]:
        # An IPv4 address is never inside an IPv6 network (and vice versa).
        # Checking the version first makes that explicit.
        if address.version == network.version and address in network:
            inside_include = True
            break
    if not inside_include:
        raise ValueError(str(address) + " is out of scope: it is not inside any include entry")

    for network in scope["exclude"]:
        if address.version == network.version and address in network:
            raise ValueError(
                str(address) + " is out of scope: it matches exclude entry " + str(network)
            )

    return True


def check_network_in_scope(cidr_text, scope):
    """Check a CIDR range before scanning it.

    Returns the list of exclude entries (as strings) that overlap the range.
    The caller MUST pass these to nmap with --exclude, so the excluded
    addresses inside the range are skipped.

    Raises ValueError if:
      - the range is not entirely inside one include entry (part of it would
        be unauthorized), or
      - the range is entirely inside an exclude entry (nothing in it may be
        scanned, so starting the scan makes no sense).
    """
    validate_scope(scope)
    if type(cidr_text) is not str:
        raise ValueError("CIDR range must be a string, got " + type(cidr_text).__name__)
    network = parse_scope_entry(cidr_text)

    inside_include = False
    for include_network in scope["include"]:
        if network.version == include_network.version and network.subnet_of(include_network):
            inside_include = True
            break
    if not inside_include:
        raise ValueError(
            str(network) + " is out of scope: it is not entirely inside any include entry"
        )

    overlapping_excludes = []
    for exclude_network in scope["exclude"]:
        if network.version != exclude_network.version:
            continue
        if network.subnet_of(exclude_network):
            raise ValueError(
                str(network) + " is out of scope: the whole range is inside exclude entry "
                + str(exclude_network)
            )
        if network.overlaps(exclude_network):
            overlapping_excludes.append(str(exclude_network))

    return overlapping_excludes


def parse_window_time(value, field_name):
    """Parse a window_start / window_end value into a timezone-aware datetime.

    PyYAML turns an unquoted ISO timestamp into a datetime object by itself,
    while a quoted one stays a string, so both are accepted. A time without a
    UTC offset is rejected: "09:00" means different moments in different
    places, and the window has to mean one specific moment.
    """
    if type(value) is datetime:
        moment = value
    elif type(value) is str:
        if value.strip() == "":
            raise ValueError(field_name + " is empty")
        try:
            moment = datetime.fromisoformat(value.strip())
        except ValueError:
            raise ValueError(field_name + " is not a valid ISO 8601 date-time: " + repr(value))
    else:
        raise ValueError(field_name + " must be an ISO 8601 string, got " + type(value).__name__)

    if moment.tzinfo is None:
        raise ValueError(
            field_name + " must include a UTC offset, e.g. 2026-12-01T09:00:00-05:00"
        )
    return moment


def check_in_window(engagement, now):
    """Return True if `now` is inside the engagement window. Raise ValueError
    otherwise, or if the window itself is invalid (end not after start).

    `now` is passed in rather than read from the clock inside this function,
    so the check can be tested with fixed times. Callers pass
    datetime.now(timezone.utc).

    In --dry-run mode no scan happens, so the scan scripts skip this check.
    That decision belongs to the caller, not to this function.
    """
    if type(engagement) is not dict or "engagement" not in engagement:
        raise ValueError("engagement must be a dict with an 'engagement' section")
    details = engagement["engagement"]
    if type(details) is not dict:
        raise ValueError("'engagement' section must be a mapping")
    if "window_start" not in details or "window_end" not in details:
        raise ValueError("engagement section must have window_start and window_end")

    start = parse_window_time(details["window_start"], "window_start")
    end = parse_window_time(details["window_end"], "window_end")
    if end <= start:
        raise ValueError("window_end must be after window_start")

    if type(now) is not datetime or now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    if now < start:
        raise ValueError("outside the engagement window: it starts at " + start.isoformat())
    if now > end:
        raise ValueError("outside the engagement window: it ended at " + end.isoformat())
    return True


def check_approved(engagement):
    """Return True if the human has approved the scope. Raise ValueError otherwise.

    The rules of engagement say no scan runs until the human has reviewed
    the scope and set approval.scope_approved to true. Checking it in code
    means a prompt mistake cannot skip the approval step.

    The flag must be the YAML boolean `true`. A string such as "true" or
    "yes" is refused, because it suggests the file was edited by something
    other than the documented process. approved_at must also be filled in,
    so every approval has a recorded time.
    """
    if type(engagement) is not dict or "approval" not in engagement:
        raise ValueError("engagement must be a dict with an 'approval' section")
    approval = engagement["approval"]
    if type(approval) is not dict:
        raise ValueError("'approval' section must be a mapping")
    if "scope_approved" not in approval:
        raise ValueError("approval.scope_approved is missing")
    if type(approval["scope_approved"]) is not bool:
        raise ValueError(
            "approval.scope_approved must be the YAML boolean true or false, got "
            + repr(approval["scope_approved"])
        )
    if approval["scope_approved"] is not True:
        raise ValueError(
            "scope is not approved: review the scope summary and set "
            "approval.scope_approved to true yourself before any scan runs"
        )
    if "approved_at" not in approval:
        raise ValueError("approval.approved_at is missing")
    parse_window_time(approval["approved_at"], "approval.approved_at")
    return True


# --- whole-file validation (used by the intake prompt) -------------------------

def require_text(section, key, label):
    """Return section[key] if it is a non-empty string, else raise."""
    value = section.get(key)
    if type(value) is not str or value.strip() == "":
        raise ValueError(label + " must be filled in")
    return value.strip()


def check_scope_entries_consistent(scope):
    """Catch include/exclude combinations that are almost certainly mistakes.

    Two CIDR blocks are always either nested or completely separate, so for
    each exclude entry there are only three cases:
      - it is the same as an include entry, or contains a whole include
        entry: that include would have nothing left to test;
      - it lies inside an include entry: the normal case (skip one host);
      - it lies outside every include entry: it has no effect, which usually
        means a typo in an address the client wanted protected.
    """
    for excluded in scope["exclude"]:
        inside_an_include = False
        for included in scope["include"]:
            if excluded.version != included.version:
                continue
            if excluded == included:
                raise ValueError(str(excluded) + " is listed in both include and exclude")
            if included.subnet_of(excluded):
                raise ValueError(
                    "exclude " + str(excluded) + " covers the whole include entry "
                    + str(included) + ", leaving nothing to test there"
                )
            if excluded.subnet_of(included):
                inside_an_include = True
        if not inside_an_include:
            raise ValueError(
                "exclude " + str(excluded) + " is not inside any include entry, so it has no "
                "effect; check it for a typo"
            )
    return True


def validate_engagement(engagement):
    """Check every field the agents rely on. Returns a summary dict
    (name, include, exclude, window) for the intake prompt to show the human.
    Raises ValueError naming the first problem found."""
    details = engagement["engagement"]
    name = require_text(details, "name", "engagement.name")
    require_text(details, "client", "engagement.client")
    require_text(details, "authorized_by", "engagement.authorized_by")
    require_text(details, "authorization_reference", "engagement.authorization_reference")
    start = parse_window_time(details.get("window_start"), "engagement.window_start")
    end = parse_window_time(details.get("window_end"), "engagement.window_end")
    if end <= start:
        raise ValueError("engagement.window_end must be after window_start")

    scope = build_scope(engagement)
    check_scope_entries_consistent(scope)

    scanning = engagement["scanning"]
    if scanning.get("nmap_profile") not in NMAP_PROFILES:
        raise ValueError("scanning.nmap_profile must be one of " + ", ".join(NMAP_PROFILES))
    require_text(scanning, "nessus_policy_name", "scanning.nessus_policy_name")
    if type(scanning.get("credentialed")) is not bool:
        raise ValueError("scanning.credentialed must be true or false")
    if type(scanning.get("credential_notes")) is not str:
        raise ValueError("scanning.credential_notes must be text (use \"\" for none)")

    reporting = engagement["reporting"]
    if reporting.get("audience") not in AUDIENCES:
        raise ValueError("reporting.audience must be one of " + ", ".join(AUDIENCES))
    if reporting.get("framework") not in FRAMEWORKS:
        raise ValueError("reporting.framework must be one of " + ", ".join(FRAMEWORKS))
    sla = reporting.get("severity_sla")
    if type(sla) is not dict:
        raise ValueError("reporting.severity_sla must be a mapping of severity to days")
    for severity in SLA_SEVERITIES:
        days = sla.get(severity)
        # type() is int rejects True/False, which Python would otherwise count as 1/0.
        if type(days) is not int or days < 1:
            raise ValueError("reporting.severity_sla." + severity + " must be a whole number of days, at least 1")

    if type(engagement["approval"].get("scope_approved")) is not bool:
        raise ValueError("approval.scope_approved must be true or false (without quotes)")

    include = []
    for network in scope["include"]:
        include.append(str(network))
    exclude = []
    for network in scope["exclude"]:
        exclude.append(str(network))
    return {
        "name": name,
        "include": include,
        "exclude": exclude,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "scope_approved": engagement["approval"]["scope_approved"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Check targets against the engagement scope and window. "
        "Raises an error (non-zero exit) on the first target that is not allowed."
    )
    parser.add_argument("--engagement", default="engagement.yaml", help="path to engagement.yaml")
    parser.add_argument(
        "--target", action="append", default=None,
        help="IP address or CIDR range to check (repeat for several)",
    )
    parser.add_argument(
        "--validate", action="store_true",
        help="check the whole engagement file instead of targets (used by the intake prompt)",
    )
    parser.add_argument("--output-dir", default="engagement/output", help="where to write JSON")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="skip the engagement window check (no real scan will run)",
    )
    args = parser.parse_args()

    engagement = load_engagement(args.engagement)
    if args.validate:
        summary = validate_engagement(engagement)
        os.makedirs(args.output_dir, exist_ok=True)
        output_path = os.path.join(args.output_dir, "engagement_check.json")
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2)
        print(json.dumps(summary, indent=2))
        print("Engagement file is valid. Wrote " + output_path)
        return
    if args.target is None:
        raise ValueError("give at least one --target, or --validate")

    scope = build_scope(engagement)
    now = datetime.now(timezone.utc)

    window_checked = False
    if not args.dry_run:
        check_in_window(engagement, now)
        window_checked = True

    results = []
    for target in args.target:
        # A "/" means a range. Ranges have their own check because a range
        # can be partly covered by exclude entries, which nmap must skip.
        if "/" in target:
            excludes = check_network_in_scope(target, scope)
            results.append({"target": target, "type": "range", "nmap_exclude": excludes})
        else:
            check_in_scope(target, scope)
            results.append({"target": target, "type": "ip", "nmap_exclude": []})

    output = {
        "engagement_file": args.engagement,
        "checked_at": now.isoformat(),
        "window_checked": window_checked,
        "all_in_scope": True,
        "results": results,
    }
    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, "scope_check.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)
    print("All targets in scope. Wrote " + output_path)


if __name__ == "__main__":
    main()
