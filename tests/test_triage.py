import copy
import os
from datetime import date

import pytest

import enrich_epss
import enrich_kev
import enrich_nvd
import enrich_vendor
import group_findings
import parse_nessus
import scope
import triage

ROOT = os.path.dirname(os.path.dirname(__file__))
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
CANNED = os.path.join(FIXTURES, "api")
RULES_FILE = os.path.join(ROOT, "playbook", "triage-rules.yaml")
ENGAGEMENT_FILE = os.path.join(FIXTURES, "engagement_test.yaml")
TODAY = date(2026, 12, 2)
NOW = 1796134200.0


def no_network(url, params, headers, timeout):
    raise AssertionError("triage tests must not use the network")


def no_sleep(seconds):
    pass


def rules():
    return triage.load_rules(RULES_FILE)


def fixture_groups():
    engagement = scope.load_engagement(ENGAGEMENT_FILE)
    parsed = parse_nessus.parse_nessus_file(os.path.join(FIXTURES, "sample.nessus"), scope.build_scope(engagement))
    return group_findings.group_findings(parsed["findings"])


def find_group(groups, plugin_id):
    for group in groups:
        if group["plugin_id"] == plugin_id:
            return group
    raise AssertionError("no group " + str(plugin_id))


def canned_enrichment(group):
    """Run the four enrichers in dry-run mode for one group."""
    catalog = enrich_kev.load_canned_kev(CANNED)
    return {
        "nvd": enrich_nvd.enrich_nvd(group["cves"], None, NOW, None, no_network, no_sleep, no_sleep, CANNED),
        "kev": enrich_kev.enrich_kev(group["cves"], catalog),
        "epss": enrich_epss.enrich_epss(group["cves"], None, NOW, no_network, no_sleep, CANNED),
        "vendor": {"records": enrich_vendor.enrich_vendor(group, None, NOW, no_network, no_sleep, CANNED)},
    }


def accepted():
    return triage.load_accepted_risks(scope.load_engagement(ENGAGEMENT_FILE))


def verdict_for(plugin_id):
    group = find_group(fixture_groups(), plugin_id)
    return triage.triage_verify(group, canned_enrichment(group), rules(), accepted(), TODAY)


def facts(overrides):
    """Verify-stage facts with neutral defaults. `overrides` is a dict of the
    facts a test wants to change."""
    base = {
        "plugin_id": 1, "severity": 2, "has_cve": True, "kev": False, "kev_cves": [],
        "banner_only": False, "backport_distro": False, "vendor_status": "unknown",
        "accepted_risk": False,
    }
    for key in overrides:
        base[key] = overrides[key]
    return base


# --- the rules file itself ---------------------------------------------------

def test_shipped_rules_file_is_valid():
    # If the shipped rules fail validation, no finding can be triaged.
    data = rules()
    assert data["rules"][0]["name"] == "informational_plugin"
    assert data["rules"][-1]["when"] == {}


def test_rule_order_matches_approved_design():
    # Order IS the logic (first match wins). Pin it so a reordering edit is a
    # deliberate change that has to update this test too.
    names = []
    for rule in rules()["rules"]:
        names.append(rule["name"])
    assert names == [
        "informational_plugin", "accepted_risk_listed", "kev_on_backport_banner", "kev_match",
        "backport_not_affected", "backport_no_fix_yet", "banner_only_backport",
        "low_severity_hardening", "direct_detection", "banner_only_vendor_version",
        "fallback_needs_human",
    ]


def test_false_positive_rule_without_kev_false_is_refused():
    # Code-level guard: a false-positive rule that could match a KEV CVE would
    # break "never dismiss KEV without a human".
    data = copy.deepcopy(rules())
    for rule in data["rules"]:
        if rule["name"] == "backport_not_affected":
            del rule["when"]["kev"]
    with pytest.raises(ValueError, match="kev: false"):
        triage.validate_rules(data)


def test_missing_catch_all_is_refused():
    # Without a final empty-'when' rule some findings would get no verdict.
    data = copy.deepcopy(rules())
    data["rules"][-1]["when"] = {"kev": True}
    with pytest.raises(ValueError, match="empty 'when'"):
        triage.validate_rules(data)


def test_recon_rule_using_enrichment_is_refused():
    # KEV data does not exist before issues are opened, so a recon rule on
    # 'kev' would silently never match.
    data = copy.deepcopy(rules())
    data["rules"][0]["when"] = {"kev": True}
    with pytest.raises(ValueError, match="recon"):
        triage.validate_rules(data)


def test_bad_rule_fields_are_refused():
    # Typos in condition names, actions or names must fail at load time, not
    # quietly change verdicts.
    data = copy.deepcopy(rules())
    data["rules"][1]["when"] = {"kevv": True}
    with pytest.raises(ValueError, match="unknown condition"):
        triage.validate_rules(data)
    data = copy.deepcopy(rules())
    data["rules"][1]["action"] = "maybe"
    with pytest.raises(ValueError, match="not allowed"):
        triage.validate_rules(data)
    data = copy.deepcopy(rules())
    data["rules"][2]["name"] = data["rules"][1]["name"]
    with pytest.raises(ValueError, match="twice"):
        triage.validate_rules(data)


# --- recon stage ---------------------------------------------------------------

def test_recon_excludes_informational_plugins_with_rule():
    # Dry-run requirement: informational plugins never reach the board, and
    # each exclusion records the rule that fired.
    result = triage.triage_recon(fixture_groups(), rules())
    excluded_ids = []
    for entry in result["excluded"]:
        excluded_ids.append(entry["plugin_id"])
        assert entry["rule"] == "informational_plugin"
    excluded_ids.sort()
    assert excluded_ids == [10287, 11936, 19506, 22964]
    assert len(result["to_open"]) == 6


# --- verify stage on the dry-run fixture (end to end) -----------------------

def test_kev_finding_is_verified_by_kev_match():
    # Dry-run requirement: the KEV finding is verified. Red Hat's "RHEL 8 log4j
    # not affected" must not override a direct remote detection.
    result = verdict_for(900104)
    assert result["verdict"] == "verified"
    assert result["rule"] == "kev_match"
    assert result["facts"]["kev_cves"] == ["CVE-2021-44228"]


def test_ubuntu_banner_goes_to_needs_human():
    # Dry-run requirement: a banner-only detection on Ubuntu, where Ubuntu has
    # shipped a fix, cannot be decided from the banner. A human must check.
    result = verdict_for(900101)
    assert result["verdict"] == "needs-human"
    assert result["rule"] == "banner_only_backport"
    assert result["facts"]["vendor_status"] == "fixed"


def test_other_fixture_verdicts():
    # The rest of the dry run: direct detections verified, the client-accepted
    # TLS 1.0 finding accepted, the low-severity finding to the appendix.
    assert verdict_for(900102)["rule"] == "direct_detection"
    assert verdict_for(900105)["verdict"] == "verified"
    assert verdict_for(900106)["verdict"] == "accepted-risk"
    assert verdict_for(900103)["verdict"] == "appendix"


def test_evidence_contains_sources_with_links():
    # Every verdict must cite evidence. The KEV verdict needs the NVD link and
    # the KEV entry date at minimum.
    evidence = verdict_for(900104)["evidence"]
    sources = []
    for item in evidence:
        sources.append(item["source"])
        if item["source"] == "kev":
            assert item["date_added"] == "2021-12-10"
        if item["source"] == "nvd":
            assert item["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert "tenable" in sources
    assert "nvd" in sources
    assert "kev" in sources
    assert "epss" in sources


def test_accepted_risk_evidence_names_reference():
    # An accepted-risk verdict must point to the client's acceptance record,
    # or the auditor cannot check it.
    evidence = verdict_for(900106)["evidence"]
    found = False
    for item in evidence:
        if item["source"] == "accepted_risk":
            found = True
            assert item["reference"] == "RISK-0042"
    assert found


# --- individual rules through evaluate() --------------------------------------

def test_kev_never_reaches_false_positive():
    # Even when the vendor says "not affected", a KEV CVE on a backport banner
    # goes to a human, never straight to false-positive.
    result = triage.evaluate("verify", facts({"kev": True, "banner_only": True, "backport_distro": True, "vendor_status": "not-affected"}), rules())
    assert result["verdict"] == "needs-human"
    assert result["rule"] == "kev_on_backport_banner"


def test_backport_vendor_not_affected_is_false_positive():
    # The textbook false positive: a banner says "old version", but the vendor
    # says this release was never affected.
    result = triage.evaluate("verify", facts({"banner_only": True, "backport_distro": True, "vendor_status": "not-affected"}), rules())
    assert result["verdict"] == "false-positive"


def test_backport_vendor_affected_is_verified():
    # No fix exists, so every build is vulnerable and the banner is enough.
    result = triage.evaluate("verify", facts({"banner_only": True, "backport_distro": True, "vendor_status": "affected"}), rules())
    assert result["rule"] == "backport_no_fix_yet"


def test_banner_on_non_backport_os_is_verified():
    # Windows or vendor appliances do not backport, so a version banner is reliable.
    result = triage.evaluate("verify", facts({"banner_only": True, "backport_distro": False}), rules())
    assert result["rule"] == "banner_only_vendor_version"


def test_accepted_risk_comes_first():
    # A formal client acceptance applies even to a KEV finding. The report
    # still lists it, but as accepted risk.
    result = triage.evaluate("verify", facts({"accepted_risk": True, "kev": True}), rules())
    assert result["verdict"] == "accepted-risk"


# --- vendor status combining -----------------------------------------------------

def vendor_record(cve, status):
    return {"cve": cve, "status": status}


def test_combine_vendor_status_rules():
    # "not-affected" can lead to a false positive, so it needs EVERY CVE
    # covered. One affected CVE makes the finding affected.
    cves = ["CVE-1", "CVE-2"]
    assert triage.combine_vendor_status(cves, [vendor_record("CVE-1", "not-affected"), vendor_record("CVE-2", "not-affected")]) == "not-affected"
    assert triage.combine_vendor_status(cves, [vendor_record("CVE-1", "not-affected")]) == "unknown"
    assert triage.combine_vendor_status(cves, [vendor_record("CVE-1", "fixed"), vendor_record("CVE-2", "affected")]) == "affected"
    assert triage.combine_vendor_status(cves, [vendor_record("CVE-1", "fixed"), vendor_record("CVE-2", "unknown")]) == "fixed"
    assert triage.combine_vendor_status([], []) == "unknown"


# --- accepted risks ------------------------------------------------------------

def test_load_accepted_risks_from_fixture():
    # The dry-run engagement accepts plugin 900106 until 2027-06-30.
    entries = accepted()
    assert entries[0]["plugin_id"] == 900106
    assert entries[0]["expires"] == date(2027, 6, 30)


def test_expired_acceptance_no_longer_applies():
    # An acceptance with an end date must stop applying after it, or a
    # temporary exception becomes permanent without anyone deciding so.
    group = {"plugin_id": 900106, "cves": []}
    assert len(triage.matching_acceptances(group, accepted(), date(2027, 6, 30))) == 1
    assert triage.matching_acceptances(group, accepted(), date(2027, 7, 1)) == []


def test_acceptance_by_cve_matches():
    # An acceptance can name a CVE instead of a plugin, and must match any
    # finding that lists that CVE.
    entries = triage.load_accepted_risks({"accepted_risks": [
        {"cve": "CVE-2016-2183", "accepted_by": "A", "reference": "R"}]})
    group = {"plugin_id": 900105, "cves": ["CVE-2016-2183"]}
    assert len(triage.matching_acceptances(group, entries, TODAY)) == 1


def test_invalid_accepted_risks_raise():
    # An acceptance must say exactly what it covers and who accepted it.
    # Anything vaguer could hide a real finding.
    bad_entries = [
        {"accepted_by": "A", "reference": "R"},                                      # neither id
        {"plugin_id": 1, "cve": "CVE-2016-2183", "accepted_by": "A", "reference": "R"},  # both
        {"plugin_id": "1", "accepted_by": "A", "reference": "R"},                    # id as text
        {"cve": "2016-2183", "accepted_by": "A", "reference": "R"},                  # bad CVE
        {"plugin_id": 1, "reference": "R"},                                          # no accepted_by
        {"plugin_id": 1, "accepted_by": "A", "reference": "R", "expires": "June"},   # bad date
    ]
    for entry in bad_entries:
        with pytest.raises(ValueError):
            triage.load_accepted_risks({"accepted_risks": [entry]})
    with pytest.raises(ValueError):
        triage.load_accepted_risks({})


# --- missing enrichment -------------------------------------------------------

def test_missing_enrichment_raises_instead_of_guessing():
    # Without KEV data, "kev" is unknown, not false. Treating it as false could
    # bury an actively exploited CVE.
    group = find_group(fixture_groups(), 900104)
    enrichment = canned_enrichment(group)
    enrichment["kev"] = {}
    with pytest.raises(ValueError, match="enrich_kev"):
        triage.triage_verify(group, enrichment, rules(), accepted(), TODAY)
    del enrichment["kev"]
    with pytest.raises(ValueError):
        triage.triage_verify(group, enrichment, rules(), accepted(), TODAY)


def test_bad_stage_raises():
    # Only recon and verify exist. Any other stage is a caller bug.
    with pytest.raises(ValueError):
        triage.evaluate("report", facts({}), rules())
