import os

import pytest

import group_findings
import parse_nessus
import scope

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_NESSUS = os.path.join(FIXTURES, "sample.nessus")
ENGAGEMENT_FILE = os.path.join(FIXTURES, "engagement_test.yaml")

SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def grouped_sample():
    engagement_scope = scope.build_scope(scope.load_engagement(ENGAGEMENT_FILE))
    parsed = parse_nessus.parse_nessus_file(SAMPLE_NESSUS, engagement_scope)
    return group_findings.group_findings(parsed["findings"])


def find_group(groups, plugin_id):
    for group in groups:
        if group["plugin_id"] == plugin_id:
            return group
    raise AssertionError("no group for plugin " + str(plugin_id))


def make_finding(host_ip, port, plugin_id, severity, cves):
    """A finding with every key parse_nessus.py produces. Only the fields a
    test cares about are parameters. The rest are fixed placeholder values."""
    return {
        "host_ip": host_ip,
        "hostname": None,
        "operating_system": None,
        "port": port,
        "protocol": "tcp",
        "service": "www",
        "plugin_id": plugin_id,
        "plugin_name": "Plugin " + str(plugin_id),
        "plugin_family": "General",
        "plugin_type": "remote",
        "severity": severity,
        "severity_name": SEVERITY_NAMES[severity],
        "risk_factor": None,
        "cves": cves,
        "cvss3_base_score": None,
        "cvss3_vector": None,
        "cvss_base_score": None,
        "vpr_score": None,
        "exploit_available": None,
        "synopsis": None,
        "description": None,
        "solution": None,
        "see_also": [],
        "plugin_output": None,
    }


# --- happy path on the synthetic fixture ------------------------------------

def test_one_group_per_plugin():
    # The board gets one issue per group. Two groups for one plugin would mean
    # duplicate issues and the same fix being reported twice.
    groups = grouped_sample()
    plugin_ids = []
    for group in groups:
        assert group["plugin_id"] not in plugin_ids
        plugin_ids.append(group["plugin_id"])
    assert len(groups) == 10


def test_affected_hosts_are_collected():
    # The KEV finding is on two hosts. Both must be listed, or one vulnerable
    # server would drop out of the remediation plan.
    group = find_group(grouped_sample(), 900104)
    hosts = []
    for entry in group["affected"]:
        hosts.append(entry["host_ip"])
    assert hosts == ["192.0.2.20", "198.51.100.20"]
    assert group["host_count"] == 2


def test_same_host_on_several_ports_counts_once():
    # SWEET32 is on 192.0.2.20 ports 443 and 3389, and on 192.0.2.10. Each
    # port is listed (the fixer needs every one), but host_count counts hosts.
    group = find_group(grouped_sample(), 900102)
    assert len(group["affected"]) == 3
    assert group["host_count"] == 2


def test_duplicate_cve_is_cross_referenced():
    # CVE-2016-2183 is reported by two plugins. Each must point to the other,
    # so the CVE is not verified twice or counted twice in the report.
    groups = grouped_sample()
    assert find_group(groups, 900102)["related_plugin_ids"] == [900105]
    assert find_group(groups, 900105)["related_plugin_ids"] == [900102]
    assert find_group(groups, 900104)["related_plugin_ids"] == []


def test_groups_ordered_by_severity_then_plugin_id():
    # A stable order gives the same issue numbers on every dry run, and puts
    # the critical KEV finding first on the board.
    groups = grouped_sample()
    assert groups[0]["plugin_id"] == 900104
    previous_severity = 5
    for group in groups:
        assert group["severity"] <= previous_severity
        previous_severity = group["severity"]


def test_rejected_hosts_never_appear_in_groups():
    # Grouping must not bring back data from hosts that scope rejected.
    for group in grouped_sample():
        for entry in group["affected"]:
            assert entry["host_ip"] != "203.0.113.50"
            assert entry["host_ip"] != "192.0.2.250"


# --- merging rules (hand-made findings) -------------------------------------

def test_affected_sorted_numerically_not_as_text():
    # Sorted as text, "192.0.2.10" comes before "192.0.2.9". Numeric order is
    # what a reader expects in the report's host table.
    findings = [
        make_finding("192.0.2.10", 443, 1, 2, []),
        make_finding("192.0.2.9", 443, 1, 2, []),
    ]
    group = group_findings.group_findings(findings)[0]
    assert group["affected"][0]["host_ip"] == "192.0.2.9"


def test_highest_severity_wins_and_stays_consistent():
    # If two results of one plugin disagree, under-reporting is the worse
    # mistake, so the higher severity is kept along with its matching name.
    findings = [
        make_finding("192.0.2.10", 443, 1, 2, []),
        make_finding("192.0.2.11", 443, 1, 3, []),
    ]
    group = group_findings.group_findings(findings)[0]
    assert group["severity"] == 3
    assert group["severity_name"] == "high"


def test_scores_keep_highest_and_ignore_missing():
    # A missing score on one host must not erase a real score from another,
    # and the higher of two real scores is the one kept.
    first = make_finding("192.0.2.10", 443, 1, 2, [])
    second = make_finding("192.0.2.11", 443, 1, 2, [])
    third = make_finding("192.0.2.12", 443, 1, 2, [])
    first["cvss3_base_score"] = 5.3
    second["cvss3_base_score"] = None
    third["cvss3_base_score"] = 6.1
    group = group_findings.group_findings([first, second, third])[0]
    assert group["cvss3_base_score"] == 6.1


def test_exploit_available_if_any_result_says_so():
    # A known public exploit on even one host raises urgency for the whole
    # finding, so one True must win over False and None.
    first = make_finding("192.0.2.10", 443, 1, 2, [])
    second = make_finding("192.0.2.11", 443, 1, 2, [])
    first["exploit_available"] = False
    second["exploit_available"] = True
    group = group_findings.group_findings([first, second])[0]
    assert group["exploit_available"] is True


def test_cves_are_merged_unique_and_sorted():
    # Results of one plugin can list CVEs in different orders. The group needs
    # one clean, sorted list for enrichment and for the report.
    findings = [
        make_finding("192.0.2.10", 443, 1, 2, ["CVE-2023-51385", "CVE-2023-48795"]),
        make_finding("192.0.2.11", 443, 1, 2, ["CVE-2023-48795"]),
    ]
    group = group_findings.group_findings(findings)[0]
    assert group["cves"] == ["CVE-2023-48795", "CVE-2023-51385"]


def test_higher_score_helper():
    # Check the helper directly, including both "None" cases, since the merge
    # rules above all depend on it.
    assert group_findings.higher_score(None, 4.0) == 4.0
    assert group_findings.higher_score(4.0, None) == 4.0
    assert group_findings.higher_score(None, None) is None
    assert group_findings.higher_score(7.5, 5.9) == 7.5


def test_empty_list_gives_no_groups():
    # A scan with no in-scope findings is valid and must give an empty
    # list, not an error.
    assert group_findings.group_findings([]) == []


# --- invalid input ----------------------------------------------------------

def test_non_list_input_raises():
    # Passing the whole parse result (a dict) instead of its findings list is
    # an easy mistake. It must be caught, not looped over as dict keys.
    with pytest.raises(ValueError):
        group_findings.group_findings({"findings": []})


def test_finding_missing_key_raises():
    # A finding without plugin_id did not come from parse_nessus.py. Grouping
    # it under a made-up key would create a fake finding.
    finding = make_finding("192.0.2.10", 443, 1, 2, [])
    del finding["plugin_id"]
    with pytest.raises(ValueError, match="plugin_id"):
        group_findings.group_findings([finding])


def test_non_integer_plugin_id_raises():
    # "900104" and 900104 would become two separate groups for the same
    # plugin, so the type is checked strictly.
    finding = make_finding("192.0.2.10", 443, 1, 2, [])
    finding["plugin_id"] = "1"
    with pytest.raises(ValueError):
        group_findings.group_findings([finding])


def test_non_dict_finding_raises():
    # A stray string or None in the list means the input file is corrupt.
    with pytest.raises(ValueError):
        group_findings.group_findings([None])
