import os
import tempfile

import pytest

import parse_nessus
import scope

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_NESSUS = os.path.join(FIXTURES, "sample.nessus")
ENGAGEMENT_FILE = os.path.join(FIXTURES, "engagement_test.yaml")


def fixture_scope():
    return scope.build_scope(scope.load_engagement(ENGAGEMENT_FILE))


def parse_sample():
    return parse_nessus.parse_nessus_file(SAMPLE_NESSUS, fixture_scope())


def find_finding(findings, host_ip, plugin_id):
    """Return the one finding for this host and plugin. Fails the test if
    there is not exactly one."""
    matches = []
    for finding in findings:
        if finding["host_ip"] == host_ip and finding["plugin_id"] == plugin_id:
            matches.append(finding)
    assert len(matches) == 1
    return matches[0]


def nessus_document(report_hosts_xml):
    """Wrap ReportHost XML in a minimal valid .nessus document."""
    return (
        '<?xml version="1.0" ?>\n<NessusClientData_v2>\n'
        "<Policy><policyName>Test Policy</policyName></Policy>\n"
        '<Report name="test">\n' + report_hosts_xml + "\n</Report>\n</NessusClientData_v2>\n"
    )


def one_host(ip, item_xml):
    """A ReportHost with a host-ip tag and the given ReportItem XML."""
    return (
        '<ReportHost name="' + ip + '"><HostProperties>'
        '<tag name="host-ip">' + ip + "</tag></HostProperties>" + item_xml + "</ReportHost>"
    )


# A minimal, valid ReportItem. Tests copy it and break one thing at a time.
GOOD_ITEM = (
    '<ReportItem port="443" svc_name="www" protocol="tcp" severity="2" '
    'pluginID="900200" pluginName="Test Plugin" pluginFamily="General">'
    "<cve>CVE-2016-2183</cve><cvss3_base_score>5.9</cvss3_base_score></ReportItem>"
)


def parse_text(xml_text):
    """Write XML to a temporary .nessus file and parse it with the fixture scope."""
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "test.nessus")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(xml_text)
        return parse_nessus.parse_nessus_file(path, fixture_scope())


# --- happy path on the synthetic fixture ------------------------------------

def test_sample_counts():
    # The fixture is built to give exact numbers (4 in-scope hosts, 20 items,
    # 2 rejected hosts). Any change here means scope filtering or item
    # parsing changed behaviour.
    result = parse_sample()
    assert result["hosts_in_scope"] == ["192.0.2.10", "192.0.2.20", "198.51.100.20", "192.0.2.30"]
    assert len(result["findings"]) == 20
    assert len(result["rejected_hosts"]) == 2
    assert result["policy_name"] == "Internal Basic Network Scan"


def test_out_of_scope_host_is_rejected_and_recorded():
    # A Nessus policy can be edited to include extra targets. The
    # out-of-scope host must be recorded with a reason, and none of its data
    # may reach a finding. That data was never authorized.
    result = parse_sample()
    rejected_ips = []
    for rejected in result["rejected_hosts"]:
        rejected_ips.append(rejected["ip"])
    assert "203.0.113.50" in rejected_ips
    for finding in result["findings"]:
        assert finding["host_ip"] != "203.0.113.50"


def test_excluded_host_is_rejected_with_exclude_reason():
    # 192.0.2.250 sits inside an include range but was explicitly excluded by
    # the client. The reason must say "exclude" so the report explains why
    # it is missing.
    result = parse_sample()
    excluded = None
    for rejected in result["rejected_hosts"]:
        if rejected["ip"] == "192.0.2.250":
            excluded = rejected
    assert excluded is not None
    assert "exclude" in excluded["reason"]
    assert excluded["item_count"] == 2
    for finding in result["findings"]:
        assert finding["host_ip"] != "192.0.2.250"


def test_finding_fields_are_normalized():
    # Later scripts rely on real types: severity as int, scores as float,
    # booleans as bool. A string "10.0" would sort wrongly in the risk ranking.
    finding = find_finding(parse_sample()["findings"], "192.0.2.20", 900104)
    assert finding["severity"] == 4
    assert finding["severity_name"] == "critical"
    assert finding["port"] == 8080
    assert finding["protocol"] == "tcp"
    assert finding["cves"] == ["CVE-2021-44228"]
    assert finding["cvss3_base_score"] == 10.0
    assert finding["vpr_score"] == 10.0
    assert finding["exploit_available"] is True
    assert finding["hostname"] == "app01.example.test"
    assert finding["operating_system"] == "Microsoft Windows Server 2019 Standard"
    assert finding["plugin_type"] == "remote"


def test_banner_detection_keeps_description_and_os():
    # The verifier decides "banner-only on Ubuntu" from the OS and the
    # description text. If parsing dropped either one, that finding could
    # never be routed to needs-human.
    finding = find_finding(parse_sample()["findings"], "192.0.2.10", 900101)
    assert "Ubuntu" in finding["operating_system"]
    assert "self-reported version number" in finding["description"]
    assert "OpenSSH_8.9p1 Ubuntu" in finding["plugin_output"]


def test_see_also_is_split_into_urls():
    # see_also holds one URL per line. Kept as one blob, the URLs could not be
    # cited individually as evidence.
    finding = find_finding(parse_sample()["findings"], "192.0.2.10", 900101)
    assert finding["see_also"] == [
        "https://www.openssh.com/txt/release-9.6",
        "https://terrapin-attack.com/",
    ]


def test_informational_items_are_kept_at_parse_stage():
    # Parsing must not make triage decisions. Severity 0 items are excluded
    # later by triage-rules.yaml, which records the rule that fired. Dropping
    # them here would bypass that record.
    severities = []
    for finding in parse_sample()["findings"]:
        severities.append(finding["severity"])
    assert 0 in severities


def test_optional_fields_absent_become_none():
    # Informational plugins have no CVSS or exploit data. "Absent" must be
    # None, not 0.0, or a missing score would look like a real score of zero.
    finding = find_finding(parse_sample()["findings"], "192.0.2.10", 19506)
    assert finding["cvss3_base_score"] is None
    assert finding["exploit_available"] is None
    assert finding["cves"] == []


# --- host IP handling -------------------------------------------------------

def test_host_ip_falls_back_to_name_attribute():
    # Some exports omit the host-ip tag. When the ReportHost name is itself
    # an IP we can still check scope, so the host must not be lost.
    xml = nessus_document('<ReportHost name="192.0.2.30">' + GOOD_ITEM + "</ReportHost>")
    result = parse_text(xml)
    assert result["hosts_in_scope"] == ["192.0.2.30"]
    assert len(result["findings"]) == 1


def test_hostname_only_host_is_rejected_not_crashed():
    # With no IP we cannot prove the host is in scope, so it must be refused.
    # One such host must not abort the whole import, so it is recorded instead.
    xml = nessus_document('<ReportHost name="web09.example.test">' + GOOD_ITEM + "</ReportHost>")
    result = parse_text(xml)
    assert result["findings"] == []
    assert result["rejected_hosts"][0]["host"] == "web09.example.test"
    assert result["rejected_hosts"][0]["ip"] is None


def test_empty_report_is_valid():
    # A scan that found nothing (or only rejected hosts) is a real outcome.
    # It should give empty lists, not an error.
    result = parse_text(nessus_document(""))
    assert result["findings"] == []
    assert result["hosts_in_scope"] == []


def test_duplicate_cve_inside_one_item_is_kept_once():
    # A CVE listed twice in one item would otherwise be enriched and counted
    # twice.
    item = GOOD_ITEM.replace(
        "<cve>CVE-2016-2183</cve>", "<cve>CVE-2016-2183</cve><cve>CVE-2016-2183</cve>"
    )
    result = parse_text(nessus_document(one_host("192.0.2.10", item)))
    assert result["findings"][0]["cves"] == ["CVE-2016-2183"]


# --- invalid input ----------------------------------------------------------

def test_missing_plugin_id_raises():
    # Without a plugin ID a result cannot be grouped or traced to a Tenable
    # check. The file is corrupt and must not be half-imported.
    item = GOOD_ITEM.replace(' pluginID="900200"', "")
    with pytest.raises(ValueError, match="pluginID"):
        parse_text(nessus_document(one_host("192.0.2.10", item)))


def test_severity_out_of_range_raises():
    # Nessus severity is 0 to 4. A 5 (or -1) would map to no severity label
    # and break the risk ordering, so it is rejected at the boundary.
    with pytest.raises(ValueError, match="severity"):
        parse_text(nessus_document(one_host("192.0.2.10", GOOD_ITEM.replace('severity="2"', 'severity="5"'))))
    with pytest.raises(ValueError, match="severity"):
        parse_text(nessus_document(one_host("192.0.2.10", GOOD_ITEM.replace('severity="2"', 'severity="-1"'))))


def test_port_out_of_range_raises():
    # Port 70000 cannot exist. Accepting it would put a meaningless value
    # into the report's affected-host table.
    item = GOOD_ITEM.replace('port="443"', 'port="70000"')
    with pytest.raises(ValueError, match="port"):
        parse_text(nessus_document(one_host("192.0.2.10", item)))


def test_malformed_cve_raises():
    # CVE IDs are put into NVD URLs and API queries. A malformed one would
    # produce a broken lookup that looks like "no data found".
    item = GOOD_ITEM.replace("CVE-2016-2183", "CVE-16-2183")
    with pytest.raises(ValueError, match="CVE"):
        parse_text(nessus_document(one_host("192.0.2.10", item)))


def test_non_numeric_score_raises():
    # A CVSS score of "high" cannot be ranked. Silently treating it as None
    # would hide a critical finding at the bottom of the report.
    item = GOOD_ITEM.replace("<cvss3_base_score>5.9", "<cvss3_base_score>high")
    with pytest.raises(ValueError, match="cvss3_base_score"):
        parse_text(nessus_document(one_host("192.0.2.10", item)))


def test_bad_boolean_raises():
    # exploit_available feeds the risk ranking. "maybe" is neither true nor
    # false, so it must not be guessed either way.
    item = GOOD_ITEM.replace("</ReportItem>", "<exploit_available>maybe</exploit_available></ReportItem>")
    with pytest.raises(ValueError, match="exploit_available"):
        parse_text(nessus_document(one_host("192.0.2.10", item)))


def test_wrong_root_element_raises():
    # Someone might drop an Nmap XML or another tool's export in the inbox.
    # It must be refused clearly, not parsed into zero findings.
    with pytest.raises(ValueError, match="NessusClientData_v2"):
        parse_text('<?xml version="1.0"?><nmaprun></nmaprun>')


def test_malformed_xml_raises():
    # A truncated download is a common real-world failure. It must stop the
    # import, not produce a partial finding list.
    with pytest.raises(ValueError, match="well-formed"):
        parse_text("<NessusClientData_v2><Report>")


def test_missing_file_and_bad_path_raise():
    # A wrong path or wrong type should give a clear ValueError right away.
    with pytest.raises(ValueError):
        parse_nessus.parse_nessus_file(os.path.join(FIXTURES, "missing.nessus"), fixture_scope())
    with pytest.raises(ValueError):
        parse_nessus.parse_nessus_file(None, fixture_scope())


def test_raw_scope_is_refused():
    # Passing the unparsed YAML scope by mistake would compare addresses to
    # strings. It must fail before any host is processed.
    raw = {"include": ["192.0.2.0/24"], "exclude": []}
    with pytest.raises(ValueError):
        parse_nessus.parse_nessus_file(SAMPLE_NESSUS, raw)
