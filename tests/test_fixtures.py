import ipaddress
import os
import re
import xml.etree.ElementTree as ET

import parse_nessus
import scope

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_NESSUS = os.path.join(FIXTURES, "sample.nessus")
NMAP_SAMPLE = os.path.join(FIXTURES, "nmap_sample.xml")
ENGAGEMENT_FILE = os.path.join(FIXTURES, "engagement_test.yaml")

DOCUMENTATION_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

# Four dot-separated groups of 1 to 3 digits, e.g. 192.0.2.10.
IPV4_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def read_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def all_sample_findings_unfiltered():
    """Parse the fixture with a scope wide enough to keep every host, so the
    tests below can look at everything the file contains."""
    wide = scope.build_scope({"scope": {
        "include": ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
        "exclude": [],
    }})
    return parse_nessus.parse_nessus_file(SAMPLE_NESSUS, wide)["findings"]


def test_every_fixture_ip_is_a_documentation_address():
    # The template repo is public. A real address slipping into a fixture
    # would leak client data, or point the dry run at a real network.
    # Only the hand-written files at the top of tests/fixtures are checked.
    # The api/ folder holds trimmed real API responses, where strings such as
    # software version numbers can look like IPs.
    found_any = False
    for name in os.listdir(FIXTURES):
        path = os.path.join(FIXTURES, name)
        if os.path.isdir(path):
            continue
        text = read_text(path)
        for match in IPV4_PATTERN.findall(text):
            found_any = True
            address = ipaddress.ip_address(match)
            inside = False
            for network in DOCUMENTATION_RANGES:
                if address in network:
                    inside = True
            assert inside, name + " contains a non-documentation IP: " + match
    assert found_any


def test_sample_contains_a_kev_listed_cve():
    # The dry run must show a KEV finding ranked first. CVE-2021-44228 is in
    # the CISA KEV catalog, so the fixture must contain it.
    cves = []
    for finding in all_sample_findings_unfiltered():
        for cve in finding["cves"]:
            cves.append(cve)
    assert "CVE-2021-44228" in cves


def test_sample_contains_ubuntu_banner_only_detection():
    # The dry run must send a banner-only detection on Ubuntu to needs-human,
    # so the fixture needs one: Ubuntu OS plus "self-reported version" wording.
    found = False
    for finding in all_sample_findings_unfiltered():
        if finding["operating_system"] is None or finding["description"] is None:
            continue
        is_ubuntu = "Ubuntu" in finding["operating_system"]
        is_banner_only = "self-reported version number" in finding["description"]
        if is_ubuntu and is_banner_only:
            found = True
    assert found


def test_sample_contains_several_informational_plugins():
    # The dry run must show informational plugins being excluded. "Several"
    # means at least three distinct severity-0 plugins.
    info_plugins = []
    for finding in all_sample_findings_unfiltered():
        if finding["severity"] == 0 and finding["plugin_id"] not in info_plugins:
            info_plugins.append(finding["plugin_id"])
    assert len(info_plugins) >= 3


def test_sample_contains_one_cve_reported_by_two_plugins():
    # The duplicate-CVE case tests the related_plugin_ids cross-reference. It
    # needs one CVE that appears under two different plugin IDs.
    plugins_by_cve = {}
    for finding in all_sample_findings_unfiltered():
        for cve in finding["cves"]:
            if cve not in plugins_by_cve:
                plugins_by_cve[cve] = []
            if finding["plugin_id"] not in plugins_by_cve[cve]:
                plugins_by_cve[cve].append(finding["plugin_id"])
    duplicated = []
    for cve in plugins_by_cve:
        if len(plugins_by_cve[cve]) >= 2:
            duplicated.append(cve)
    assert "CVE-2016-2183" in duplicated


def test_sample_contains_a_host_outside_the_test_scope():
    # The dry run must show an out-of-scope host being rejected, so at least
    # one host in the file must fail the test engagement's scope check.
    test_scope = scope.build_scope(scope.load_engagement(ENGAGEMENT_FILE))
    root = ET.parse(SAMPLE_NESSUS).getroot()
    outside = 0
    for report_host in root.iter("ReportHost"):
        try:
            scope.check_in_scope(report_host.get("name"), test_scope)
        except ValueError:
            outside = outside + 1
    assert outside >= 1


def test_nmap_sample_has_up_and_down_hosts():
    # Pass 2 of discovery re-sweeps hosts that pass 1 missed. The fixture
    # must contain both states, or that logic cannot be tested later.
    root = ET.parse(NMAP_SAMPLE).getroot()
    assert root.tag == "nmaprun"
    states = {}
    for host in root.findall("host"):
        address = host.find("address").get("addr")
        states[address] = host.find("status").get("state")
    assert states == {
        "192.0.2.10": "up",
        "192.0.2.20": "up",
        "192.0.2.30": "down",
        "192.0.2.40": "down",
        "192.0.2.50": "down",
        "198.51.100.20": "up",
    }
