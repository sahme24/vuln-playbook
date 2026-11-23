import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

import nmap_discovery
import scope

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
ENGAGEMENT_FILE = os.path.join(FIXTURES, "engagement_test.yaml")
PASS1_XML = os.path.join(FIXTURES, "nmap_sample.xml")
PASS2_XML = os.path.join(FIXTURES, "nmap_pass2_sample.xml")

EST = timezone(timedelta(hours=-5))
INSIDE_WINDOW = datetime(2026, 12, 2, 12, 0, tzinfo=EST)
AFTER_WINDOW = datetime(2026, 12, 9, 12, 0, tzinfo=EST)


def fixture_engagement():
    return scope.load_engagement(ENGAGEMENT_FILE)


def fixture_scope():
    return scope.build_scope(fixture_engagement())


def write_xml(folder, text):
    path = os.path.join(folder, "scan.xml")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def pass2_host_xml(ports_xml):
    """A one-host pass 2 document with the given <ports> content."""
    return (
        '<?xml version="1.0"?><nmaprun><host><status state="up" reason="user-set"/>'
        '<address addr="192.0.2.30" addrtype="ipv4"/><ports>' + ports_xml + "</ports></host></nmaprun>"
    )


# --- planning and command building -------------------------------------------

def test_plan_pass1_uses_include_ranges_and_overlapping_excludes():
    # Pass 1 must scan exactly the authorized ranges and pass the excluded
    # printer to nmap. Forgetting the exclude would scan a device the client
    # asked us not to touch.
    targets, excludes = nmap_discovery.plan_pass1(fixture_scope())
    assert targets == ["192.0.2.0/24", "198.51.100.0/24"]
    assert excludes == ["192.0.2.250/32"]


def test_build_pass1_command_contains_probes_exclude_and_targets():
    # The command is what actually hits the network. Check the discovery-only
    # flag, the mixed probes, the exclude list and the targets are all present.
    command = nmap_discovery.build_pass1_command(
        ["192.0.2.0/24"], ["192.0.2.250/32"], "standard", "out.xml"
    )
    assert command[0] == "nmap"
    assert "-sn" in command
    assert "-PE" in command
    assert "-PU53,161" in command
    exclude_position = command.index("--exclude")
    assert command[exclude_position + 1] == "192.0.2.250/32"
    assert command[-1] == "192.0.2.0/24"


def test_build_pass1_command_omits_exclude_when_none():
    # An empty "--exclude" argument would make nmap fail, or swallow the next
    # argument as the exclude list.
    command = nmap_discovery.build_pass1_command(["192.0.2.0/24"], [], "standard", "out.xml")
    assert "--exclude" not in command


def test_quiet_profile_is_slower_and_rate_limited():
    # The quiet profile exists to protect fragile networks. It must really be
    # gentler (slower timing plus a packet-rate cap), not just renamed.
    command = nmap_discovery.build_pass1_command(["192.0.2.0/24"], [], "quiet", "out.xml")
    assert "-T2" in command
    assert command[command.index("--max-rate") + 1] == "20"


def test_unknown_profile_raises():
    # A typo like "agressive" must not fall back to some default intensity.
    # Scan intensity is fixed by the engagement, so unknown values are refused.
    with pytest.raises(ValueError):
        nmap_discovery.build_pass1_command(["192.0.2.0/24"], [], "aggressive", "out.xml")


def test_build_pass1_command_needs_targets():
    # nmap with no targets does nothing useful. More importantly, an empty
    # list usually means scope loading went wrong upstream.
    with pytest.raises(ValueError):
        nmap_discovery.build_pass1_command([], [], "standard", "out.xml")


def test_plan_pass2_takes_only_down_hosts():
    # Pass 2 is the slow -Pn sweep. It should only cover hosts pass 1 missed.
    # Re-scanning live hosts wastes the scan window.
    hosts = nmap_discovery.parse_pass1_xml(PASS1_XML)
    assert nmap_discovery.plan_pass2(hosts, fixture_scope()) == [
        "192.0.2.30", "192.0.2.40", "192.0.2.50",
    ]


def test_plan_pass2_refuses_out_of_scope_host():
    # Pass 2 takes its targets from a results file. If that file were tampered
    # with or mixed up, scope.py must still stop an unauthorized host.
    hosts = [{"ip": "203.0.113.50", "state": "down", "reason": "no-response", "hostname": None}]
    with pytest.raises(ValueError):
        nmap_discovery.plan_pass2(hosts, fixture_scope())


def test_build_pass2_command_uses_pn_and_common_ports():
    # -Pn is what makes pass 2 different from pass 1: it probes ports even on
    # hosts that ignored ping.
    command = nmap_discovery.build_pass2_command(["192.0.2.30"], "standard", "out.xml")
    assert "-Pn" in command
    ports = command[command.index("-p") + 1]
    assert "445" in ports.split(",")
    assert command[-1] == "192.0.2.30"


# --- parsing and classification ----------------------------------------------

def test_parse_pass1_reads_up_and_down():
    # Both states matter: "up" hosts become targets and "down" hosts feed pass 2.
    hosts = nmap_discovery.parse_pass1_xml(PASS1_XML)
    assert len(hosts) == 6
    assert hosts[0] == {
        "ip": "192.0.2.10", "state": "up", "reason": "echo-reply", "hostname": "web01.example.test",
    }
    assert hosts[2]["state"] == "down"


def test_parse_pass2_classifies_live_filtered_unresponsive():
    # The three statuses drive what we tell the human: live hosts get scanned,
    # filtered ones may hide behind a firewall, unresponsive ones are probably empty.
    hosts = nmap_discovery.parse_pass2_xml(PASS2_XML)
    statuses = {}
    for host in hosts:
        statuses[host["ip"]] = host["status"]
    assert statuses == {"192.0.2.30": "live", "192.0.2.40": "filtered", "192.0.2.50": "unresponsive"}
    assert hosts[0]["open_ports"] == [445]


def test_closed_port_counts_as_live():
    # A closed port answers with a TCP reset, which proves a host exists.
    # Treating it as unresponsive would hide a real machine from the scan.
    with tempfile.TemporaryDirectory() as folder:
        path = write_xml(folder, pass2_host_xml(
            '<port protocol="tcp" portid="22"><state state="closed" reason="reset"/></port>'
        ))
        hosts = nmap_discovery.parse_pass2_xml(path)
    assert hosts[0]["status"] == "live"
    assert hosts[0]["open_ports"] == []


def test_no_ports_element_is_unresponsive():
    # A host entry with no port data at all gave us nothing. It must not be
    # reported as live by accident.
    with tempfile.TemporaryDirectory() as folder:
        path = write_xml(folder, '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
                                 '<address addr="192.0.2.30" addrtype="ipv4"/></host></nmaprun>')
        hosts = nmap_discovery.parse_pass2_xml(path)
    assert hosts[0]["status"] == "unresponsive"


def test_wrong_xml_root_raises():
    # Feeding a .nessus file to the nmap parser is an easy mix-up. It must
    # fail clearly, not report "zero hosts found".
    with tempfile.TemporaryDirectory() as folder:
        path = write_xml(folder, '<?xml version="1.0"?><NessusClientData_v2/>')
        with pytest.raises(ValueError, match="Nmap"):
            nmap_discovery.parse_pass1_xml(path)


def test_missing_xml_raises():
    # A pass that never produced output must stop the pipeline.
    with pytest.raises(ValueError):
        nmap_discovery.parse_pass1_xml(os.path.join(FIXTURES, "missing.xml"))


# --- run_pass safety gates (dry-run, no packets sent) ------------------------

def test_dry_run_pass1_and_pass2_end_to_end():
    # The dry run is the demo path. Pass 1 then pass 2 must work from the
    # fixtures and record the command that would have run.
    engagement = fixture_engagement()
    with tempfile.TemporaryDirectory() as folder:
        first = nmap_discovery.run_pass(1, engagement, folder, True, PASS1_XML, INSIDE_WINDOW)
        assert first["dry_run"] is True
        assert "-sn" in first["command"]
        with open(os.path.join(folder, "discovery_pass1.json"), "w", encoding="utf-8") as handle:
            json.dump(first, handle)
        second = nmap_discovery.run_pass(2, engagement, folder, True, PASS2_XML, INSIDE_WINDOW)
    assert len(second["hosts"]) == 3


def test_run_pass_refuses_unapproved_scope_even_in_dry_run():
    # The approval gate applies in dry-run too, so the demo shows the real
    # workflow and the gate cannot be bypassed by adding --dry-run.
    engagement = fixture_engagement()
    engagement["approval"]["scope_approved"] = False
    with tempfile.TemporaryDirectory() as folder:
        with pytest.raises(ValueError, match="not approved"):
            nmap_discovery.run_pass(1, engagement, folder, True, PASS1_XML, INSIDE_WINDOW)


def test_live_run_refuses_outside_window():
    # Outside --dry-run, a scan after the window ends must be refused before
    # nmap is called. The window check comes first in run_pass.
    engagement = fixture_engagement()
    with tempfile.TemporaryDirectory() as folder:
        with pytest.raises(ValueError, match="window"):
            nmap_discovery.run_pass(1, engagement, folder, False, None, AFTER_WINDOW)


def test_pass2_requires_pass1_results():
    # Pass 2 depends on pass 1's down list. Running it first must fail
    # clearly instead of sweeping nothing.
    with tempfile.TemporaryDirectory() as folder:
        with pytest.raises(ValueError, match="pass 1"):
            nmap_discovery.run_pass(2, fixture_engagement(), folder, True, PASS2_XML, INSIDE_WINDOW)


def test_pass2_result_with_unplanned_host_raises():
    # If the pass 2 XML lists a host we never asked about, it belongs to a
    # different run. Mixing runs would corrupt the target list.
    with pytest.raises(ValueError, match="not in the planned"):
        nmap_discovery.check_results_match_plan(["192.0.2.99"], ["192.0.2.30"], "pass 2")


def test_invalid_pass_number_raises():
    # Only passes 1 and 2 exist. Anything else is a caller bug.
    with tempfile.TemporaryDirectory() as folder:
        with pytest.raises(ValueError):
            nmap_discovery.run_pass(3, fixture_engagement(), folder, True, PASS1_XML, INSIDE_WINDOW)
