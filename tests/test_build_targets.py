import os

import pytest

import build_targets
import nmap_discovery
import scope

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
ENGAGEMENT_FILE = os.path.join(FIXTURES, "engagement_test.yaml")


def fixture_scope():
    return scope.build_scope(scope.load_engagement(ENGAGEMENT_FILE))


def pass1_host(ip, state):
    return {"ip": ip, "state": state, "reason": None, "hostname": None}


def pass2_host(ip, status):
    return {"ip": ip, "status": status, "open_ports": [], "hostname": None}


def test_fixture_passes_merge_into_expected_groups():
    # This is the exact dry-run result. Live hosts from both passes become
    # targets, and filtered/unresponsive hosts are kept apart for the summary.
    pass1 = nmap_discovery.parse_pass1_xml(os.path.join(FIXTURES, "nmap_sample.xml"))
    pass2 = nmap_discovery.parse_pass2_xml(os.path.join(FIXTURES, "nmap_pass2_sample.xml"))
    hosts = build_targets.build_targets(pass1, pass2, fixture_scope())
    assert hosts["live"] == ["192.0.2.10", "192.0.2.20", "192.0.2.30", "198.51.100.20"]
    assert hosts["filtered"] == ["192.0.2.40"]
    assert hosts["unresponsive"] == ["192.0.2.50"]


def test_host_found_only_by_pass2_is_a_target():
    # The whole point of pass 2: a host that ignored every ping but has an
    # open port must still reach Nessus.
    hosts = build_targets.build_targets(
        [pass1_host("192.0.2.30", "down")], [pass2_host("192.0.2.30", "live")], fixture_scope()
    )
    assert hosts["live"] == ["192.0.2.30"]


def test_live_hosts_sorted_numerically():
    # targets.txt is read by people too. Text order puts .10 before .9,
    # which makes the list hard to check against the scope.
    hosts = build_targets.build_targets(
        [pass1_host("192.0.2.10", "up"), pass1_host("192.0.2.9", "up")], [], fixture_scope()
    )
    assert hosts["live"] == ["192.0.2.9", "192.0.2.10"]


def test_down_host_missing_from_pass2_raises():
    # If pass 2 never reported a host, it did not finish. Building targets anyway
    # would silently drop a host that might be live.
    with pytest.raises(ValueError, match="missing from pass 2"):
        build_targets.build_targets([pass1_host("192.0.2.30", "down")], [], fixture_scope())


def test_pass2_host_not_down_in_pass1_raises():
    # A pass 2 entry for a host pass 1 never marked down means the two files
    # are from different runs. Mixing them would give a wrong target list.
    with pytest.raises(ValueError, match="do not belong together"):
        build_targets.build_targets(
            [pass1_host("192.0.2.10", "up")], [pass2_host("192.0.2.10", "live")], fixture_scope()
        )


def test_out_of_scope_live_host_raises():
    # Last line of defence before Nessus: even if an out-of-scope host got into
    # the results somehow, it must not be written to targets.txt.
    with pytest.raises(ValueError):
        build_targets.build_targets([pass1_host("203.0.113.50", "up")], [], fixture_scope())


def test_unknown_states_raise():
    # A state we don't understand must not be guessed into one of the groups.
    with pytest.raises(ValueError):
        build_targets.build_targets([pass1_host("192.0.2.10", "maybe")], [], fixture_scope())
    with pytest.raises(ValueError):
        build_targets.build_targets(
            [pass1_host("192.0.2.30", "down")], [pass2_host("192.0.2.30", "sleepy")], fixture_scope()
        )


def test_non_list_input_raises():
    # Passing the whole JSON result instead of its "hosts" list is an easy
    # mistake, and must fail loudly.
    with pytest.raises(ValueError):
        build_targets.build_targets({"hosts": []}, [], fixture_scope())
