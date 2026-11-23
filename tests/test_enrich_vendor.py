import json
import os

import pytest

import cache
import enrich_vendor

CANNED = os.path.join(os.path.dirname(__file__), "fixtures", "api")
NOW = 1796134200.0

REQUESTS = []


def canned(folder, cve):
    with open(os.path.join(CANNED, folder, cve + ".json"), "r", encoding="utf-8") as handle:
        return json.load(handle)


def fake_get_404(url, params, headers, timeout):
    REQUESTS.append(url)
    return {"status": 404, "body": None}


def fake_get_down(url, params, headers, timeout):
    REQUESTS.append(url)
    return {"status": 504, "body": None}


def fake_get_ubuntu(url, params, headers, timeout):
    REQUESTS.append(url)
    return {"status": 200, "body": canned("vendor_ubuntu", "CVE-2023-48795")}


def fake_sleep(seconds):
    pass


def make_group(plugin_name, operating_system, cves):
    """A grouped finding with one affected host. Only the fields
    enrich_vendor reads are filled in."""
    return {
        "plugin_id": 900101,
        "plugin_name": plugin_name,
        "cves": cves,
        "affected": [{"host_ip": "192.0.2.10", "operating_system": operating_system}],
    }


# --- vendor and package detection --------------------------------------------

def test_detect_vendor_for_supported_systems():
    # The vendor source is chosen from the OS string. A wrong mapping would
    # check the wrong advisory and give a meaningless status.
    assert enrich_vendor.detect_vendor("Linux Kernel 5.15 on Ubuntu 22.04") == {"vendor": "ubuntu", "release": "jammy"}
    assert enrich_vendor.detect_vendor("Linux Kernel 4.18.0 on Red Hat Enterprise Linux 8") == {
        "vendor": "redhat", "release": "Red Hat Enterprise Linux 8"}
    assert enrich_vendor.detect_vendor("Microsoft Windows Server 2019 Standard") == {
        "vendor": "msrc", "release": "Windows Server 2019"}
    assert enrich_vendor.detect_vendor("Microsoft Windows Server 2012 R2 Standard")["release"] == "Windows Server 2012 R2"


def test_detect_vendor_unsupported_and_unknown_release():
    # An unsupported OS gives vendor None (nothing to look up). An Ubuntu
    # release missing from our table keeps the vendor, so the record can
    # explain why there is no data.
    assert enrich_vendor.detect_vendor("Embedded printer firmware") == {"vendor": None, "release": None}
    assert enrich_vendor.detect_vendor(None) == {"vendor": None, "release": None}
    assert enrich_vendor.detect_vendor("Ubuntu 12.04") == {"vendor": "ubuntu", "release": None}


def test_detect_vendor_rejects_non_string():
    # A number in the OS field means the input is corrupt.
    with pytest.raises(ValueError):
        enrich_vendor.detect_vendor(22.04)


def test_package_hint_prefers_specific_keyword():
    # "Apache Log4j" must map to log4j, not to the Apache web server. Mixing
    # them up would check the wrong package's fix status.
    assert enrich_vendor.package_hint("Apache Log4j Remote Code Execution (Log4Shell)", "redhat") == "log4j"
    assert enrich_vendor.package_hint("OpenSSH < 9.6 Multiple Vulnerabilities", "ubuntu") == "openssh"
    assert enrich_vendor.package_hint("SSL Medium Strength Cipher Suites Supported (SWEET32)", "ubuntu") is None
    assert enrich_vendor.package_hint("OpenSSH < 9.6", "msrc") is None


# --- parsing real (canned) vendor data ----------------------------------------

def test_ubuntu_released_means_fixed_with_version():
    # CVE-2023-48795 is fixed in jammy's openssh 1:8.9p1-3ubuntu0.5. The fixed
    # build is what a human compares against the installed package.
    record = enrich_vendor.parse_ubuntu("CVE-2023-48795", canned("vendor_ubuntu", "CVE-2023-48795"), "jammy", "openssh")
    assert record["status"] == "fixed"
    assert record["fixed_version"] == "1:8.9p1-3ubuntu0.5"


def test_ubuntu_package_choice_matters():
    # The same CVE has different statuses per package (libssh2 is
    # not-affected in jammy). Picking the wrong package would flip the verdict.
    record = enrich_vendor.parse_ubuntu("CVE-2023-48795", canned("vendor_ubuntu", "CVE-2023-48795"), "jammy", "libssh2")
    assert record["status"] == "not-affected"


def test_ubuntu_without_package_or_record_is_unknown():
    # With no package mapping or no Ubuntu record we know nothing, and the
    # status must say "unknown" rather than guess either way.
    raw = canned("vendor_ubuntu", "CVE-2023-48795")
    assert enrich_vendor.parse_ubuntu("CVE-2023-48795", raw, "jammy", None)["status"] == "unknown"
    assert enrich_vendor.parse_ubuntu("CVE-2023-48795", None, "jammy", "openssh")["status"] == "unknown"


def test_redhat_rhel8_log4j_not_affected():
    # Red Hat says RHEL 8's own log4j package is not affected by Log4Shell.
    # The parser must report that faithfully. Triage then decides it does not
    # outweigh a direct detection.
    record = enrich_vendor.parse_redhat(
        "CVE-2021-44228", canned("vendor_redhat", "CVE-2021-44228"), "Red Hat Enterprise Linux 8", "log4j"
    )
    assert record["status"] == "not-affected"


def test_redhat_rows_that_disagree_give_unknown():
    # Without a package hint, rows for one product can disagree. Picking one
    # would be a guess, so the answer is "unknown".
    raw = {"package_state": [
        {"product_name": "Red Hat Enterprise Linux 9", "fix_state": "Not affected", "package_name": "a"},
        {"product_name": "Red Hat Enterprise Linux 9", "fix_state": "Affected", "package_name": "b"},
    ]}
    record = enrich_vendor.parse_redhat("CVE-2000-0001", raw, "Red Hat Enterprise Linux 9", None)
    assert record["status"] == "unknown"


def test_redhat_released_fix_wins():
    # An RHSA advisory for the product means a fix ships. That is "fixed" with
    # the advisory ID as the evidence.
    raw = {"affected_release": [
        {"product_name": "Red Hat Enterprise Linux 9", "advisory": "RHSA-2000:0001", "package": "openssh-8.7p1-1.el9"},
    ]}
    record = enrich_vendor.parse_redhat("CVE-2000-0001", raw, "Red Hat Enterprise Linux 9", "openssh")
    assert record["status"] == "fixed"
    assert record["fixed_version"] == "RHSA-2000:0001"


def test_msrc_lists_kbs_or_unknown():
    # MSRC only lists affected products. A match gives "fixed" with the KB
    # numbers. No match gives "unknown", never "not-affected".
    raw = {"value": [{"product": "Windows Server 2019", "kbArticles": [{"articleName": "5043050"}]}]}
    record = enrich_vendor.parse_msrc("CVE-2024-38063", raw, "Windows Server 2019")
    assert record["status"] == "fixed"
    assert record["fixed_version"] == "KB5043050"
    empty = enrich_vendor.parse_msrc("CVE-2016-2183", canned("vendor_msrc", "CVE-2016-2183"), "Windows Server 2019")
    assert empty["status"] == "unknown"


def test_malformed_vendor_data_raises():
    # A changed API format must stop the run, not read as "no data".
    with pytest.raises(ValueError):
        enrich_vendor.parse_ubuntu("CVE-2023-48795", {"pkgs": []}, "jammy", "openssh")
    with pytest.raises(ValueError):
        enrich_vendor.parse_msrc("CVE-2016-2183", {"items": []}, "Windows Server 2019")


# --- enrich_vendor end to end -------------------------------------------------

def test_dry_run_records_for_banner_finding():
    # The dry-run finding: CVE-2023-48795 is "fixed", and CVE-2023-51385 has
    # no canned response, which must show up as a lookup_error.
    group = make_group("OpenSSH < 9.6 Multiple Vulnerabilities", "Linux Kernel 5.15 on Ubuntu 22.04",
                       ["CVE-2023-48795", "CVE-2023-51385"])
    records = enrich_vendor.enrich_vendor(group, None, NOW, fake_get_404, fake_sleep, CANNED)
    assert records[0]["status"] == "fixed"
    assert records[1]["status"] == "unknown"
    assert records[1]["lookup_error"] is not None


def test_vendor_outage_is_recorded_not_raised():
    # Vendor data is optional evidence. A vendor API outage must be visible in
    # the record, but it must not abort the whole verification.
    group = make_group("OpenSSH < 9.6", "Ubuntu 22.04", ["CVE-2023-48795"])
    connection = cache.open_cache(":memory:")
    records = enrich_vendor.enrich_vendor(group, connection, NOW, fake_get_down, fake_sleep, None)
    assert records[0]["status"] == "unknown"
    assert "504" in records[0]["lookup_error"]


def test_404_is_cached_as_not_found():
    # A "no record" answer is cached too, so the same CVE is not asked again
    # within the TTL.
    REQUESTS.clear()
    group = make_group("OpenSSH < 9.6", "Ubuntu 22.04", ["CVE-2099-0001"])
    connection = cache.open_cache(":memory:")
    enrich_vendor.enrich_vendor(group, connection, NOW, fake_get_404, fake_sleep, None)
    records = enrich_vendor.enrich_vendor(group, connection, NOW + 60, fake_get_404, fake_sleep, None)
    assert len(REQUESTS) == 1
    assert records[0]["details"] == "Ubuntu does not track this CVE"


def test_live_lookup_is_cached():
    # Second lookup within a day must come from cache.db.
    REQUESTS.clear()
    group = make_group("OpenSSH < 9.6", "Ubuntu 22.04", ["CVE-2023-48795"])
    connection = cache.open_cache(":memory:")
    enrich_vendor.enrich_vendor(group, connection, NOW, fake_get_ubuntu, fake_sleep, None)
    enrich_vendor.enrich_vendor(group, connection, NOW + 60, fake_get_ubuntu, fake_sleep, None)
    assert len(REQUESTS) == 1


def test_unsupported_os_gives_no_records():
    # No supported vendor means nothing to look up, so an empty list, not a fake record.
    group = make_group("Some plugin", "Embedded printer firmware", ["CVE-2023-48795"])
    assert enrich_vendor.enrich_vendor(group, None, NOW, fake_get_404, fake_sleep, CANNED) == []


def test_bad_group_raises():
    # A raw finding (not a group) lacks 'affected', so refuse it.
    with pytest.raises(ValueError):
        enrich_vendor.enrich_vendor({"cves": []}, None, NOW, fake_get_404, fake_sleep, CANNED)
