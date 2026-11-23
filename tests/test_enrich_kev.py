import json
import os

import pytest

import cache
import enrich_kev

CANNED = os.path.join(os.path.dirname(__file__), "fixtures", "api")
NOW = 1796134200.0

CALLS = []


def canned_catalog():
    with open(os.path.join(CANNED, "kev", "catalog.json"), "r", encoding="utf-8") as handle:
        return json.load(handle)


def fake_get_catalog(url, params, headers, timeout):
    """Stands in for the network: records the call and returns the canned feed."""
    CALLS.append(url)
    return {"status": 200, "body": canned_catalog()}


def fake_sleep(seconds):
    pass


def test_kev_cve_is_found_with_dates():
    # Log4Shell is in KEV. The record must say so and carry the date added,
    # which the handoff cites as evidence.
    records = enrich_kev.enrich_kev(["CVE-2021-44228"], canned_catalog())
    record = records["CVE-2021-44228"]
    assert record["in_kev"] is True
    assert record["date_added"] == "2021-12-10"
    assert record["known_ransomware_use"] == "Known"


def test_non_kev_cve_is_not_found():
    # A CVE missing from KEV must come back as in_kev False, an explicit
    # answer the triage rules can test, not as a missing key.
    records = enrich_kev.enrich_kev(["CVE-2023-48795"], canned_catalog())
    assert records["CVE-2023-48795"]["in_kev"] is False


def test_empty_cve_list_gives_empty_result():
    # Findings without CVEs (like TLS 1.0) still pass through enrichment.
    assert enrich_kev.enrich_kev([], canned_catalog()) == {}


def test_catalog_downloaded_once_then_cached():
    # The spec says to download KEV once per run. A second lookup within the
    # day must come from the cache, not a second 2 MB download.
    CALLS.clear()
    connection = cache.open_cache(":memory:")
    enrich_kev.get_kev_catalog(connection, NOW, fake_get_catalog, fake_sleep, None)
    enrich_kev.get_kev_catalog(connection, NOW + 3600, fake_get_catalog, fake_sleep, None)
    assert len(CALLS) == 1


def test_dry_run_uses_canned_catalog_without_network():
    # In dry-run no network call may happen. The fake getter would record
    # one if it did.
    CALLS.clear()
    catalog = enrich_kev.get_kev_catalog(None, NOW, fake_get_catalog, fake_sleep, CANNED)
    assert len(CALLS) == 0
    assert catalog["count"] == len(catalog["vulnerabilities"])


def test_changed_feed_format_raises():
    # If CISA renamed the list, every CVE would wrongly look "not in KEV".
    # A format change must stop the run instead.
    with pytest.raises(ValueError, match="format"):
        enrich_kev.enrich_kev(["CVE-2021-44228"], {"entries": []})
    with pytest.raises(ValueError):
        enrich_kev.enrich_kev(["CVE-2021-44228"], {"vulnerabilities": [{"id": "x"}]})


def test_non_list_cves_raises():
    # A single CVE string passed by mistake would be looped over letter by letter.
    with pytest.raises(ValueError):
        enrich_kev.enrich_kev("CVE-2021-44228", canned_catalog())
