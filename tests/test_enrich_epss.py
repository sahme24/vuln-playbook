import os

import pytest

import cache
import enrich_epss

CANNED = os.path.join(os.path.dirname(__file__), "fixtures", "api")
NOW = 1796134200.0

REQUESTS = []


def fake_get(url, params, headers, timeout):
    """Answer like the EPSS API: return a score for every CVE asked about,
    except CVE-2099-0001, which EPSS 'does not know'. Records each request."""
    REQUESTS.append(params["cve"])
    data = []
    for cve in params["cve"].split(","):
        if cve != "CVE-2099-0001":
            data.append({"cve": cve, "epss": "0.500000000", "percentile": "0.900000000", "date": "2026-11-22"})
    return {"status": 200, "body": {"status": "OK", "data": data}}


def fake_sleep(seconds):
    pass


def test_make_batches_splits_and_keeps_remainder():
    # 250 CVEs in batches of 100 must give 100, 100, 50. Dropping the last
    # partial batch would silently lose scores.
    items = []
    for number in range(250):
        items.append("CVE-2020-" + str(1000 + number))
    batches = enrich_epss.make_batches(items, 100)
    assert len(batches) == 3
    assert len(batches[2]) == 50


def test_make_batches_rejects_bad_size():
    # A batch size of 0 would loop forever or divide by zero in other designs.
    with pytest.raises(ValueError):
        enrich_epss.make_batches(["a"], 0)


def test_canned_scores_are_floats():
    # The API sends scores as strings. They must become floats so the report
    # can sort by EPSS.
    records = enrich_epss.enrich_epss(["CVE-2021-44228"], None, NOW, fake_get, fake_sleep, CANNED)
    record = records["CVE-2021-44228"]
    assert record["found"] is True
    assert type(record["epss"]) is float
    assert record["epss"] > 0.9


def test_one_request_for_many_cves():
    # Batching is the point: several CVEs must cost one request, not one each.
    REQUESTS.clear()
    connection = cache.open_cache(":memory:")
    cves = ["CVE-2021-44228", "CVE-2016-2183", "CVE-2023-48795"]
    enrich_epss.enrich_epss(cves, connection, NOW, fake_get, fake_sleep, None)
    assert len(REQUESTS) == 1


def test_cached_cves_are_not_requested_again():
    # The second run within a day should send nothing. Every score is cached
    # per CVE.
    REQUESTS.clear()
    connection = cache.open_cache(":memory:")
    enrich_epss.enrich_epss(["CVE-2021-44228"], connection, NOW, fake_get, fake_sleep, None)
    enrich_epss.enrich_epss(["CVE-2021-44228"], connection, NOW + 60, fake_get, fake_sleep, None)
    assert len(REQUESTS) == 1


def test_unknown_cve_is_recorded_as_not_found_and_cached():
    # New CVEs often have no EPSS score yet. That must be an explicit
    # found=False (not a crash), and caching it avoids asking again every run.
    REQUESTS.clear()
    connection = cache.open_cache(":memory:")
    records = enrich_epss.enrich_epss(["CVE-2099-0001"], connection, NOW, fake_get, fake_sleep, None)
    assert records["CVE-2099-0001"]["found"] is False
    assert records["CVE-2099-0001"]["epss"] is None
    enrich_epss.enrich_epss(["CVE-2099-0001"], connection, NOW + 60, fake_get, fake_sleep, None)
    assert len(REQUESTS) == 1


def test_out_of_range_score_raises():
    # A probability above 1 means the data is corrupt. Ranking on it would
    # push a finding to the top for no real reason.
    with pytest.raises(ValueError):
        enrich_epss.epss_record("CVE-2021-44228", {"epss": "1.7", "percentile": "0.5"})


def test_non_numeric_score_raises():
    # A missing or text score must not quietly become 0, which would read as
    # "no exploitation expected".
    with pytest.raises(ValueError):
        enrich_epss.epss_record("CVE-2021-44228", {"epss": "n/a", "percentile": "0.5"})


def test_changed_response_format_raises():
    # Without a 'data' list every CVE would look unscored. Stop instead.
    with pytest.raises(ValueError):
        enrich_epss.parse_epss_response({"results": []})
