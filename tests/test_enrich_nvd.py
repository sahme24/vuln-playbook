import json
import os
import tempfile

import pytest

import cache
import enrich_nvd

CANNED = os.path.join(os.path.dirname(__file__), "fixtures", "api")
NOW = 1796134200.0

REQUESTS = []
SLEPT = []
# A fake clock for rate limiting. Each read moves time forward by 0.1 s, so
# requests look like they happen in quick succession.
CLOCK = [1000.0]


def canned_nvd(cve):
    with open(os.path.join(CANNED, "nvd", cve + ".json"), "r", encoding="utf-8") as handle:
        return json.load(handle)


def fake_get(url, params, headers, timeout):
    """Stands in for NVD: records the request (and headers) and answers from
    canned data, or with an empty result for CVEs that have no canned file."""
    REQUESTS.append({"cve": params["cveId"], "headers": headers})
    path = os.path.join(CANNED, "nvd", params["cveId"] + ".json")
    if not os.path.isfile(path):
        # NVD's real answer for an ID it does not know.
        return {"status": 200, "body": {"vulnerabilities": []}}
    return {"status": 200, "body": canned_nvd(params["cveId"])}


def fake_sleep(seconds):
    SLEPT.append(seconds)
    CLOCK[0] = CLOCK[0] + seconds


def fake_clock():
    CLOCK[0] = CLOCK[0] + 0.1
    return CLOCK[0]


def reset():
    REQUESTS.clear()
    SLEPT.clear()
    CLOCK[0] = 1000.0


# --- parsing ------------------------------------------------------------------

def test_parse_picks_primary_cvss31():
    # The report must cite NVD's own (Primary) CVSS 3.1 score. Taking a
    # vendor's Secondary score could under- or over-state the severity.
    record = enrich_nvd.parse_nvd_response("CVE-2021-44228", canned_nvd("CVE-2021-44228"))
    assert record["found"] is True
    assert record["cvss3_score"] == 10.0
    assert record["cvss3_severity"] == "CRITICAL"
    assert record["cvss3_source"] == "nvd@nist.gov"
    assert record["cvss3_vector"].startswith("CVSS:3.1/")
    assert record["cisa_kev_date_added"] == "2021-12-10"
    assert record["nvd_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


def test_parse_keeps_description_and_caps_references():
    # The description feeds the report text. References are capped so a
    # popular CVE does not flood the evidence list.
    record = enrich_nvd.parse_nvd_response("CVE-2016-2183", canned_nvd("CVE-2016-2183"))
    assert record["description"] is not None
    assert len(record["references"]) <= enrich_nvd.MAX_REFERENCES


def test_unknown_cve_is_not_found():
    # NVD answers an unknown ID with 200 and an empty list. That is
    # "not found", not an error, and the record must say so.
    record = enrich_nvd.parse_nvd_response("CVE-2099-0001", {"vulnerabilities": []})
    assert record["found"] is False


def test_pick_cvss_falls_back_to_secondary_and_v30():
    # Some CVEs only have a CNA (Secondary) score or only a v3.0 score.
    # They must still get a score instead of none.
    metrics = {"cvssMetricV30": [{"type": "Secondary", "cvssData": {"baseScore": 7.5}}]}
    entry = enrich_nvd.pick_cvss(metrics, ["cvssMetricV31", "cvssMetricV30"])
    assert entry["cvssData"]["baseScore"] == 7.5
    assert enrich_nvd.pick_cvss({}, ["cvssMetricV31"]) is None


def test_mismatched_cve_id_raises():
    # If NVD (or a cache mix-up) returned a different CVE, attaching its
    # score to ours would be fabricated evidence.
    with pytest.raises(ValueError, match="when asked for"):
        enrich_nvd.parse_nvd_response("CVE-2016-2183", canned_nvd("CVE-2021-44228"))


def test_malformed_response_raises():
    # A response without the vulnerabilities list means the API format
    # changed. Silently treating it as "not found" would hide real CVEs.
    with pytest.raises(ValueError):
        enrich_nvd.parse_nvd_response("CVE-2021-44228", {"error": "oops"})


# --- rate limiting ------------------------------------------------------------

def test_seconds_to_wait_under_limit_is_zero():
    # Fewer than 5 requests in the last 30 s: no need to wait.
    assert enrich_nvd.seconds_to_wait([100.0, 101.0], 105.0, 5, 30) == 0.0


def test_seconds_to_wait_full_window():
    # 5 requests already in the window: wait until the oldest (at t=100) is
    # 30 s old, i.e. 25 s from t=105.
    times = [100.0, 101.0, 102.0, 103.0, 104.0]
    assert enrich_nvd.seconds_to_wait(times, 105.0, 5, 30) == 25.0


def test_seconds_to_wait_ignores_old_requests():
    # Requests older than the window no longer count against the limit.
    times = [10.0, 11.0, 12.0, 13.0, 104.0]
    assert enrich_nvd.seconds_to_wait(times, 105.0, 5, 30) == 0.0


def test_six_lookups_without_key_sleep_once():
    # Without a key NVD allows 5 requests per 30 s. The 6th live lookup must
    # wait for the window to clear, or NVD starts answering 403 and may block
    # us for longer.
    reset()
    connection = cache.open_cache(":memory:")
    cves = ["CVE-2021-44228", "CVE-2016-2183", "CVE-2023-48795", "CVE-2023-51385",
            "CVE-2008-5161", "CVE-2099-0001"]
    enrich_nvd.enrich_nvd(cves, connection, NOW, None, fake_get, fake_sleep, fake_clock, None)
    assert len(REQUESTS) == 6
    assert len(SLEPT) == 1
    # The fake clock advanced under 1 s during the first five requests, so the
    # wait is just under 30 s.
    assert SLEPT[0] > 29
    assert SLEPT[0] <= 30


def test_api_key_raises_limit_and_is_sent():
    # With a key the limit is 50, so 5 quick lookups never wait, and the key
    # must actually be sent in the apiKey header or NVD applies the low limit.
    reset()
    connection = cache.open_cache(":memory:")
    cves = ["CVE-2021-44228", "CVE-2016-2183"]
    enrich_nvd.enrich_nvd(cves, connection, NOW, "test-key", fake_get, fake_sleep, fake_clock, None)
    assert REQUESTS[0]["headers"] == {"apiKey": "test-key"}
    assert SLEPT == []


def test_cached_lookup_makes_no_request():
    # NVD data is cached for 7 days. A repeat lookup must not use up the
    # rate limit.
    reset()
    connection = cache.open_cache(":memory:")
    enrich_nvd.enrich_nvd(["CVE-2021-44228"], connection, NOW, None, fake_get, fake_sleep, fake_clock, None)
    enrich_nvd.enrich_nvd(["CVE-2021-44228"], connection, NOW + 3600, None, fake_get, fake_sleep, fake_clock, None)
    assert len(REQUESTS) == 1


def test_dry_run_reads_canned_files_only():
    # Dry-run must not touch the network: the fake getter records nothing.
    reset()
    records = enrich_nvd.enrich_nvd(["CVE-2023-48795"], None, NOW, None, fake_get, fake_sleep, fake_clock, CANNED)
    assert REQUESTS == []
    assert records["CVE-2023-48795"]["found"] is True


def test_dry_run_missing_canned_file_raises():
    # A CVE with no canned response means the dry-run data is incomplete.
    # That must be reported, not turned into "not found".
    reset()
    with pytest.raises(ValueError, match="canned"):
        enrich_nvd.enrich_nvd(["CVE-2099-0001"], None, NOW, None, fake_get, fake_sleep, fake_clock, CANNED)


# --- API key file ------------------------------------------------------------

def test_read_api_key_from_env_file():
    # The key lives in .env (gitignored). Comments and blank lines must be skipped.
    previous = os.environ.pop("NVD_API_KEY", None)
    try:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, ".env")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# comment\n\nNVD_API_KEY=abc123\n")
            assert enrich_nvd.read_api_key(path) == "abc123"
    finally:
        if previous is not None:
            os.environ["NVD_API_KEY"] = previous


def test_read_api_key_empty_value_means_no_key():
    # .env.example ships with "NVD_API_KEY=" (empty). That must mean "no key",
    # not a key made of an empty string that NVD would reject.
    previous = os.environ.pop("NVD_API_KEY", None)
    try:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, ".env")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("NVD_API_KEY=\n")
            assert enrich_nvd.read_api_key(path) is None
            assert enrich_nvd.read_api_key(os.path.join(folder, "missing.env")) is None
    finally:
        if previous is not None:
            os.environ["NVD_API_KEY"] = previous
