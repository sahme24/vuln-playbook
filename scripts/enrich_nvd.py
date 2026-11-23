"""Look up CVE details in the NVD (National Vulnerability Database) API 2.0.

From NVD we take the authoritative CVSS score and vector, the description,
the publication dates and the reference links. The verifier compares the
NVD score with Nessus's, and the report cites the NVD page as evidence.

Rate limits (set by NVD):
    without an API key:  5 requests in any 30-second window
    with an API key:    50 requests in any 30-second window
The key is read from NVD_API_KEY (in the environment or the .env file) and
sent in the "apiKey" header. Before each request, seconds_to_wait() checks
how many requests were made in the last 30 seconds and sleeps if the
window is full. If NVD still answers 403 or 429 (for example because two
verifier processes share one key), get_with_retry() backs off and tries again.

Output per finding: engagement/output/enrichment/<plugin_id>/nvd.json

CLI usage:
    python scripts/enrich_nvd.py --grouped engagement/output/grouped.json --plugin-id 900104
    python scripts/enrich_nvd.py --dry-run
"""

import argparse
import json
import os
import time

import cache
import group_findings
import http_client

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"
WINDOW_SECONDS = 30
LIMIT_WITHOUT_KEY = 5
LIMIT_WITH_KEY = 50

# Cap on how many reference links are kept per CVE. Popular CVEs have
# hundreds, and the report only needs the first few.
MAX_REFERENCES = 10


def read_api_key(env_path):
    """Return the NVD API key, or None if there is none.

    None is a valid answer: the API works without a key, just more slowly.
    The environment variable wins over the .env file, so a key can be set
    for one run without editing the file. The .env file is read by hand
    (simple KEY=VALUE lines), so no extra dependency is needed for it.
    """
    from_environment = os.environ.get("NVD_API_KEY")
    if from_environment is not None and from_environment.strip() != "":
        return from_environment.strip()
    if type(env_path) is not str or not os.path.isfile(env_path):
        return None
    with open(env_path, "r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if text == "" or text.startswith("#") or "=" not in text:
                continue
            name, value = text.split("=", 1)
            if name.strip() == "NVD_API_KEY" and value.strip() != "":
                return value.strip()
    return None


def seconds_to_wait(request_times, now, max_requests, window_seconds):
    """How long to sleep before the next request so we stay under the limit.

    request_times holds the clock times of earlier requests. Only the ones
    inside the last `window_seconds` count. If fewer than max_requests are
    in the window, no wait is needed. Otherwise wait until the oldest one in
    the window drops out of it.
    """
    if type(request_times) is not list:
        raise ValueError("request_times must be a list")
    recent = []
    for moment in request_times:
        if now - moment < window_seconds:
            recent.append(moment)
    if len(recent) < max_requests:
        return 0.0
    oldest = recent[0]
    for moment in recent:
        if moment < oldest:
            oldest = moment
    return window_seconds - (now - oldest)


def pick_cvss(metrics, metric_names):
    """Pick one CVSS entry from NVD's metrics block.

    metric_names is in order of preference (for example v3.1 before v3.0).
    Inside each list, the "Primary" entry (scored by NVD itself) is
    preferred over "Secondary" ones (scored by the vendor or another CNA).
    Returns the chosen entry, or None if the CVE has no score of these kinds.
    """
    for name in metric_names:
        if name not in metrics:
            continue
        entries = metrics[name]
        if type(entries) is not list or len(entries) == 0:
            continue
        for entry in entries:
            if entry.get("type") == "Primary":
                return entry
        return entries[0]
    return None


def parse_nvd_response(cve, raw):
    """Turn one NVD API response into a normalized record."""
    if type(raw) is not dict or "vulnerabilities" not in raw:
        raise ValueError("NVD response for " + cve + " has no 'vulnerabilities' list")
    if len(raw["vulnerabilities"]) == 0:
        # NVD answers 200 with an empty list for an ID it does not know.
        return {"cve": cve, "found": False, "nvd_url": NVD_DETAIL_URL + cve}

    item = raw["vulnerabilities"][0]["cve"]
    if item.get("id") != cve:
        raise ValueError("NVD returned " + repr(item.get("id")) + " when asked for " + cve)

    description = None
    for entry in item.get("descriptions", []):
        if entry.get("lang") == "en":
            description = entry.get("value")
            break

    metrics = item.get("metrics", {})
    cvss3 = pick_cvss(metrics, ["cvssMetricV31", "cvssMetricV30"])
    cvss2 = pick_cvss(metrics, ["cvssMetricV2"])

    record = {
        "cve": cve,
        "found": True,
        "nvd_url": NVD_DETAIL_URL + cve,
        "vuln_status": item.get("vulnStatus"),
        "published": item.get("published"),
        "last_modified": item.get("lastModified"),
        "description": description,
        "cvss3_score": None,
        "cvss3_severity": None,
        "cvss3_vector": None,
        "cvss3_version": None,
        "cvss3_source": None,
        "cvss2_score": None,
        # NVD also copies the KEV date into the CVE record. Kept so the
        # verifier can cross-check it against the KEV catalog itself.
        "cisa_kev_date_added": item.get("cisaExploitAdd"),
        "references": [],
    }
    if cvss3 is not None:
        data = cvss3["cvssData"]
        record["cvss3_score"] = data.get("baseScore")
        record["cvss3_severity"] = data.get("baseSeverity")
        record["cvss3_vector"] = data.get("vectorString")
        record["cvss3_version"] = data.get("version")
        record["cvss3_source"] = cvss3.get("source")
    if cvss2 is not None:
        record["cvss2_score"] = cvss2["cvssData"].get("baseScore")

    for reference in item.get("references", []):
        if len(record["references"]) >= MAX_REFERENCES:
            break
        if "url" in reference:
            record["references"].append(reference["url"])
    return record


def fetch_nvd(cve, api_key, http_get, sleep_fn):
    """Fetch one CVE live. Raises RuntimeError if NVD cannot be reached."""
    headers = None
    if api_key is not None:
        headers = {"apiKey": api_key}
    # NVD asks clients to wait about 6 seconds after being throttled, so the
    # backoff starts there.
    response = http_client.get_with_retry(
        NVD_URL, {"cveId": cve}, headers, http_get, sleep_fn, 5, 6.0
    )
    if response["status"] != 200:
        raise RuntimeError("NVD returned HTTP " + str(response["status"]) + " for " + cve)
    return response["body"]


def load_canned_nvd(cve, canned_dir):
    path = os.path.join(canned_dir, "nvd", cve + ".json")
    if not os.path.isfile(path):
        raise ValueError("canned NVD response not found: " + path)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def enrich_nvd(cves, connection, now, api_key, http_get, sleep_fn, clock_fn, canned_dir):
    """Return {cve: nvd_record} for every CVE in the list.

    clock_fn gives the current time for rate limiting (time.monotonic in real
    use, which never jumps backwards when the system clock is adjusted).
    `now` is wall-clock time, used for the cache timestamps.
    """
    if type(cves) is not list:
        raise ValueError("cves must be a list")
    limit = LIMIT_WITHOUT_KEY
    if api_key is not None:
        limit = LIMIT_WITH_KEY

    request_times = []
    records = {}
    for cve in cves:
        if canned_dir is not None:
            raw = load_canned_nvd(cve, canned_dir)
        else:
            raw = cache.cache_get(connection, "nvd", cve, now)
            if raw is None:
                wait = seconds_to_wait(request_times, clock_fn(), limit, WINDOW_SECONDS)
                if wait > 0:
                    sleep_fn(wait)
                request_times.append(clock_fn())
                raw = fetch_nvd(cve, api_key, http_get, sleep_fn)
                cache.cache_put(connection, "nvd", cve, raw, now)
        records[cve] = parse_nvd_response(cve, raw)
    return records


def main():
    parser = argparse.ArgumentParser(description="Look up finding CVEs in the NVD API 2.0.")
    parser.add_argument("--grouped", default="engagement/output/grouped.json")
    parser.add_argument("--plugin-id", type=int, default=None, help="only this finding")
    parser.add_argument("--output-dir", default="engagement/output")
    parser.add_argument("--cache", default="cache.db")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--dry-run", action="store_true", help="use canned data, no network")
    parser.add_argument("--canned-dir", default=os.path.join("tests", "fixtures", "api"))
    args = parser.parse_args()

    canned_dir = None
    connection = None
    if args.dry_run:
        canned_dir = args.canned_dir
    else:
        connection = cache.open_cache(args.cache)
    api_key = read_api_key(args.env_file)

    groups = group_findings.load_groups(args.grouped, args.plugin_id)

    # One call for all CVEs, so the rate limiter sees every request of the
    # run (calling once per finding would reset its count each time).
    all_cves = []
    for group in groups:
        for cve in group["cves"]:
            if cve not in all_cves:
                all_cves.append(cve)
    all_records = enrich_nvd(
        all_cves, connection, time.time(), api_key,
        http_client.live_get, time.sleep, time.monotonic, canned_dir,
    )

    for group in groups:
        records = {}
        for cve in group["cves"]:
            records[cve] = all_records[cve]
        folder = os.path.join(args.output_dir, "enrichment", str(group["plugin_id"]))
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "nvd.json"), "w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
    print("NVD: enriched " + str(len(groups)) + " finding(s)")


if __name__ == "__main__":
    main()
