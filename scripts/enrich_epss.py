"""Look up EPSS scores for CVEs, in batches.

EPSS (Exploit Prediction Scoring System) estimates the probability that a
CVE will be exploited in the next 30 days, as a number from 0 to 1. The
percentile says how that compares to every other CVE. The report uses EPSS
as the last tie-breaker when ranking findings (after KEV and VPR/CVSS).

The API accepts many CVEs in one request (comma-separated), so the CVEs
not already in the cache are sent in batches of up to BATCH_SIZE instead of
one request each.

The cache is keyed per CVE, as the spec asks. A CVE that EPSS has no score
for (common for very new CVEs) is cached as {"cve": ..., "missing": true}.
Otherwise every run would ask for it again.

Output per finding: engagement/output/enrichment/<plugin_id>/epss.json

CLI usage:
    python scripts/enrich_epss.py --grouped engagement/output/grouped.json --plugin-id 900104
    python scripts/enrich_epss.py --dry-run
"""

import argparse
import json
import os
import time

import cache
import group_findings
import http_client

EPSS_URL = "https://api.first.org/data/v1/epss"

# 100 matches the API's default page size, so one batch is always one page
# of results and no pagination is needed.
BATCH_SIZE = 100


def make_batches(items, size):
    """Split a list into consecutive chunks of at most `size` items."""
    if type(items) is not list:
        raise ValueError("items must be a list")
    if type(size) is not int or size < 1:
        raise ValueError("batch size must be a positive integer")
    batches = []
    current = []
    for item in items:
        current.append(item)
        if len(current) == size:
            batches.append(current)
            current = []
    if len(current) > 0:
        batches.append(current)
    return batches


def parse_epss_response(raw):
    """Turn an EPSS API response into {cve: raw data item}.

    The API sends the numbers as strings ("0.935470000"). They are converted
    to floats when the record is built (epss_record)."""
    if type(raw) is not dict or "data" not in raw or type(raw["data"]) is not list:
        raise ValueError("EPSS response has no 'data' list; has the API format changed?")
    items = {}
    for item in raw["data"]:
        if type(item) is not dict or "cve" not in item or "epss" not in item:
            raise ValueError("EPSS data item missing 'cve' or 'epss'")
        items[item["cve"]] = item
    return items


def epss_record(cve, item):
    """Build the normalized record from a cached or fetched item."""
    if item.get("missing") is True:
        return {"cve": cve, "found": False, "epss": None, "percentile": None, "date": None}
    try:
        score = float(item["epss"])
        percentile = float(item["percentile"])
    except (KeyError, ValueError):
        raise ValueError("EPSS item for " + cve + " has a missing or non-numeric score")
    if score < 0 or score > 1 or percentile < 0 or percentile > 1:
        raise ValueError("EPSS values for " + cve + " must be between 0 and 1")
    return {"cve": cve, "found": True, "epss": score, "percentile": percentile, "date": item.get("date")}


def fetch_epss_batch(cves, http_get, sleep_fn):
    """Fetch one batch live and return {cve: item} for the CVEs EPSS knows."""
    params = {"cve": ",".join(cves)}
    response = http_client.get_with_retry(EPSS_URL, params, None, http_get, sleep_fn, 4, 2.0)
    if response["status"] != 200:
        raise RuntimeError("EPSS API returned HTTP " + str(response["status"]))
    return parse_epss_response(response["body"])


def load_canned_epss(canned_dir):
    path = os.path.join(canned_dir, "epss", "batch.json")
    if not os.path.isfile(path):
        raise ValueError("canned EPSS data not found: " + path)
    with open(path, "r", encoding="utf-8") as handle:
        return parse_epss_response(json.load(handle))


def enrich_epss(cves, connection, now, http_get, sleep_fn, canned_dir):
    """Return {cve: epss_record} for every CVE in the list."""
    if type(cves) is not list:
        raise ValueError("cves must be a list")

    items = {}
    if canned_dir is not None:
        canned = load_canned_epss(canned_dir)
        for cve in cves:
            if cve in canned:
                items[cve] = canned[cve]
            else:
                items[cve] = {"cve": cve, "missing": True}
    else:
        to_fetch = []
        for cve in cves:
            cached = cache.cache_get(connection, "epss", cve, now)
            if cached is None:
                to_fetch.append(cve)
            else:
                items[cve] = cached
        for batch in make_batches(to_fetch, BATCH_SIZE):
            fetched = fetch_epss_batch(batch, http_get, sleep_fn)
            for cve in batch:
                if cve in fetched:
                    item = fetched[cve]
                else:
                    item = {"cve": cve, "missing": True}
                cache.cache_put(connection, "epss", cve, item, now)
                items[cve] = item

    records = {}
    for cve in cves:
        records[cve] = epss_record(cve, items[cve])
    return records


def main():
    parser = argparse.ArgumentParser(description="Look up EPSS scores for finding CVEs.")
    parser.add_argument("--grouped", default="engagement/output/grouped.json")
    parser.add_argument("--plugin-id", type=int, default=None, help="only this finding")
    parser.add_argument("--output-dir", default="engagement/output")
    parser.add_argument("--cache", default="cache.db")
    parser.add_argument("--dry-run", action="store_true", help="use canned data, no network")
    parser.add_argument("--canned-dir", default=os.path.join("tests", "fixtures", "api"))
    args = parser.parse_args()

    canned_dir = None
    connection = None
    if args.dry_run:
        canned_dir = args.canned_dir
    else:
        connection = cache.open_cache(args.cache)

    groups = group_findings.load_groups(args.grouped, args.plugin_id)

    # Collect the CVEs of every selected finding first, so the batching works
    # across findings: 30 findings with one CVE each is one request, not 30.
    all_cves = []
    for group in groups:
        for cve in group["cves"]:
            if cve not in all_cves:
                all_cves.append(cve)
    all_records = enrich_epss(
        all_cves, connection, time.time(), http_client.live_get, time.sleep, canned_dir
    )

    for group in groups:
        records = {}
        for cve in group["cves"]:
            records[cve] = all_records[cve]
        folder = os.path.join(args.output_dir, "enrichment", str(group["plugin_id"]))
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "epss.json"), "w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
    print("EPSS: enriched " + str(len(groups)) + " finding(s)")


if __name__ == "__main__":
    main()
