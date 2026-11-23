"""Check CVEs against the CISA Known Exploited Vulnerabilities (KEV) catalog.

KEV lists CVEs that are confirmed to be exploited in real attacks. A
finding with a KEV CVE goes to the top of the report and can never be marked
a false positive without a human.

The whole catalog is one JSON file (~2 MB, ~1,800 entries). It is downloaded
once per run (cached for a day) and every CVE is matched locally, instead of
making one request per CVE.

Output per finding: engagement/output/enrichment/<plugin_id>/kev.json
    {"CVE-2021-44228": {"cve": ..., "in_kev": true, "date_added": ..., ...}, ...}

CLI usage:
    python scripts/enrich_kev.py --grouped engagement/output/grouped.json --plugin-id 900104
    python scripts/enrich_kev.py --dry-run          # canned catalog, no network
"""

import argparse
import json
import os
import time

import cache
import group_findings
import http_client

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CATALOG_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
CACHE_KEY = "catalog"


def validate_catalog(catalog):
    """The parts of the feed we rely on must exist. A changed feed format has
    to stop the run, or every CVE would wrongly come back as 'not in KEV'."""
    if type(catalog) is not dict:
        raise ValueError("KEV catalog must be a JSON object")
    if "vulnerabilities" not in catalog or type(catalog["vulnerabilities"]) is not list:
        raise ValueError("KEV catalog has no 'vulnerabilities' list; has the feed format changed?")
    for entry in catalog["vulnerabilities"]:
        if type(entry) is not dict or "cveID" not in entry:
            raise ValueError("KEV catalog entry without a cveID; has the feed format changed?")
    return True


def fetch_kev_catalog(http_get, sleep_fn):
    """Download the catalog (live). Raises RuntimeError if it cannot be fetched."""
    response = http_client.get_with_retry(KEV_URL, None, None, http_get, sleep_fn, 4, 5.0)
    if response["status"] != 200:
        raise RuntimeError("KEV catalog download returned HTTP " + str(response["status"]))
    validate_catalog(response["body"])
    return response["body"]


def load_canned_kev(canned_dir):
    """Read the catalog from the canned dry-run data."""
    path = os.path.join(canned_dir, "kev", "catalog.json")
    if not os.path.isfile(path):
        raise ValueError("canned KEV catalog not found: " + path)
    with open(path, "r", encoding="utf-8") as handle:
        catalog = json.load(handle)
    validate_catalog(catalog)
    return catalog


def get_kev_catalog(connection, now, http_get, sleep_fn, canned_dir):
    """Return the catalog: from canned data in dry-run, else from the cache,
    else downloaded (and then cached)."""
    if canned_dir is not None:
        return load_canned_kev(canned_dir)
    catalog = cache.cache_get(connection, "kev", CACHE_KEY, now)
    if catalog is None:
        catalog = fetch_kev_catalog(http_get, sleep_fn)
        cache.cache_put(connection, "kev", CACHE_KEY, catalog, now)
    return catalog


def index_catalog(catalog):
    """Build {cveID: entry} so each lookup is a dictionary access, not a scan
    of the whole list."""
    validate_catalog(catalog)
    index = {}
    for entry in catalog["vulnerabilities"]:
        index[entry["cveID"]] = entry
    return index


def kev_record(cve, index, catalog_version):
    """The normalized KEV result for one CVE."""
    if cve not in index:
        return {"cve": cve, "in_kev": False, "catalog_version": catalog_version}
    entry = index[cve]
    return {
        "cve": cve,
        "in_kev": True,
        "catalog_version": catalog_version,
        "date_added": entry.get("dateAdded"),
        "due_date": entry.get("dueDate"),
        "vulnerability_name": entry.get("vulnerabilityName"),
        "required_action": entry.get("requiredAction"),
        "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
        "catalog_url": KEV_CATALOG_PAGE,
    }


def enrich_kev(cves, catalog):
    """Return {cve: kev_record} for every CVE in the list."""
    if type(cves) is not list:
        raise ValueError("cves must be a list")
    index = index_catalog(catalog)
    version = catalog.get("catalogVersion")
    records = {}
    for cve in cves:
        records[cve] = kev_record(cve, index, version)
    return records


def main():
    parser = argparse.ArgumentParser(description="Match finding CVEs against the CISA KEV catalog.")
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

    catalog = get_kev_catalog(connection, time.time(), http_client.live_get, time.sleep, canned_dir)
    groups = group_findings.load_groups(args.grouped, args.plugin_id)
    for group in groups:
        records = enrich_kev(group["cves"], catalog)
        folder = os.path.join(args.output_dir, "enrichment", str(group["plugin_id"]))
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "kev.json"), "w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
    print("KEV: enriched " + str(len(groups)) + " finding(s)")


if __name__ == "__main__":
    main()
