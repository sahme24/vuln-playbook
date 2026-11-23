"""Check the OS vendor's own advisory data for each CVE.

Why vendor data matters ("backporting"):
    Ubuntu, Debian and Red Hat fix security bugs in place without changing
    the upstream version number. A patched Ubuntu server can still announce
    "OpenSSH_8.9p1", and a scanner that only reads that banner reports it as
    vulnerable. The vendor's tracker says which package build contains the
    fix, so the verifier can judge whether the banner is telling the truth.

Sources:
    Ubuntu   CVE tracker JSON       https://ubuntu.com/security/cves/<CVE>.json
    Red Hat  Security Data API      https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json
    MSRC     Security Update Guide  https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct

Which source is used depends on the operating system Nessus reported for the
affected host (detect_vendor). Each record says, for one CVE on one OS release:
    status = "fixed"         the vendor ships a fix (the host may or may not have it)
             "not-affected"  the vendor says this release was never vulnerable
             "affected"      vulnerable, and no fix is available (or never will be)
             "unknown"       no usable vendor data

Vendor data is optional evidence. If a vendor API is down after all retries,
the record is written with status "unknown" and the error text in
"lookup_error", so the failure is visible to the verifier and in the
output file. Triage then treats the vendor status as unknown, which can only
lead to needs-human or to a verdict based on direct evidence, never to a
false positive.

Output per finding: engagement/output/enrichment/<plugin_id>/vendor.json
    {"records": [ {cve, vendor, release, package, status, ...}, ... ]}

CLI usage:
    python scripts/enrich_vendor.py --grouped engagement/output/grouped.json --plugin-id 900101
    python scripts/enrich_vendor.py --dry-run
"""

import argparse
import json
import os
import re
import time

import cache
import group_findings
import http_client

UBUNTU_URL = "https://ubuntu.com/security/cves/"
REDHAT_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/"
REDHAT_PAGE = "https://access.redhat.com/security/cve/"
MSRC_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct"
MSRC_PAGE = "https://msrc.microsoft.com/update-guide/vulnerability/"

# Ubuntu version number -> release codename used in the tracker data.
UBUNTU_RELEASES = {
    "16.04": "xenial",
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
}

# A CVE often affects many packages (CVE-2023-48795 lists openssh, dropbear,
# libssh, putty, ...), so we have to know which package the plugin is
# about. Each entry maps a word in the plugin name to the package name each
# vendor uses. Checked in order, first match wins: "log4j" comes before any
# broader word so that "Apache Log4j" maps to log4j, not to Apache httpd.
PACKAGE_HINTS = [
    {"keyword": "log4j", "ubuntu": "apache-log4j2", "redhat": "log4j"},
    {"keyword": "openssh", "ubuntu": "openssh", "redhat": "openssh"},
    {"keyword": "openssl", "ubuntu": "openssl", "redhat": "openssl"},
    {"keyword": "apache http server", "ubuntu": "apache2", "redhat": "httpd"},
    {"keyword": "apache httpd", "ubuntu": "apache2", "redhat": "httpd"},
    {"keyword": "nginx", "ubuntu": "nginx", "redhat": "nginx"},
    {"keyword": "samba", "ubuntu": "samba", "redhat": "samba"},
    {"keyword": "sudo", "ubuntu": "sudo", "redhat": "sudo"},
]

UBUNTU_STATUS_MAP = {
    "released": "fixed",
    "not-affected": "not-affected",
    "DNE": "not-affected",          # "does not exist": package not in this release
    "needed": "affected",
    "deferred": "affected",
    "pending": "affected",          # a fix is being prepared but is not out yet
    "ignored": "affected",          # will not be fixed in this release
    "needs-triage": "unknown",
}

REDHAT_STATE_MAP = {
    "Not affected": "not-affected",
    "Affected": "affected",
    "Fix deferred": "affected",
    "Will not fix": "affected",
    "Out of support scope": "affected",
    "Under investigation": "unknown",
}

CACHE_SOURCES = {"ubuntu": "vendor_ubuntu", "redhat": "vendor_redhat", "msrc": "vendor_msrc"}

UBUNTU_PATTERN = re.compile(r"Ubuntu (\d{2}\.\d{2})")
REDHAT_PATTERN = re.compile(r"Red Hat Enterprise Linux (?:Server |Workstation )?(\d+)")
WINDOWS_SERVER_PATTERN = re.compile(r"Windows Server (\d{4})( R2)?")
WINDOWS_CLIENT_PATTERN = re.compile(r"Windows (10|11)\b")


def detect_vendor(operating_system):
    """Map a Nessus OS string to the vendor source and release to look up.

    Returns {"vendor": "ubuntu"|"redhat"|"msrc", "release": ...}, or
    {"vendor": None, "release": None} when no supported vendor applies.
    Ubuntu releases outside UBUNTU_RELEASES give vendor "ubuntu" with release
    None, so the record can say exactly why there is no data.
    """
    if operating_system is None:
        return {"vendor": None, "release": None}
    if type(operating_system) is not str:
        raise ValueError("operating_system must be a string or None")

    match = UBUNTU_PATTERN.search(operating_system)
    if match is not None:
        version = match.group(1)
        if version in UBUNTU_RELEASES:
            return {"vendor": "ubuntu", "release": UBUNTU_RELEASES[version]}
        return {"vendor": "ubuntu", "release": None}

    match = REDHAT_PATTERN.search(operating_system)
    if match is not None:
        return {"vendor": "redhat", "release": "Red Hat Enterprise Linux " + match.group(1)}

    match = WINDOWS_SERVER_PATTERN.search(operating_system)
    if match is not None:
        release = "Windows Server " + match.group(1)
        if match.group(2) is not None:
            release = release + " R2"
        return {"vendor": "msrc", "release": release}

    match = WINDOWS_CLIENT_PATTERN.search(operating_system)
    if match is not None:
        return {"vendor": "msrc", "release": "Windows " + match.group(1)}

    return {"vendor": None, "release": None}


def package_hint(plugin_name, vendor):
    """Return the vendor's package name for the software a plugin checks, or
    None when the plugin name matches no hint (MSRC does not use packages)."""
    if type(plugin_name) is not str:
        raise ValueError("plugin_name must be a string")
    if vendor == "msrc":
        return None
    lowered = plugin_name.lower()
    for hint in PACKAGE_HINTS:
        if hint["keyword"] in lowered:
            return hint[vendor]
    return None


def new_record(cve, vendor, release, package, url):
    return {
        "cve": cve,
        "vendor": vendor,
        "release": release,
        "package": package,
        "status": "unknown",
        "fixed_version": None,
        "details": None,
        "url": url,
        "lookup_error": None,
    }


def parse_ubuntu(cve, raw, release, package):
    """Ubuntu status of one package in one release. raw is None for a 404."""
    record = new_record(cve, "ubuntu", release, package, UBUNTU_URL + cve)
    if raw is None:
        record["details"] = "Ubuntu does not track this CVE"
        return record
    if release is None:
        record["details"] = "Ubuntu release is not in the release table"
        return record
    if package is None:
        record["details"] = "plugin could not be mapped to an Ubuntu package"
        return record
    if type(raw) is not dict or type(raw.get("packages")) is not list:
        raise ValueError("Ubuntu response for " + cve + " has no 'packages' list")

    for entry in raw["packages"]:
        if entry.get("name") != package:
            continue
        for status in entry.get("statuses", []):
            if status.get("release_codename") != release:
                continue
            ubuntu_status = status.get("status")
            if ubuntu_status in UBUNTU_STATUS_MAP:
                record["status"] = UBUNTU_STATUS_MAP[ubuntu_status]
            record["details"] = "Ubuntu status: " + str(ubuntu_status)
            if ubuntu_status == "released":
                record["fixed_version"] = status.get("description")
            return record
        record["details"] = "package " + package + " has no entry for release " + release
        return record

    record["details"] = "package " + package + " is not listed for this CVE"
    return record


def parse_redhat(cve, raw, release, package):
    """Red Hat status for one RHEL major release. raw is None for a 404.

    A released fix (affected_release) is checked first. Otherwise the
    package_state rows for that product give the state. Without a package
    hint, all rows for the product must agree, or the answer is "unknown".
    """
    record = new_record(cve, "redhat", release, package, REDHAT_PAGE + cve)
    if raw is None:
        record["details"] = "Red Hat has no record of this CVE"
        return record
    if type(raw) is not dict:
        raise ValueError("Red Hat response for " + cve + " is not a JSON object")

    for fix in raw.get("affected_release", []):
        if fix.get("product_name") != release:
            continue
        if package is not None and package not in str(fix.get("package")):
            continue
        record["status"] = "fixed"
        record["fixed_version"] = fix.get("advisory")
        record["details"] = "fixed by " + str(fix.get("advisory")) + " in " + str(fix.get("package"))
        return record

    states = []
    for row in raw.get("package_state", []):
        if row.get("product_name") != release:
            continue
        if package is not None and package not in str(row.get("package_name")):
            continue
        fix_state = row.get("fix_state")
        if fix_state in REDHAT_STATE_MAP:
            mapped = REDHAT_STATE_MAP[fix_state]
        else:
            mapped = "unknown"
        if mapped not in states:
            states.append(mapped)

    if len(states) == 0:
        record["details"] = "no entry for " + str(release)
    elif len(states) == 1:
        record["status"] = states[0]
        record["details"] = "Red Hat package state for " + str(release) + ": " + states[0]
    else:
        record["details"] = "Red Hat rows for " + str(release) + " disagree: " + ", ".join(states)
    return record


def parse_msrc(cve, raw, release):
    """MSRC status for one Windows product. MSRC lists only affected products
    (each with its KB updates), so it can say "fixed" but never "not-affected"."""
    record = new_record(cve, "msrc", release, None, MSRC_PAGE + cve)
    if type(raw) is not dict or type(raw.get("value")) is not list:
        raise ValueError("MSRC response for " + cve + " has no 'value' list")
    articles = []
    for entry in raw["value"]:
        product = str(entry.get("product"))
        if not product.startswith(str(release)):
            continue
        for article in entry.get("kbArticles", []):
            name = "KB" + str(article.get("articleName"))
            if name not in articles:
                articles.append(name)
    if len(articles) == 0:
        record["details"] = "MSRC lists no update for " + str(release)
        return record
    record["status"] = "fixed"
    record["fixed_version"] = ", ".join(articles)
    record["details"] = "MSRC lists security updates for " + str(release)
    return record


def fetch_vendor_raw(vendor, cve, http_get, sleep_fn):
    """Fetch one vendor response live. Returns the JSON body, or None for 404."""
    if vendor == "ubuntu":
        response = http_client.get_with_retry(
            UBUNTU_URL + cve + ".json", None, None, http_get, sleep_fn, 4, 3.0
        )
    elif vendor == "redhat":
        response = http_client.get_with_retry(
            REDHAT_URL + cve + ".json", None, None, http_get, sleep_fn, 4, 3.0
        )
    elif vendor == "msrc":
        params = {"$filter": "cveNumber eq '" + cve + "'"}
        response = http_client.get_with_retry(MSRC_URL, params, None, http_get, sleep_fn, 4, 3.0)
    else:
        raise ValueError("unknown vendor " + repr(vendor))
    if response["status"] == 404:
        return None
    return response["body"]


def load_canned_vendor(vendor, cve, canned_dir):
    """Read a canned vendor response.

    A canned file holding {"not_found": true} stands for a real 404 (the
    vendor has no record). A MISSING file means no response was captured when
    the canned set was made (for example, the vendor API timed out). That is
    raised as RuntimeError, the same way a live lookup failure is, so it shows
    up as a lookup_error and is not mistaken for "the vendor has no record".
    """
    path = os.path.join(canned_dir, CACHE_SOURCES[vendor], cve + ".json")
    if not os.path.isfile(path):
        raise RuntimeError("no canned " + vendor + " response for " + cve)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if type(data) is dict and data.get("not_found") is True:
        return None
    return data


def get_vendor_raw(vendor, cve, connection, now, http_get, sleep_fn, canned_dir):
    """Raw vendor response from canned data, the cache, or the network.
    A 404 is cached as {"not_found": true}, so it is not asked again until the
    entry expires."""
    if canned_dir is not None:
        return load_canned_vendor(vendor, cve, canned_dir)
    source = CACHE_SOURCES[vendor]
    cached = cache.cache_get(connection, source, cve, now)
    if cached is not None:
        if type(cached) is dict and cached.get("not_found") is True:
            return None
        return cached
    raw = fetch_vendor_raw(vendor, cve, http_get, sleep_fn)
    if raw is None:
        cache.cache_put(connection, source, cve, {"not_found": True}, now)
    else:
        cache.cache_put(connection, source, cve, raw, now)
    return raw


def enrich_vendor(group, connection, now, http_get, sleep_fn, canned_dir):
    """Return the list of vendor records for one grouped finding: one per
    (vendor release seen on an affected host, CVE)."""
    if type(group) is not dict or "cves" not in group or "affected" not in group:
        raise ValueError("group must be a grouped finding from group_findings.py")

    targets = []
    for entry in group["affected"]:
        detected = detect_vendor(entry["operating_system"])
        if detected["vendor"] is not None and detected not in targets:
            targets.append(detected)

    records = []
    for target in targets:
        vendor = target["vendor"]
        release = target["release"]
        package = package_hint(group["plugin_name"], vendor)
        for cve in group["cves"]:
            try:
                raw = get_vendor_raw(vendor, cve, connection, now, http_get, sleep_fn, canned_dir)
            except RuntimeError as error:
                # Vendor API down after every retry: record it, do not hide it.
                record = new_record(cve, vendor, release, package, None)
                record["lookup_error"] = str(error)
                record["details"] = "vendor lookup failed"
                records.append(record)
                continue
            if vendor == "ubuntu":
                records.append(parse_ubuntu(cve, raw, release, package))
            elif vendor == "redhat":
                records.append(parse_redhat(cve, raw, release, package))
            else:
                if raw is None:
                    record = new_record(cve, "msrc", release, None, MSRC_PAGE + cve)
                    record["details"] = "MSRC has no record of this CVE"
                    records.append(record)
                else:
                    records.append(parse_msrc(cve, raw, release))
    return records


def main():
    parser = argparse.ArgumentParser(description="Check vendor advisories for finding CVEs.")
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
    for group in groups:
        records = enrich_vendor(group, connection, time.time(), http_client.live_get, time.sleep, canned_dir)
        folder = os.path.join(args.output_dir, "enrichment", str(group["plugin_id"]))
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "vendor.json"), "w", encoding="utf-8") as handle:
            json.dump({"records": records}, handle, indent=2)
    print("Vendor: enriched " + str(len(groups)) + " finding(s)")


if __name__ == "__main__":
    main()
