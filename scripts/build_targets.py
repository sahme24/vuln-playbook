"""Merge the two discovery passes into targets.txt and a host summary.

    live          = pass 1 "up"  +  pass 2 "live"    -> targets.txt (for Nessus)
    filtered      = pass 2 "filtered"                -> summary only
    unresponsive  = pass 2 "unresponsive"            -> summary only

Only live hosts become Nessus targets. Filtered and unresponsive hosts are
listed in the summary posted to the board, so the human can add them by hand
if they want them scanned anyway.

Every host pass 1 marked "down" must appear in the pass 2 results. If one is
missing, pass 2 did not finish (or was run with a different pass 1), and
building a target list from it would silently drop hosts, so it raises
ValueError instead.

CLI usage:
    python scripts/build_targets.py --engagement engagement.yaml
"""

import argparse
import ipaddress
import json
import os
from datetime import datetime, timezone

import scope


def ip_sort_key(ip_text):
    """Numeric IP order (so .9 comes before .10), IPv4 before IPv6."""
    address = ipaddress.ip_address(ip_text)
    return (address.version, int(address))


def build_targets(pass1_hosts, pass2_hosts, engagement_scope):
    """Return {"live": [...], "filtered": [...], "unresponsive": [...]}, each
    sorted numerically. Every live host is re-checked against scope."""
    if type(pass1_hosts) is not list or type(pass2_hosts) is not list:
        raise ValueError("pass1_hosts and pass2_hosts must be lists")
    scope.validate_scope(engagement_scope)

    live = []
    down_in_pass1 = []
    for host in pass1_hosts:
        if host["state"] == "up":
            live.append(host["ip"])
        elif host["state"] == "down":
            down_in_pass1.append(host["ip"])
        else:
            raise ValueError("pass 1 host " + str(host["ip"]) + " has unknown state " + repr(host["state"]))

    filtered = []
    unresponsive = []
    seen_in_pass2 = []
    for host in pass2_hosts:
        ip = host["ip"]
        if ip not in down_in_pass1:
            raise ValueError(
                "pass 2 reports " + ip + ", which pass 1 did not mark as down; "
                "the two result files do not belong together"
            )
        seen_in_pass2.append(ip)
        if host["status"] == "live":
            live.append(ip)
        elif host["status"] == "filtered":
            filtered.append(ip)
        elif host["status"] == "unresponsive":
            unresponsive.append(ip)
        else:
            raise ValueError("pass 2 host " + ip + " has unknown status " + repr(host["status"]))

    for ip in down_in_pass1:
        if ip not in seen_in_pass2:
            raise ValueError(
                ip + " was down in pass 1 but is missing from pass 2; re-run pass 2 before building targets"
            )

    for ip in live:
        scope.check_in_scope(ip, engagement_scope)

    live.sort(key=ip_sort_key)
    filtered.sort(key=ip_sort_key)
    unresponsive.sort(key=ip_sort_key)
    return {"live": live, "filtered": filtered, "unresponsive": unresponsive}


def read_json(path):
    if not os.path.isfile(path):
        raise ValueError("file not found: " + path + " (run nmap_discovery.py first)")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser(description="Build targets.txt from the two discovery passes.")
    parser.add_argument("--engagement", default="engagement.yaml", help="path to engagement.yaml")
    parser.add_argument("--output-dir", default="engagement/output", help="where pass results live")
    args = parser.parse_args()

    engagement = scope.load_engagement(args.engagement)
    engagement_scope = scope.build_scope(engagement)
    pass1 = read_json(os.path.join(args.output_dir, "discovery_pass1.json"))
    pass2 = read_json(os.path.join(args.output_dir, "discovery_pass2.json"))

    hosts = build_targets(pass1["hosts"], pass2["hosts"], engagement_scope)

    targets_path = os.path.join(args.output_dir, "targets.txt")
    with open(targets_path, "w", encoding="utf-8") as handle:
        for ip in hosts["live"]:
            handle.write(ip + "\n")

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": pass1.get("dry_run"),
        "live": hosts["live"],
        "filtered": hosts["filtered"],
        "unresponsive": hosts["unresponsive"],
        "counts": {
            "live": len(hosts["live"]),
            "filtered": len(hosts["filtered"]),
            "unresponsive": len(hosts["unresponsive"]),
        },
    }
    summary_path = os.path.join(args.output_dir, "host_summary.json")
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    print("Wrote " + str(len(hosts["live"])) + " live targets to " + targets_path + " and " + summary_path)


if __name__ == "__main__":
    main()
