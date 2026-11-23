"""Group normalized findings into one finding per Nessus plugin.

parse_nessus.py produces one finding per (host, port, plugin). For the
board and the report we want one finding per plugin, with the list of
affected hosts and ports. Ten servers with the same weak cipher are one
problem with one fix, not ten issues.

Each group also lists `related_plugin_ids`: other plugins that report at
least one of the same CVEs. Two different plugins can detect the same CVE
(for example, two checks for the same cipher weakness). Without this link the
report would count that CVE twice and the verifier would verify it twice
without knowing.

CLI usage:
    python scripts/group_findings.py --findings engagement/output/findings.json
"""

import argparse
import ipaddress
import json
import os

# Keys every input finding must have. These are the fields this script reads
# directly. A finding missing one of them did not come from parse_nessus.py.
REQUIRED_KEYS = [
    "host_ip", "hostname", "operating_system", "port", "protocol", "service",
    "plugin_id", "plugin_name", "plugin_family", "plugin_type", "severity",
    "severity_name", "risk_factor", "cves", "cvss3_base_score", "cvss3_vector",
    "cvss_base_score", "vpr_score", "exploit_available", "synopsis",
    "description", "solution", "see_also", "plugin_output",
]


def validate_finding(finding, position):
    """Check one input finding has the shape parse_nessus.py produces."""
    if type(finding) is not dict:
        raise ValueError("finding #" + str(position) + " must be a dict")
    for key in REQUIRED_KEYS:
        if key not in finding:
            raise ValueError("finding #" + str(position) + " is missing the '" + key + "' key")
    if type(finding["plugin_id"]) is not int:
        raise ValueError("finding #" + str(position) + " has a non-integer plugin_id")
    if type(finding["severity"]) is not int:
        raise ValueError("finding #" + str(position) + " has a non-integer severity")
    if type(finding["cves"]) is not list or type(finding["see_also"]) is not list:
        raise ValueError("finding #" + str(position) + " must have 'cves' and 'see_also' as lists")


def higher_score(current, new):
    """Return the higher of two optional scores (None means "no score").

    Nessus normally gives every result of one plugin the same score. If two
    results ever disagree, we keep the higher one. Under-stating a risk in
    the report is worse than over-stating it, and the verifier rechecks the
    score against NVD anyway.
    """
    if current is None:
        return new
    if new is None:
        return current
    if new > current:
        return new
    return current


def new_group(finding):
    """Start a group from the first finding seen for a plugin."""
    return {
        "plugin_id": finding["plugin_id"],
        "plugin_name": finding["plugin_name"],
        "plugin_family": finding["plugin_family"],
        "plugin_type": finding["plugin_type"],
        "severity": finding["severity"],
        "severity_name": finding["severity_name"],
        "risk_factor": finding["risk_factor"],
        "cves": [],
        "cvss3_base_score": None,
        "cvss3_vector": finding["cvss3_vector"],
        "cvss_base_score": None,
        "vpr_score": None,
        "exploit_available": None,
        "synopsis": finding["synopsis"],
        "description": finding["description"],
        "solution": finding["solution"],
        "see_also": [],
        "affected": [],
        "host_count": 0,
        "related_plugin_ids": [],
    }


def add_to_group(group, finding):
    """Fold one finding into its plugin group."""
    # Severity: keep the highest, and keep its name and risk factor with it,
    # so the three fields always agree with each other.
    if finding["severity"] > group["severity"]:
        group["severity"] = finding["severity"]
        group["severity_name"] = finding["severity_name"]
        group["risk_factor"] = finding["risk_factor"]

    if group["cvss3_vector"] is None:
        group["cvss3_vector"] = finding["cvss3_vector"]
    group["cvss3_base_score"] = higher_score(group["cvss3_base_score"], finding["cvss3_base_score"])
    group["cvss_base_score"] = higher_score(group["cvss_base_score"], finding["cvss_base_score"])
    group["vpr_score"] = higher_score(group["vpr_score"], finding["vpr_score"])

    # If any result says a public exploit exists, the group says so.
    if finding["exploit_available"] is True:
        group["exploit_available"] = True
    elif finding["exploit_available"] is False and group["exploit_available"] is None:
        group["exploit_available"] = False

    for cve in finding["cves"]:
        if cve not in group["cves"]:
            group["cves"].append(cve)
    for url in finding["see_also"]:
        if url not in group["see_also"]:
            group["see_also"].append(url)

    # Each affected entry is one (host, port, protocol). The same host can
    # appear more than once if the issue was seen on several ports (for
    # example a weak cipher on both 443 and 3389). That is useful detail
    # for whoever applies the fix.
    group["affected"].append({
        "host_ip": finding["host_ip"],
        "hostname": finding["hostname"],
        "operating_system": finding["operating_system"],
        "port": finding["port"],
        "protocol": finding["protocol"],
        "service": finding["service"],
        "plugin_output": finding["plugin_output"],
    })


def affected_sort_key(entry):
    """Order affected entries by IP (numerically, not as text, so .9 comes
    before .10), then by port. The IP version comes first so IPv4 and IPv6
    addresses are never compared to each other directly."""
    address = ipaddress.ip_address(entry["host_ip"])
    return (address.version, int(address), entry["port"], entry["protocol"])


def group_sort_key(group):
    """Order groups by severity (highest first), then by plugin ID, so the
    output is the same on every run. The final risk ranking (KEV, VPR,
    EPSS) is done later by the report-writer, once enrichment data exists."""
    return (-group["severity"], group["plugin_id"])


def group_findings(findings):
    """Return a list of plugin groups built from a list of findings."""
    if type(findings) is not list:
        raise ValueError("findings must be a list")

    groups_by_plugin = {}
    position = 0
    for finding in findings:
        validate_finding(finding, position)
        plugin_id = finding["plugin_id"]
        if plugin_id not in groups_by_plugin:
            groups_by_plugin[plugin_id] = new_group(finding)
        add_to_group(groups_by_plugin[plugin_id], finding)
        position = position + 1

    groups = []
    for plugin_id in groups_by_plugin:
        group = groups_by_plugin[plugin_id]
        group["cves"].sort()
        group["affected"].sort(key=affected_sort_key)

        distinct_hosts = []
        for entry in group["affected"]:
            if entry["host_ip"] not in distinct_hosts:
                distinct_hosts.append(entry["host_ip"])
        group["host_count"] = len(distinct_hosts)
        groups.append(group)

    # Cross-reference: map each CVE to every plugin that reports it, then give
    # each group the other plugins that share one of its CVEs.
    plugins_by_cve = {}
    for group in groups:
        for cve in group["cves"]:
            if cve not in plugins_by_cve:
                plugins_by_cve[cve] = []
            plugins_by_cve[cve].append(group["plugin_id"])

    for group in groups:
        related = []
        for cve in group["cves"]:
            for other_plugin_id in plugins_by_cve[cve]:
                if other_plugin_id != group["plugin_id"] and other_plugin_id not in related:
                    related.append(other_plugin_id)
        related.sort()
        group["related_plugin_ids"] = related

    groups.sort(key=group_sort_key)
    return groups


def load_groups(grouped_path, plugin_id):
    """Read grouped.json and return its groups: all of them when plugin_id is
    None, or a one-item list with the matching group.

    The enrichers and triage use this. A verifier works on one finding issue
    at a time, and the issue names the plugin ID.
    """
    if type(grouped_path) is not str or not os.path.isfile(grouped_path):
        raise ValueError("grouped findings file not found: " + repr(grouped_path))
    with open(grouped_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if type(data) is not dict or "groups" not in data or type(data["groups"]) is not list:
        raise ValueError("grouped file must be the JSON object written by group_findings.py")
    if plugin_id is None:
        return data["groups"]
    if type(plugin_id) is not int:
        raise ValueError("plugin_id must be an integer or None")
    for group in data["groups"]:
        if group["plugin_id"] == plugin_id:
            return [group]
    raise ValueError("no grouped finding with plugin_id " + str(plugin_id) + " in " + grouped_path)


def main():
    parser = argparse.ArgumentParser(
        description="Group parsed Nessus findings into one finding per plugin."
    )
    parser.add_argument(
        "--findings", default="engagement/output/findings.json",
        help="findings JSON written by parse_nessus.py",
    )
    parser.add_argument("--output-dir", default="engagement/output", help="where to write JSON")
    args = parser.parse_args()

    if not os.path.isfile(args.findings):
        raise ValueError("findings file not found: " + args.findings)
    with open(args.findings, "r", encoding="utf-8") as handle:
        parsed = json.load(handle)
    if type(parsed) is not dict or "findings" not in parsed:
        raise ValueError("findings file must be the JSON object written by parse_nessus.py")

    groups = group_findings(parsed["findings"])

    # Carry the scan-level facts forward so the next step (triage, opening
    # issues) needs only this one file.
    output = {
        "source_file": parsed.get("source_file"),
        "policy_name": parsed.get("policy_name"),
        "hosts_in_scope": parsed.get("hosts_in_scope", []),
        "rejected_hosts": parsed.get("rejected_hosts", []),
        "groups": groups,
    }
    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, "grouped.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)
    print("Wrote " + str(len(groups)) + " grouped findings to " + output_path)


if __name__ == "__main__":
    main()
