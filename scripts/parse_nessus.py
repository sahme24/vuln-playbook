"""Convert a Nessus export (.nessus, format v2 XML) into normalized findings JSON.

A .nessus file is structured as:

    NessusClientData_v2
      Policy / policyName
      Report
        ReportHost name="..."         one per scanned host
          HostProperties / tag ...    host facts (IP, hostname, OS)
          ReportItem ...              one per (plugin, port) result on that host

This script turns every ReportItem into one flat "finding" dict that holds the
host facts too, so later scripts never have to walk the XML again.

Scope is enforced here as well, not only before scanning. A Nessus policy
can be edited by hand, so the export may contain hosts that were never
authorized. Each host is checked with scope.check_in_scope(). Hosts that fail
are left out of the findings entirely and listed in `rejected_hosts` with the
reason. They are recorded, not silently dropped, but none of their data
moves further down the pipeline.

Malformed data inside an in-scope host (a missing pluginID, a severity
outside 0-4, ...) raises ValueError for the whole file. A half-parsed scan
would produce a report with findings silently missing.

CLI usage:
    python scripts/parse_nessus.py --nessus engagement/inbox/scan.nessus \
        --engagement engagement.yaml
"""

import argparse
import json
import os
import re
import xml.etree.ElementTree as ET

import scope

# Nessus severity numbers and the names used everywhere else in the playbook
# (labels, triage rules, the report).
SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# A CVE ID is "CVE-", a 4-digit year, "-", then 4 or more digits. CVE IDs end
# up in URLs (NVD links) and API queries, so a malformed one is rejected here
# instead of producing a broken lookup later.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def get_child_text(element, tag):
    """Return the stripped text of the first child with this tag, or None if
    the child is absent or empty.

    None is a real answer here, not an error: most ReportItem fields are
    optional (an informational plugin has no CVSS score, for example).
    """
    child = element.find(tag)
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    if text == "":
        return None
    return text


def get_all_child_texts(element, tag):
    """Return the stripped text of every child with this tag, in file order.
    Used for fields that repeat, like <cve>."""
    texts = []
    for child in element.findall(tag):
        if child.text is not None and child.text.strip() != "":
            texts.append(child.text.strip())
    return texts


def parse_optional_score(text, field_name, context):
    """Turn a score field (CVSS, VPR) into a float, or None if absent."""
    if text is None:
        return None
    try:
        return float(text)
    except ValueError:
        raise ValueError(field_name + " is not a number (" + repr(text) + ") in " + context)


def parse_optional_bool(text, field_name, context):
    """Nessus writes booleans as the strings "true" / "false"."""
    if text is None:
        return None
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    raise ValueError(field_name + " must be 'true' or 'false', got " + repr(text) + " in " + context)


def parse_required_int(element, attribute, context, minimum, maximum):
    """Read an integer XML attribute that every ReportItem must have and
    check that it is inside [minimum, maximum]."""
    raw = element.get(attribute)
    if raw is None:
        raise ValueError("ReportItem is missing the '" + attribute + "' attribute in " + context)
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(attribute + " is not an integer (" + repr(raw) + ") in " + context)
    if value < minimum or value > maximum:
        raise ValueError(
            attribute + " must be between " + str(minimum) + " and " + str(maximum)
            + ", got " + str(value) + " in " + context
        )
    return value


def read_host_properties(report_host):
    """Return the HostProperties tags as a dict: {"host-ip": "...", ...}."""
    properties = {}
    host_properties = report_host.find("HostProperties")
    if host_properties is None:
        return properties
    for tag in host_properties.findall("tag"):
        name = tag.get("name")
        if name is not None and tag.text is not None:
            properties[name] = tag.text.strip()
    return properties


def find_host_ip(report_host, properties):
    """Work out the IP address of a ReportHost.

    The host-ip tag is preferred. The ReportHost `name` attribute is whatever
    the scan target was typed as, which may be a hostname. If there is no
    host-ip tag, `name` is used, but only if it is itself an IP address.
    Raises ValueError when no IP can be found, because scope can only be
    checked against an IP.
    """
    if "host-ip" in properties:
        candidate = properties["host-ip"]
    else:
        candidate = report_host.get("name")
    if candidate is None:
        raise ValueError("host has neither a host-ip tag nor a name attribute")
    address = scope.parse_ip(candidate)
    return str(address)


def parse_report_item(item, host):
    """Turn one ReportItem into a finding dict. `host` holds the facts shared
    by every item on that host (ip, hostname, operating_system)."""
    plugin_id_text = item.get("pluginID")
    context = "host " + host["ip"] + ", pluginID " + str(plugin_id_text)

    # Plugin ID 0 is valid: some Nessus versions use it for plain
    # "open port" entries.
    plugin_id = parse_required_int(item, "pluginID", context, 0, 999999999)
    severity = parse_required_int(item, "severity", context, 0, 4)
    port = parse_required_int(item, "port", context, 0, 65535)

    protocol = item.get("protocol")
    if protocol is None or protocol.strip() == "":
        raise ValueError("ReportItem is missing the 'protocol' attribute in " + context)
    plugin_name = item.get("pluginName")
    if plugin_name is None or plugin_name.strip() == "":
        raise ValueError("ReportItem is missing the 'pluginName' attribute in " + context)

    cves = []
    for cve in get_all_child_texts(item, "cve"):
        if CVE_PATTERN.fullmatch(cve) is None:
            raise ValueError("malformed CVE ID " + repr(cve) + " in " + context)
        # The same CVE can be listed twice in one item. Keep one copy.
        if cve not in cves:
            cves.append(cve)

    # see_also holds one URL per line.
    see_also = []
    see_also_text = get_child_text(item, "see_also")
    if see_also_text is not None:
        for line in see_also_text.splitlines():
            if line.strip() != "":
                see_also.append(line.strip())

    finding = {
        "host_ip": host["ip"],
        "hostname": host["hostname"],
        "operating_system": host["operating_system"],
        "port": port,
        "protocol": protocol.strip().lower(),
        "service": item.get("svc_name"),
        "plugin_id": plugin_id,
        "plugin_name": plugin_name.strip(),
        "plugin_family": item.get("pluginFamily"),
        # plugin_type says HOW Nessus detected the issue: "remote" (network
        # probe or banner), "local" (credentialed check on the host),
        # "combined", or "summary". The verifier uses this to judge how much
        # to trust a detection.
        "plugin_type": get_child_text(item, "plugin_type"),
        "severity": severity,
        "severity_name": SEVERITY_NAMES[severity],
        "risk_factor": get_child_text(item, "risk_factor"),
        "cves": cves,
        "cvss3_base_score": parse_optional_score(
            get_child_text(item, "cvss3_base_score"), "cvss3_base_score", context
        ),
        "cvss3_vector": get_child_text(item, "cvss3_vector"),
        "cvss_base_score": parse_optional_score(
            get_child_text(item, "cvss_base_score"), "cvss_base_score", context
        ),
        "vpr_score": parse_optional_score(get_child_text(item, "vpr_score"), "vpr_score", context),
        "exploit_available": parse_optional_bool(
            get_child_text(item, "exploit_available"), "exploit_available", context
        ),
        "synopsis": get_child_text(item, "synopsis"),
        "description": get_child_text(item, "description"),
        "solution": get_child_text(item, "solution"),
        "see_also": see_also,
        "plugin_output": get_child_text(item, "plugin_output"),
    }
    return finding


def parse_nessus_file(path, engagement_scope):
    """Parse a .nessus file and return:

        {
          "source_file":   path,
          "policy_name":   "..." or None,
          "hosts_in_scope": ["192.0.2.10", ...],
          "rejected_hosts": [{"host": ..., "ip": ..., "reason": ..., "item_count": n}],
          "findings":      [finding, ...]      # in-scope hosts only
        }
    """
    if type(path) is not str or path == "":
        raise ValueError("nessus path must be a non-empty string")
    if not os.path.isfile(path):
        raise ValueError(".nessus file not found: " + path)
    scope.validate_scope(engagement_scope)

    try:
        # ElementTree does not fetch external entities, so a hostile file
        # cannot make the parser read local files or reach the network.
        tree = ET.parse(path)
    except ET.ParseError as error:
        raise ValueError("not well-formed XML: " + path + " (" + str(error) + ")")

    root = tree.getroot()
    if root.tag != "NessusClientData_v2":
        raise ValueError(
            "not a Nessus v2 export (root element is <" + root.tag
            + ">, expected <NessusClientData_v2>): " + path
        )
    report = root.find("Report")
    if report is None:
        raise ValueError("Nessus export has no <Report> element: " + path)

    policy_name = None
    policy = root.find("Policy")
    if policy is not None:
        policy_name = get_child_text(policy, "policyName")

    hosts_in_scope = []
    rejected_hosts = []
    findings = []

    for report_host in report.findall("ReportHost"):
        host_name = report_host.get("name")
        properties = read_host_properties(report_host)
        items = report_host.findall("ReportItem")

        # The scope gate. Only the scope / IP lookup is wrapped in try,
        # so a ValueError here means "this host is not allowed", never "the
        # data is broken". Broken data further down still stops the whole run.
        ip_text = None
        try:
            ip_text = find_host_ip(report_host, properties)
            scope.check_in_scope(ip_text, engagement_scope)
        except ValueError as error:
            rejected_hosts.append({
                "host": host_name,
                "ip": ip_text,
                "reason": str(error),
                "item_count": len(items),
            })
            continue

        # Prefer the fully qualified name, then the short hostname.
        hostname = None
        if "host-fqdn" in properties:
            hostname = properties["host-fqdn"]
        elif "hostname" in properties:
            hostname = properties["hostname"]

        operating_system = None
        if "operating-system" in properties:
            operating_system = properties["operating-system"]

        host = {"ip": ip_text, "hostname": hostname, "operating_system": operating_system}
        if ip_text not in hosts_in_scope:
            hosts_in_scope.append(ip_text)

        for item in items:
            findings.append(parse_report_item(item, host))

    return {
        "source_file": path,
        "policy_name": policy_name,
        "hosts_in_scope": hosts_in_scope,
        "rejected_hosts": rejected_hosts,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Parse a .nessus export into normalized findings JSON (in-scope hosts only)."
    )
    parser.add_argument("--nessus", required=True, help="path to the .nessus file")
    parser.add_argument("--engagement", default="engagement.yaml", help="path to engagement.yaml")
    parser.add_argument("--output-dir", default="engagement/output", help="where to write JSON")
    args = parser.parse_args()

    engagement = scope.load_engagement(args.engagement)
    engagement_scope = scope.build_scope(engagement)
    result = parse_nessus_file(args.nessus, engagement_scope)

    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, "findings.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)

    print(
        "Parsed " + str(len(result["findings"])) + " findings from "
        + str(len(result["hosts_in_scope"])) + " in-scope hosts; rejected "
        + str(len(result["rejected_hosts"])) + " hosts. Wrote " + output_path
    )


if __name__ == "__main__":
    main()
