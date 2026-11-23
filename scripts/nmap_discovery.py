"""Two-pass Nmap host discovery.

Pass 1: host discovery only (-sn) against every include range, sending a
        mix of probes so that hosts which block one kind of probe can still
        answer another:
          -PE  ICMP echo request          -PP  ICMP timestamp request
          -PS  TCP SYN to common ports    -PA  TCP ACK to web ports
          -PU  UDP to DNS and SNMP
        On a directly attached Ethernet segment, Nmap (run with root or
        administrator rights) uses ARP requests instead of the probes above,
        because ARP is faster and cannot be blocked by a host firewall. That
        covers the "ARP on local subnets" part of discovery without a
        separate command. Verbose mode (-v) makes Nmap list the hosts that did
        NOT answer as well, which is what pass 2 needs.

Pass 2: every host pass 1 reported as down is scanned again with -Pn
        ("treat the host as up and probe its ports anyway") on a short list
        of common TCP ports. A host that drops every discovery probe can
        still have an open service. The port answers sort each host into:
          live          an open or closed port replied (a closed port sends
                        a TCP reset, which proves something is there)
          filtered      no port replied, but a firewall sent ICMP errors
                        such as "admin-prohibited" for this address
          unresponsive  nothing replied at all

Safety, enforced in code:
  - approval.scope_approved must be true (scope.check_approved), even in
    --dry-run, so the demo follows the same gate as a real run.
  - outside --dry-run the engagement window must be open (scope.check_in_window).
  - every range and host goes through scope.py before it is put on a
    command line, and exclude entries are passed to nmap with --exclude.
  - nmap is run as an argument list, never through a shell, so no value
    from a file can be interpreted as a shell command.

In --dry-run mode no packets are sent. The command that WOULD run is still
built and recorded, and the result is read from a fixture XML file instead.

CLI usage:
    python scripts/nmap_discovery.py --pass 1 --engagement engagement.yaml
    python scripts/nmap_discovery.py --pass 2 --engagement engagement.yaml
    python scripts/nmap_discovery.py --pass 1 --dry-run \
        --engagement tests/fixtures/engagement_test.yaml
"""

import argparse
import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import scope

# Probes for pass 1 (see the module docstring for what each one does).
PASS1_PROBES = ["-PE", "-PP", "-PS21,22,23,25,80,443,3389", "-PA80,443", "-PU53,161"]

# Ports for the pass 2 sweep: the services most often left reachable even on
# hosts that ignore ping (file sharing, remote desktop, web, databases).
COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443,
]

# Scan intensity per profile. "quiet" is slower and capped in packets per
# second, for networks with fragile devices or sensitive monitoring. Agents
# may never go above the profile written in engagement.yaml.
PROFILES = {
    "standard": {"timing": "-T3", "max_rate": None},
    "quiet": {"timing": "-T2", "max_rate": 20},
}

DEFAULT_FIXTURES = {
    1: os.path.join("tests", "fixtures", "nmap_sample.xml"),
    2: os.path.join("tests", "fixtures", "nmap_pass2_sample.xml"),
}


def get_profile(name):
    if type(name) is not str or name not in PROFILES:
        raise ValueError(
            "unknown nmap profile " + repr(name) + "; expected one of: " + ", ".join(PROFILES)
        )
    return PROFILES[name]


def profile_options(profile_name):
    """Return the timing options for a profile as a list of arguments."""
    profile = get_profile(profile_name)
    options = [profile["timing"]]
    if profile["max_rate"] is not None:
        options.append("--max-rate")
        options.append(str(profile["max_rate"]))
    return options


def plan_pass1(engagement_scope):
    """Work out the pass 1 targets and exclusions from the scope.

    Returns (targets, excludes): the include ranges as strings, and every
    exclude entry that overlaps one of them. Each range is checked with
    scope.check_network_in_scope(), so an unscannable range raises
    ValueError before any command is built.
    """
    scope.validate_scope(engagement_scope)
    targets = []
    excludes = []
    for network in engagement_scope["include"]:
        text = str(network)
        overlapping = scope.check_network_in_scope(text, engagement_scope)
        targets.append(text)
        for entry in overlapping:
            if entry not in excludes:
                excludes.append(entry)
    return targets, excludes


def build_pass1_command(targets, excludes, profile_name, output_path):
    """Build the pass 1 nmap command as an argument list."""
    if type(targets) is not list or len(targets) == 0:
        raise ValueError("pass 1 needs at least one target range")
    if type(excludes) is not list:
        raise ValueError("excludes must be a list (use [] for none)")
    command = ["nmap", "-sn", "-v"]
    for probe in PASS1_PROBES:
        command.append(probe)
    for option in profile_options(profile_name):
        command.append(option)
    if len(excludes) > 0:
        command.append("--exclude")
        command.append(",".join(excludes))
    command.append("-oX")
    command.append(output_path)
    for target in targets:
        command.append(target)
    return command


def plan_pass2(pass1_hosts, engagement_scope):
    """Return the hosts pass 1 reported as down, each re-checked against scope."""
    if type(pass1_hosts) is not list:
        raise ValueError("pass1_hosts must be a list")
    targets = []
    for host in pass1_hosts:
        if host["state"] == "down":
            scope.check_in_scope(host["ip"], engagement_scope)
            targets.append(host["ip"])
    return targets


def build_pass2_command(hosts, profile_name, output_path):
    """Build the pass 2 nmap command as an argument list."""
    if type(hosts) is not list or len(hosts) == 0:
        raise ValueError("pass 2 needs at least one host")
    port_texts = []
    for port in COMMON_TCP_PORTS:
        port_texts.append(str(port))
    command = ["nmap", "-Pn", "-v", "-p", ",".join(port_texts)]
    for option in profile_options(profile_name):
        command.append(option)
    command.append("-oX")
    command.append(output_path)
    for host in hosts:
        command.append(host)
    return command


def load_nmap_xml(path):
    """Parse an Nmap XML file and return its root element."""
    if type(path) is not str or not os.path.isfile(path):
        raise ValueError("nmap XML file not found: " + repr(path))
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as error:
        raise ValueError("not well-formed XML: " + path + " (" + str(error) + ")")
    if root.tag != "nmaprun":
        raise ValueError("not an Nmap XML file (root is <" + root.tag + ">): " + path)
    return root


def host_address(host):
    """Return the IPv4 or IPv6 address of an Nmap <host> element.
    (A host can also carry a MAC address, which we skip.)"""
    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4" or address.get("addrtype") == "ipv6":
            return address.get("addr")
    raise ValueError("Nmap <host> element has no IP address")


def host_name(host):
    """Return the first hostname Nmap found (usually from reverse DNS), or None."""
    hostnames = host.find("hostnames")
    if hostnames is None:
        return None
    first = hostnames.find("hostname")
    if first is None:
        return None
    return first.get("name")


def parse_pass1_xml(path):
    """Return [{"ip", "state", "reason", "hostname"}, ...] from a pass 1 run."""
    root = load_nmap_xml(path)
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None:
            raise ValueError("Nmap <host> element has no <status> in " + path)
        state = status.get("state")
        if state != "up" and state != "down":
            raise ValueError("unexpected host state " + repr(state) + " in " + path)
        hosts.append({
            "ip": host_address(host),
            "state": state,
            "reason": status.get("reason"),
            "hostname": host_name(host),
        })
    return hosts


def classify_pass2_host(host):
    """Decide live / filtered / unresponsive for one pass 2 <host>.

    Returns (status, open_ports). Nmap lists ports one by one in <port>, but
    folds many ports with the same state into a single <extraports> element,
    so both have to be read.
    """
    open_ports = []
    responded = False
    firewall_replied = False

    ports = host.find("ports")
    if ports is not None:
        for port in ports.findall("port"):
            state_element = port.find("state")
            if state_element is None:
                continue
            state = state_element.get("state")
            reason = state_element.get("reason")
            if state == "open":
                open_ports.append(int(port.get("portid")))
                responded = True
            elif state == "closed":
                responded = True
            elif "filtered" in state and reason != "no-response":
                firewall_replied = True

        for extra in ports.findall("extraports"):
            state = extra.get("state")
            if state == "closed":
                responded = True
            elif "filtered" in state:
                for extra_reason in extra.findall("extrareasons"):
                    if extra_reason.get("reason") != "no-response":
                        firewall_replied = True

    if responded:
        return "live", open_ports
    if firewall_replied:
        return "filtered", open_ports
    return "unresponsive", open_ports


def parse_pass2_xml(path):
    """Return [{"ip", "status", "open_ports", "hostname"}, ...] from a pass 2 run."""
    root = load_nmap_xml(path)
    hosts = []
    for host in root.findall("host"):
        status, open_ports = classify_pass2_host(host)
        hosts.append({
            "ip": host_address(host),
            "status": status,
            "open_ports": open_ports,
            "hostname": host_name(host),
        })
    return hosts


def check_results_match_plan(result_ips, planned_ips, label):
    """Every host in the XML must be one we asked nmap to scan.

    For pass 1 the plan is a set of ranges, so each result IP is checked
    against scope instead (see run_pass). For pass 2 the plan is an exact
    host list, and a host outside it means the XML belongs to some other run.
    """
    for ip in result_ips:
        if ip not in planned_ips:
            raise ValueError(label + " result contains " + ip + ", which was not in the planned host list")
    return True


def run_nmap(command):
    """Run nmap for real. Only called outside --dry-run."""
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap is not installed or not on PATH")
    # check=True raises CalledProcessError if nmap exits with an error, so a
    # failed scan can never be mistaken for "no hosts found".
    subprocess.run(command, check=True)
    return True


def run_pass(pass_number, engagement, output_dir, dry_run, fixture_path, now):
    """Run (or, in dry-run, simulate) one discovery pass and return the result dict."""
    if pass_number != 1 and pass_number != 2:
        raise ValueError("pass_number must be 1 or 2")
    scope.check_approved(engagement)
    if not dry_run:
        scope.check_in_window(engagement, now)
    engagement_scope = scope.build_scope(engagement)
    profile_name = engagement["scanning"].get("nmap_profile")
    xml_output = os.path.join(output_dir, "discovery_pass" + str(pass_number) + ".xml")

    if pass_number == 1:
        targets, excludes = plan_pass1(engagement_scope)
        command = build_pass1_command(targets, excludes, profile_name, xml_output)
    else:
        pass1_path = os.path.join(output_dir, "discovery_pass1.json")
        if not os.path.isfile(pass1_path):
            raise ValueError("run pass 1 first: " + pass1_path + " not found")
        with open(pass1_path, "r", encoding="utf-8") as handle:
            pass1 = json.load(handle)
        targets = plan_pass2(pass1["hosts"], engagement_scope)
        if len(targets) == 0:
            # Every host answered pass 1, so there is nothing to sweep. That is a
            # real result, recorded as such.
            return {
                "pass": 2, "dry_run": dry_run, "command": None, "xml": None,
                "hosts": [], "note": "pass 1 found no down hosts; pass 2 skipped",
                "finished_at": now.isoformat(),
            }
        command = build_pass2_command(targets, profile_name, xml_output)

    if dry_run:
        xml_path = fixture_path
    else:
        run_nmap(command)
        xml_path = xml_output

    if pass_number == 1:
        hosts = parse_pass1_xml(xml_path)
        # Defence in depth: nmap was given only in-scope ranges and the
        # excludes, so every host it reports must pass the scope check.
        for host in hosts:
            scope.check_in_scope(host["ip"], engagement_scope)
    else:
        hosts = parse_pass2_xml(xml_path)
        result_ips = []
        for host in hosts:
            result_ips.append(host["ip"])
        check_results_match_plan(result_ips, targets, "pass 2")

    return {
        "pass": pass_number,
        "dry_run": dry_run,
        "command": command,
        "xml": xml_path,
        "hosts": hosts,
        "finished_at": now.isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="Nmap discovery, pass 1 or pass 2.")
    parser.add_argument("--pass", dest="pass_number", type=int, choices=[1, 2], required=True)
    parser.add_argument("--engagement", default="engagement.yaml", help="path to engagement.yaml")
    parser.add_argument("--output-dir", default="engagement/output", help="where to write results")
    parser.add_argument("--dry-run", action="store_true", help="send no packets; read a fixture")
    parser.add_argument("--fixture", default=None, help="fixture XML for --dry-run")
    args = parser.parse_args()

    fixture_path = args.fixture
    if args.dry_run and fixture_path is None:
        fixture_path = DEFAULT_FIXTURES[args.pass_number]

    engagement = scope.load_engagement(args.engagement)
    os.makedirs(args.output_dir, exist_ok=True)
    result = run_pass(
        args.pass_number, engagement, args.output_dir, args.dry_run, fixture_path,
        datetime.now(timezone.utc),
    )

    output_path = os.path.join(args.output_dir, "discovery_pass" + str(args.pass_number) + ".json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print("Pass " + str(args.pass_number) + ": " + str(len(result["hosts"])) + " hosts. Wrote " + output_path)


if __name__ == "__main__":
    main()
