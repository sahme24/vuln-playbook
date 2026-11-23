"""Create every label of the state machine in the engagement repo.

The label list below is the code copy of playbook/labels.md. A test checks
that the two stay identical, so a label cannot be added to one and forgotten
in the other.

Before creating anything, the script checks that the repo is PRIVATE.
Engagement data (findings, hosts, the report) must never land in a public repo.

`gh label create ... --force` creates a label, or updates its color and
description if it already exists. That makes the script safe to run again.

GitHub's default labels (bug, enhancement, ...) are left alone.

CLI usage:
    python scripts/setup_labels.py                  # current repo
    python scripts/setup_labels.py --repo OWNER/REPO
    python scripts/setup_labels.py --dry-run        # print the gh commands only
"""

import argparse
import json
import os
import subprocess

# name, color (hex without #), description (GitHub allows at most 100 characters)
LABELS = [
    {"name": "stage:recon", "color": "1d76db", "description": "Run stage: discovery and Nessus import (recon-scanner)"},
    {"name": "stage:verify", "color": "5319e7", "description": "Run stage: finding issues are being verified"},
    {"name": "stage:report", "color": "0e8a16", "description": "Run stage: the report is being built"},
    {"name": "stage:audit", "color": "b60205", "description": "Run stage: the report PR is under audit"},

    {"name": "status:needs-verify", "color": "fbca04", "description": "New finding, waiting for a verifier"},
    {"name": "status:verified", "color": "0e8a16", "description": "Confirmed real and in scope; goes in the report"},
    {"name": "status:false-positive", "color": "cccccc", "description": "Not actually vulnerable; goes in the false-positive log"},
    {"name": "status:accepted-risk", "color": "c5def5", "description": "Real, but the client has formally accepted the risk"},
    {"name": "status:appendix", "color": "bfd4f2", "description": "Real but low value; goes in the report appendix"},
    {"name": "status:needs-human", "color": "d93f0b", "description": "Evidence conflicts; a human must decide the verdict"},
    {"name": "status:reported", "color": "006b75", "description": "Included in the report PR"},
    {"name": "status:audited", "color": "0b5394", "description": "Passed audit"},
    {"name": "status:audit-rejected", "color": "b60205", "description": "Auditor found a problem; back to the owning agent"},

    {"name": "type:finding", "color": "e99695", "description": "One grouped vulnerability (one Nessus plugin)"},
    {"name": "type:handoff", "color": "c2e0c6", "description": "Coordination issue: kickoff and stage changes"},
    {"name": "type:blocker", "color": "d93f0b", "description": "Something only the human can do or decide"},

    {"name": "needs-human", "color": "d93f0b", "description": "Blocker: the run is waiting for the human to act"},

    {"name": "claimed:recon-scanner", "color": "ededed", "description": "A recon-scanner instance is working on this"},
    {"name": "claimed:verifier", "color": "ededed", "description": "A verifier instance is working on this"},
    {"name": "claimed:report-writer", "color": "ededed", "description": "The report-writer is working on this"},
    {"name": "claimed:auditor", "color": "ededed", "description": "The auditor is working on this"},

    {"name": "severity:critical", "color": "b60205", "description": "Nessus severity 4"},
    {"name": "severity:high", "color": "d93f0b", "description": "Nessus severity 3"},
    {"name": "severity:medium", "color": "fbca04", "description": "Nessus severity 2"},
    {"name": "severity:low", "color": "0e8a16", "description": "Nessus severity 1"},
]


def label_names():
    """Every label name in the catalog, in order."""
    names = []
    for label in LABELS:
        names.append(label["name"])
    return names


def live_run_gh(args, stdin_text):
    """Run the GitHub CLI for real. Returns {"returncode", "stdout", "stderr"}.

    gh is run as an argument list (no shell), so issue titles and comment
    text can never be interpreted as shell commands. Long text (issue bodies,
    comments) is passed on standard input with `--body-file -`, because
    Windows limits a command line to about 32,000 characters.
    """
    completed = subprocess.run(
        ["gh"] + args, input=stdin_text, capture_output=True, text=True, encoding="utf-8"
    )
    return {"returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}


def repo_args(repo):
    """The --repo flag when a repo is named; nothing when gh should use the
    repo of the current folder."""
    if repo is None:
        return []
    if type(repo) is not str or "/" not in repo:
        raise ValueError("repo must look like OWNER/REPO, got " + repr(repo))
    return ["--repo", repo]


def check_repo_private(run_gh, repo):
    """Return True if the engagement repo is private. Raise ValueError otherwise."""
    args = ["repo", "view"]
    if repo is not None:
        if type(repo) is not str or "/" not in repo:
            raise ValueError("repo must look like OWNER/REPO, got " + repr(repo))
        args.append(repo)
    args.append("--json")
    args.append("visibility,nameWithOwner")
    result = run_gh(args, None)
    if result["returncode"] != 0:
        raise RuntimeError("gh repo view failed: " + result["stderr"].strip())
    info = json.loads(result["stdout"])
    if info.get("visibility") != "PRIVATE":
        raise ValueError(
            "repo " + str(info.get("nameWithOwner")) + " is " + str(info.get("visibility"))
            + "; engagement data may only be stored in a PRIVATE repo"
        )
    return True


def build_label_commands(repo):
    """The gh argument lists that create or update every label."""
    commands = []
    for label in LABELS:
        if len(label["description"]) > 100:
            raise ValueError("description of " + label["name"] + " is longer than GitHub's 100 characters")
        command = ["label", "create", label["name"], "--color", label["color"],
                   "--description", label["description"], "--force"]
        for extra in repo_args(repo):
            command.append(extra)
        commands.append(command)
    return commands


def setup_labels(run_gh, repo):
    """Check the repo is private, then create or update every label.
    Returns the list of label names created."""
    check_repo_private(run_gh, repo)
    created = []
    for command in build_label_commands(repo):
        result = run_gh(command, None)
        if result["returncode"] != 0:
            raise RuntimeError("creating label " + command[2] + " failed: " + result["stderr"].strip())
        created.append(command[2])
    return created


def main():
    parser = argparse.ArgumentParser(description="Create the playbook labels in the engagement repo.")
    parser.add_argument("--repo", default=None, help="OWNER/REPO (default: the current folder's repo)")
    parser.add_argument("--output-dir", default="engagement/output")
    parser.add_argument("--dry-run", action="store_true", help="print the gh commands, change nothing")
    args = parser.parse_args()

    if args.dry_run:
        for command in build_label_commands(args.repo):
            print("gh " + " ".join(command))
        return

    created = setup_labels(live_run_gh, args.repo)
    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, "labels_setup.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump({"repo": args.repo, "labels": created}, handle, indent=2)
    print("Created or updated " + str(len(created)) + " labels. Wrote " + output_path)


if __name__ == "__main__":
    main()
