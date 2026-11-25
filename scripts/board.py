"""Thin helpers around the GitHub CLI (gh) for the issue board.

Agents never call `gh issue edit` themselves. They go through this script,
which enforces the invariants of playbook/labels.md in code:

  1. A finding has exactly one status:* label. A transition removes the old
     label and adds the new one in ONE `gh issue edit` call.
  2. A transition is refused unless the issue's current status is the one
     the caller expects ("from"), so no agent acts on stale information.
  3. Only the actor named in labels.md may make each transition.
  4. At most one claimed:* label. Claiming an already-claimed issue is refused.
  5. The verifier must hold claimed:verifier to apply a verdict, and the claim
     is released in the same call.
  6. The kickoff issue has exactly one stage:* label.
  7. No comment or issue body may contain a "Decision:" line. Only the human
     writes those, in GitHub. Agents post through the same gh login as the
     human, so this ban is what makes a Decision line trustworthy.
  8. Every state change posts a handoff block (playbook/handoff-format.md).
  9. No comment or issue body may contain something that looks like a
     credential (password assignment, private key, cloud or GitHub token).

Testing: every function takes `run_gh` as an argument. In real use that is
setup_labels.live_run_gh. The tests pass a small stand-in that records the
gh commands and returns canned output, so nothing touches GitHub.

CLI usage (run from the engagement repo):
    python scripts/board.py view --issue 12
    python scripts/board.py list --label status:needs-verify
    python scripts/board.py create-finding --plugin-id 900104
    python scripts/board.py claim --issue 12 --agent verifier
    python scripts/board.py transition --issue 12 --actor verifier --from needs-verify \
        --to verified --rule kev_match --evidence "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" \
        --confidence high --next-owner report-writer --notes "KEV listed, confirmed remotely."
    python scripts/board.py decision --issue 17
    python scripts/board.py relay-decision --issue 17
    python scripts/board.py review-pr --pr 30 --verdict audited --rule audit_checklist \
        --evidence "audit-checklist.md: all checks passed" --confidence high \
        --next-owner human --notes "Every check passed; ready for the human to merge."
"""

import argparse
import json
import os
import re

import group_findings
import setup_labels

AGENTS = ["orchestrator", "recon-scanner", "verifier", "report-writer", "auditor"]
NEXT_OWNERS = ["recon-scanner", "verifier", "report-writer", "auditor", "orchestrator", "human", "none"]
CONFIDENCE_LEVELS = ["high", "medium", "low"]
STATUSES = [
    "needs-verify", "verified", "false-positive", "accepted-risk", "appendix",
    "needs-human", "reported", "audited", "audit-rejected",
]
STAGES = ["stage:recon", "stage:verify", "stage:report", "stage:audit"]
HUMAN_DECISIONS = ["verified", "false-positive", "accepted-risk", "appendix"]

# Allowed handoff verdicts per agent (playbook/handoff-format.md).
ALLOWED_VERDICTS = {
    "recon-scanner": ["claimed", "needs-verify", "needs-human"],
    "verifier": ["claimed", "verified", "false-positive", "accepted-risk", "appendix", "needs-human"],
    "report-writer": ["claimed", "reported"],
    "auditor": ["claimed", "audited", "audit-rejected"],
    "orchestrator": STAGES + HUMAN_DECISIONS + ["needs-verify", "needs-human", "closed"],
}

# The transition table of playbook/labels.md: actor -> list of (from, to).
# "*" as the from-state means "any status".
TRANSITIONS = {
    "verifier": [
        ("needs-verify", "verified"), ("needs-verify", "false-positive"),
        ("needs-verify", "accepted-risk"), ("needs-verify", "appendix"),
        ("needs-verify", "needs-human"),
    ],
    "orchestrator": [
        ("needs-human", "verified"), ("needs-human", "false-positive"),
        ("needs-human", "accepted-risk"), ("needs-human", "appendix"),
        ("audit-rejected", "needs-verify"), ("audit-rejected", "verified"),
    ],
    "report-writer": [("verified", "reported")],
    "auditor": [("reported", "audited"), ("*", "audit-rejected")],
    "recon-scanner": [],
}

# A finding issue body carries this marker so any agent can read the plugin
# ID back from an issue without parsing the title.
PLUGIN_MARKER = re.compile(r"<!-- vuln-playbook: plugin_id=(\d+) -->")

DECISION_LINE = re.compile(r"^\s*Decision:\s*(\S.*?)\s*$", re.MULTILINE)
REASON_LINE = re.compile(r"^\s*Reason:\s*(\S.*?)\s*$", re.MULTILINE)
RULE_NAME = re.compile(r"[a-z][a-z0-9_]*")

# Patterns that look like credentials. They are deliberately narrow (an
# assignment, a key header, a known token shape) so normal plugin text such
# as "PasswordAuthentication yes" does not trip them.
SECRET_PATTERNS = [
    ("password assignment", re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*\S+")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("API key assignment", re.compile(r"(?i)\b(api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{16,}")),
]

# Limits that keep an issue body well under GitHub's 65,536-character cap.
MAX_TABLE_ROWS = 200
MAX_OUTPUT_SAMPLES = 5
MAX_OUTPUT_LINES = 20


# --- text checks ---------------------------------------------------------------

def find_secrets(text):
    """Return the names of the credential patterns found in text (empty list
    if none)."""
    if type(text) is not str:
        raise ValueError("text must be a string")
    found = []
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text) is not None:
            found.append(name)
    return found


def check_postable(text):
    """Refuse text an agent must never post. Returns True if it is safe."""
    if type(text) is not str or text.strip() == "":
        raise ValueError("comment or issue body must be a non-empty string")
    if DECISION_LINE.search(text) is not None:
        raise ValueError(
            "refusing to post a 'Decision:' line: only the human writes decisions, directly in GitHub"
        )
    secrets = find_secrets(text)
    if len(secrets) > 0:
        raise ValueError(
            "refusing to post text that looks like a credential (" + ", ".join(secrets)
            + "); redact it and describe it instead"
        )
    return True


# --- handoff blocks ----------------------------------------------------------------

def validate_handoff(handoff):
    """Check a handoff dict against playbook/handoff-format.md."""
    if type(handoff) is not dict:
        raise ValueError("handoff must be a dict")
    for field in ["agent", "issue", "verdict", "rule", "evidence", "confidence", "next_owner", "notes"]:
        if field not in handoff:
            raise ValueError("handoff is missing '" + field + "'")
    agent = handoff["agent"]
    if agent not in AGENTS:
        raise ValueError("handoff agent must be one of " + ", ".join(AGENTS))
    issue = handoff["issue"]
    if type(issue) is int:
        if issue < 1:
            raise ValueError("handoff issue number must be positive")
    elif type(issue) is str:
        if re.fullmatch(r"PR #\d+", issue) is None:
            raise ValueError("handoff issue must be an issue number or 'PR #N'")
    else:
        raise ValueError("handoff issue must be an int or 'PR #N'")
    if handoff["verdict"] not in ALLOWED_VERDICTS[agent]:
        raise ValueError(
            "verdict " + repr(handoff["verdict"]) + " is not allowed for " + agent
            + " (allowed: " + ", ".join(ALLOWED_VERDICTS[agent]) + ")"
        )
    if type(handoff["rule"]) is not str or RULE_NAME.fullmatch(handoff["rule"]) is None:
        raise ValueError("handoff rule must be a snake_case rule name")
    evidence = handoff["evidence"]
    if type(evidence) is not list or len(evidence) == 0:
        raise ValueError("handoff needs at least one evidence item")
    for item in evidence:
        if type(item) is not str or item.strip() == "" or "\n" in item:
            raise ValueError("each evidence item must be one non-empty line")
    if handoff["confidence"] not in CONFIDENCE_LEVELS:
        raise ValueError("handoff confidence must be high, medium or low")
    if handoff["next_owner"] not in NEXT_OWNERS:
        raise ValueError("handoff next_owner must be one of " + ", ".join(NEXT_OWNERS))
    notes = handoff["notes"]
    if type(notes) is not str or notes.strip() == "" or "\n" in notes:
        raise ValueError("handoff notes must be one non-empty line")
    return True


def render_handoff(handoff):
    """Return the markdown text of a handoff block (the comment body itself)."""
    validate_handoff(handoff)
    if type(handoff["issue"]) is int:
        issue_text = "#" + str(handoff["issue"])
    else:
        issue_text = handoff["issue"]
    lines = [
        "### Handoff",
        "- Agent: " + handoff["agent"],
        "- Issue: " + issue_text,
        "- Verdict: " + handoff["verdict"],
        "- Rule fired: " + handoff["rule"],
        "- Evidence:",
    ]
    for item in handoff["evidence"]:
        lines.append("  - " + item.strip())
    lines.append("- Confidence: " + handoff["confidence"])
    lines.append("- Next owner: " + handoff["next_owner"])
    lines.append("- Notes: " + handoff["notes"].strip())
    return "\n".join(lines) + "\n"


def parse_handoff(text):
    """Parse a handoff block from the start of a comment back into a dict.
    Raises ValueError if the comment does not start with a valid block."""
    if type(text) is not str:
        raise ValueError("handoff text must be a string")
    lines = text.strip().splitlines()
    if len(lines) == 0 or lines[0].strip() != "### Handoff":
        raise ValueError("comment does not start with '### Handoff'")

    fields = {"Agent": None, "Issue": None, "Verdict": None, "Rule fired": None,
              "Confidence": None, "Next owner": None, "Notes": None}
    evidence = []
    in_evidence = False
    for line in lines[1:]:
        if line.startswith("  - ") and in_evidence:
            evidence.append(line[4:].strip())
            continue
        if not line.startswith("- "):
            # The block ends at the first line that is not part of it. Free
            # text may follow the block.
            break
        in_evidence = False
        content = line[2:]
        if content.strip() == "Evidence:":
            in_evidence = True
            continue
        if ": " not in content:
            raise ValueError("malformed handoff line: " + repr(line))
        name, value = content.split(": ", 1)
        if name not in fields:
            raise ValueError("unknown handoff field: " + repr(name))
        fields[name] = value.strip()

    for name in fields:
        if fields[name] is None:
            raise ValueError("handoff block is missing '" + name + "'")

    issue_text = fields["Issue"]
    if re.fullmatch(r"#\d+", issue_text) is not None:
        issue = int(issue_text[1:])
    else:
        issue = issue_text
    handoff = {
        "agent": fields["Agent"],
        "issue": issue,
        "verdict": fields["Verdict"],
        "rule": fields["Rule fired"],
        "evidence": evidence,
        "confidence": fields["Confidence"],
        "next_owner": fields["Next owner"],
        "notes": fields["Notes"],
    }
    validate_handoff(handoff)
    return handoff


# --- reading the board ---------------------------------------------------------------

def gh_json(run_gh, args):
    """Run a gh command that prints JSON and return the parsed result."""
    result = run_gh(args, None)
    if result["returncode"] != 0:
        raise RuntimeError("gh " + " ".join(args[:3]) + " failed: " + result["stderr"].strip())
    return json.loads(result["stdout"])


def get_issue(number, run_gh, repo):
    """Return {"number", "title", "state", "labels": [names], "body"}."""
    if type(number) is not int or number < 1:
        raise ValueError("issue number must be a positive integer")
    args = ["issue", "view", str(number), "--json", "number,title,state,labels,body"]
    data = gh_json(run_gh, args + setup_labels.repo_args(repo))
    labels = []
    for label in data["labels"]:
        labels.append(label["name"])
    return {"number": data["number"], "title": data["title"], "state": data["state"],
            "labels": labels, "body": data["body"]}


def list_issues(label, run_gh, repo):
    """Return the open issues carrying `label`, as [{"number", "title", "labels"}]."""
    if label not in setup_labels.label_names():
        raise ValueError("unknown label " + repr(label))
    args = ["issue", "list", "--label", label, "--state", "open", "--limit", "500",
            "--json", "number,title,labels"]
    data = gh_json(run_gh, args + setup_labels.repo_args(repo))
    issues = []
    for item in data:
        labels = []
        for entry in item["labels"]:
            labels.append(entry["name"])
        issues.append({"number": item["number"], "title": item["title"], "labels": labels})
    return issues


def labels_with_prefix(labels, prefix):
    found = []
    for label in labels:
        if label.startswith(prefix):
            found.append(label)
    return found


def current_status(issue):
    """The issue's single status (without the "status:" prefix). Raises if it
    has zero or several status labels, which would break invariant 1."""
    statuses = labels_with_prefix(issue["labels"], "status:")
    if len(statuses) != 1:
        raise ValueError(
            "issue #" + str(issue["number"]) + " must have exactly one status label, has: "
            + ", ".join(statuses)
        )
    return statuses[0][len("status:"):]


def plugin_id_of(issue):
    """Read the plugin ID marker from a finding issue body."""
    body = issue["body"]
    if body is None:
        body = ""
    match = PLUGIN_MARKER.search(body)
    if match is None:
        raise ValueError("issue #" + str(issue["number"]) + " has no plugin_id marker; is it a finding?")
    return int(match.group(1))


# --- writing to the board ----------------------------------------------------------

def edit_labels(number, add, remove, run_gh, repo):
    """Add and remove labels in ONE gh call, so the issue is never left
    half-changed between two calls."""
    args = ["issue", "edit", str(number)]
    for label in add:
        args.append("--add-label")
        args.append(label)
    for label in remove:
        args.append("--remove-label")
        args.append(label)
    result = run_gh(args + setup_labels.repo_args(repo), None)
    if result["returncode"] != 0:
        raise RuntimeError("gh issue edit #" + str(number) + " failed: " + result["stderr"].strip())
    return True


def comment(number, body, run_gh, repo):
    """Post a comment after the safety checks. Returns the comment URL."""
    if type(number) is not int or number < 1:
        raise ValueError("issue number must be a positive integer")
    check_postable(body)
    args = ["issue", "comment", str(number), "--body-file", "-"]
    result = run_gh(args + setup_labels.repo_args(repo), body)
    if result["returncode"] != 0:
        raise RuntimeError("gh issue comment #" + str(number) + " failed: " + result["stderr"].strip())
    return result["stdout"].strip()


def post_handoff(handoff, run_gh, repo):
    """Render and post a handoff block on its issue. Returns the comment URL."""
    if type(handoff.get("issue")) is not int:
        raise ValueError("post_handoff posts on issues; for a PR review use the auditor's gh pr review")
    return comment(handoff["issue"], render_handoff(handoff), run_gh, repo)


def create_issue(title, body, labels, run_gh, repo):
    """Create an issue with known labels only. Returns the new issue number."""
    if type(title) is not str or title.strip() == "":
        raise ValueError("issue title must be a non-empty string")
    check_postable(title)
    check_postable(body)
    if type(labels) is not list or len(labels) == 0:
        raise ValueError("an issue needs at least one label")
    known = setup_labels.label_names()
    for label in labels:
        if label not in known:
            raise ValueError("unknown label " + repr(label) + " (run setup_labels.py)")
    args = ["issue", "create", "--title", title, "--body-file", "-"]
    for label in labels:
        args.append("--label")
        args.append(label)
    result = run_gh(args + setup_labels.repo_args(repo), body)
    if result["returncode"] != 0:
        raise RuntimeError("gh issue create failed: " + result["stderr"].strip())
    # gh prints the new issue's URL, ending in /issues/<number>.
    url = result["stdout"].strip().splitlines()[-1]
    match = re.search(r"/issues/(\d+)$", url)
    if match is None:
        raise RuntimeError("could not read the new issue number from gh output: " + repr(url))
    return int(match.group(1))


def claim(number, agent, run_gh, repo):
    """Add claimed:<agent> and post the claim handoff. Refused if any
    claimed:* label is already present. Returns the handoff comment URL."""
    if agent not in AGENTS or agent == "orchestrator":
        raise ValueError("only the four subagents claim issues, got " + repr(agent))
    issue = get_issue(number, run_gh, repo)
    existing = labels_with_prefix(issue["labels"], "claimed:")
    if len(existing) > 0:
        raise ValueError("issue #" + str(number) + " is already claimed (" + ", ".join(existing) + ")")
    edit_labels(number, ["claimed:" + agent], [], run_gh, repo)
    handoff = {
        "agent": agent, "issue": number, "verdict": "claimed", "rule": "claim",
        "evidence": ["claimed:" + agent + " label added"], "confidence": "high",
        "next_owner": agent, "notes": agent + " is working on this issue.",
    }
    return post_handoff(handoff, run_gh, repo)


def release(number, agent, run_gh, repo):
    """Remove claimed:<agent>. Refused if the agent does not hold the claim."""
    issue = get_issue(number, run_gh, repo)
    if "claimed:" + agent not in issue["labels"]:
        raise ValueError("issue #" + str(number) + " is not claimed by " + str(agent))
    edit_labels(number, [], ["claimed:" + agent], run_gh, repo)
    return True


def check_transition_allowed(actor, from_status, to_status):
    if actor not in TRANSITIONS:
        raise ValueError("unknown actor " + repr(actor))
    if from_status not in STATUSES or to_status not in STATUSES:
        raise ValueError("unknown status in transition " + repr(from_status) + " -> " + repr(to_status))
    for allowed_from, allowed_to in TRANSITIONS[actor]:
        if allowed_to == to_status and (allowed_from == from_status or allowed_from == "*"):
            return True
    raise ValueError(
        actor + " may not move an issue from " + from_status + " to " + to_status
        + " (see the transition table in playbook/labels.md)"
    )


def transition(number, actor, from_status, to_status, handoff, run_gh, repo):
    """Move a finding from one status to another and post the handoff block.

    The label change happens first, in one call. It is the guarded step, so
    if it is refused, no misleading comment has been posted.
    """
    check_transition_allowed(actor, from_status, to_status)
    if handoff["agent"] != actor or handoff["issue"] != number:
        raise ValueError("the handoff must be from " + actor + " for issue #" + str(number))
    validate_handoff(handoff)
    # Check the comment can be posted BEFORE changing labels, so a refused
    # comment cannot leave a label change without its handoff block.
    check_postable(render_handoff(handoff))

    issue = get_issue(number, run_gh, repo)
    actual = current_status(issue)
    if actual != from_status:
        raise ValueError(
            "issue #" + str(number) + " is in status " + actual + ", not " + from_status
            + "; re-read the board before acting"
        )

    remove = ["status:" + from_status]
    if actor == "verifier":
        if "claimed:verifier" not in issue["labels"]:
            raise ValueError("verifier must claim issue #" + str(number) + " before giving a verdict")
        remove.append("claimed:verifier")
    edit_labels(number, ["status:" + to_status], remove, run_gh, repo)
    return post_handoff(handoff, run_gh, repo)


def set_stage(number, new_stage, handoff, run_gh, repo):
    """Move the kickoff issue to a new stage (orchestrator only)."""
    if new_stage not in STAGES:
        raise ValueError("stage must be one of " + ", ".join(STAGES))
    if handoff["agent"] != "orchestrator" or handoff["verdict"] != new_stage:
        raise ValueError("a stage change needs an orchestrator handoff with verdict " + new_stage)
    validate_handoff(handoff)
    check_postable(render_handoff(handoff))
    issue = get_issue(number, run_gh, repo)
    stages = labels_with_prefix(issue["labels"], "stage:")
    if len(stages) != 1:
        raise ValueError("kickoff issue #" + str(number) + " must have exactly one stage label")
    if stages[0] == new_stage:
        raise ValueError("kickoff issue is already in " + new_stage)
    edit_labels(number, [new_stage], [stages[0]], run_gh, repo)
    return post_handoff(handoff, run_gh, repo)


def close_issue(number, handoff, run_gh, repo):
    """Close a resolved blocker or, after the merge, a finding issue
    (orchestrator only). The plain needs-human label is removed first, so a
    closed blocker never looks like it is still waiting on the human."""
    if handoff["agent"] != "orchestrator" or handoff["verdict"] != "closed":
        raise ValueError("closing an issue needs an orchestrator handoff with verdict 'closed'")
    if handoff["issue"] != number:
        raise ValueError("the handoff must be for issue #" + str(number))
    validate_handoff(handoff)
    check_postable(render_handoff(handoff))
    issue = get_issue(number, run_gh, repo)
    if issue["state"] != "OPEN":
        raise ValueError("issue #" + str(number) + " is already closed")
    if "needs-human" in issue["labels"]:
        edit_labels(number, [], ["needs-human"], run_gh, repo)
    url = post_handoff(handoff, run_gh, repo)
    result = run_gh(["issue", "close", str(number)] + setup_labels.repo_args(repo), None)
    if result["returncode"] != 0:
        raise RuntimeError("gh issue close #" + str(number) + " failed: " + result["stderr"].strip())
    return url


def review_pr(pr_number, handoff, run_gh, repo):
    """Post the auditor's verdict on the report PR as a review comment.

    GitHub does not let an account approve, or request changes on, a pull
    request it opened itself. The report-writer and the auditor use the same
    gh login, so a formal approval is impossible. The verdict is therefore a
    review COMMENT whose handoff block says audited or audit-rejected, and the
    human merges the PR. Returns gh's output (the review URL, if printed).
    """
    if type(pr_number) is not int or pr_number < 1:
        raise ValueError("PR number must be a positive integer")
    if handoff["agent"] != "auditor":
        raise ValueError("only the auditor reviews the report PR")
    if handoff["issue"] != "PR #" + str(pr_number):
        raise ValueError("the handoff must refer to PR #" + str(pr_number))
    if handoff["verdict"] != "audited" and handoff["verdict"] != "audit-rejected":
        raise ValueError("a PR review verdict must be audited or audit-rejected")
    body = render_handoff(handoff)
    check_postable(body)
    args = ["pr", "review", str(pr_number), "--comment", "--body-file", "-"]
    result = run_gh(args + setup_labels.repo_args(repo), body)
    if result["returncode"] != 0:
        raise RuntimeError("gh pr review #" + str(pr_number) + " failed: " + result["stderr"].strip())
    return result["stdout"].strip()


# --- human decisions ----------------------------------------------------------------

def parse_decision(text):
    """Return {"decision", "reason"} from a comment, or None if it has no
    Decision line. None is the normal answer for ordinary comments."""
    if type(text) is not str:
        raise ValueError("comment text must be a string")
    match = DECISION_LINE.search(text)
    if match is None:
        return None
    reason = None
    reason_match = REASON_LINE.search(text)
    if reason_match is not None:
        reason = reason_match.group(1)
    return {"decision": match.group(1).strip().lower(), "reason": reason}


def latest_decision(number, run_gh, repo):
    """Return the most recent human decision on an issue as
    {"decision", "reason", "url", "author", "created_at"}, or None if the
    human has not answered yet."""
    args = ["issue", "view", str(number), "--json", "comments"]
    data = gh_json(run_gh, args + setup_labels.repo_args(repo))
    found = None
    for entry in data["comments"]:
        parsed = parse_decision(entry["body"])
        if parsed is None:
            continue
        author = None
        if type(entry.get("author")) is dict:
            author = entry["author"].get("login")
        found = {"decision": parsed["decision"], "reason": parsed["reason"],
                 "url": entry.get("url"), "author": author, "created_at": entry.get("createdAt")}
    return found


def relay_decision(number, run_gh, repo):
    """Apply the human's decision on a status:needs-human finding.
    Returns the decision that was applied."""
    decision = latest_decision(number, run_gh, repo)
    if decision is None:
        raise ValueError("issue #" + str(number) + " has no 'Decision:' comment from the human yet")
    if decision["decision"] not in HUMAN_DECISIONS:
        raise ValueError(
            "decision " + repr(decision["decision"]) + " is not one of: " + ", ".join(HUMAN_DECISIONS)
        )
    if decision["reason"] is None:
        raise ValueError("the human's decision on #" + str(number) + " has no 'Reason:' line; ask for one")
    evidence = [decision["url"]]
    if decision["url"] is None:
        evidence = ["Decision comment on issue #" + str(number)]
    next_owner = "none"
    if decision["decision"] == "verified":
        next_owner = "report-writer"
    handoff = {
        "agent": "orchestrator", "issue": number, "verdict": decision["decision"],
        "rule": "human_decision", "evidence": evidence, "confidence": "high",
        "next_owner": next_owner,
        "notes": "Applied the human's decision as written; see the linked comment for the reason.",
    }
    transition(number, "orchestrator", "needs-human", decision["decision"], handoff, run_gh, repo)
    return decision


def record_human_decision(output_dir, plugin_id, decision):
    """Write the human's decision into engagement/output/triage/<plugin_id>.json.

    Without this, the triage file keeps saying "needs-human" after the board
    has moved on, and anyone reading the files on disk (the report-writer,
    the auditor, the operator later) sees a stale outcome. The verifier's own
    "verdict" and "rule" are deliberately left untouched: they record what
    the triage rules concluded, and the new "human_decision" block records
    what the person decided on top of that. Keeping both preserves the history.

    `decision` is the dict returned by relay_decision. Returns the file path."""
    if type(plugin_id) is not int or plugin_id < 1:
        raise ValueError("plugin_id must be a positive integer")
    if type(decision) is not dict:
        raise ValueError("decision must be the dict returned by relay_decision")
    for field in ["decision", "reason", "url"]:
        if field not in decision:
            raise ValueError("decision is missing '" + field + "'")

    path = os.path.join(output_dir, "triage", str(plugin_id) + ".json")
    if not os.path.isfile(path):
        raise ValueError(
            "no triage file for plugin " + str(plugin_id) + " at " + path
            + "; the board was updated but the decision could not be written to disk"
        )
    with open(path, "r", encoding="utf-8") as handle:
        result = json.load(handle)
    if type(result) is not dict:
        raise ValueError(path + " must contain a JSON object")

    # Only findings the triage rules sent to a human can carry a human
    # decision. Anything else means the wrong file or a mixed-up issue.
    if result.get("verdict") != "needs-human":
        raise ValueError(
            path + " has verdict " + repr(result.get("verdict"))
            + ", not 'needs-human'; refusing to attach a human decision to it"
        )

    # Re-running with the same decision comment is harmless (same data
    # written again). A DIFFERENT decision already on file would be silently
    # overwritten, which would erase history, so that is refused.
    existing = result.get("human_decision")
    if existing is not None and existing.get("url") != decision["url"]:
        raise ValueError(
            path + " already records a different human decision (" + repr(existing.get("url")) + ")"
        )

    result["human_decision"] = {
        "verdict": decision["decision"],
        "reason": decision["reason"],
        "url": decision["url"],
        "author": decision.get("author"),
        "created_at": decision.get("created_at"),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    return path


# --- finding issues ------------------------------------------------------------------

def truncate_lines(text, max_lines):
    """Return (shortened text, number of lines removed)."""
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text, 0
    kept = "\n".join(lines[:max_lines])
    return kept, len(lines) - max_lines


def finding_title(group):
    host_word = "hosts"
    if group["host_count"] == 1:
        host_word = "host"
    return ("[" + str(group["plugin_id"]) + "] " + group["plugin_name"] + " ("
            + group["severity_name"] + ", " + str(group["host_count"]) + " " + host_word + ")")


def finding_body(group):
    """The markdown body of a finding issue, built from a grouped finding.

    Plugin output is shown for at most MAX_OUTPUT_SAMPLES hosts and cut to
    MAX_OUTPUT_LINES lines each. The full output stays in findings.json on
    the operator's machine.
    """
    lines = ["<!-- vuln-playbook: plugin_id=" + str(group["plugin_id"]) + " -->", ""]
    lines.append("## " + group["plugin_name"])
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| Plugin ID | " + str(group["plugin_id"]) + " |")
    lines.append("| Severity (Nessus) | " + group["severity_name"] + " |")
    cves = "none"
    if len(group["cves"]) > 0:
        cves = ", ".join(group["cves"])
    lines.append("| CVEs | " + cves + " |")
    lines.append("| CVSS v3 (Nessus) | " + str(group["cvss3_base_score"]) + " |")
    lines.append("| VPR | " + str(group["vpr_score"]) + " |")
    lines.append("| Exploit available | " + str(group["exploit_available"]) + " |")
    lines.append("| Detection type | " + str(group["plugin_type"]) + " |")
    lines.append("| Affected hosts | " + str(group["host_count"]) + " |")
    if len(group["related_plugin_ids"]) > 0:
        related = []
        for plugin_id in group["related_plugin_ids"]:
            related.append(str(plugin_id))
        lines.append("| Shares a CVE with plugins | " + ", ".join(related) + " |")
    lines.append("")
    lines.append("### Synopsis")
    lines.append(str(group["synopsis"]))
    lines.append("")
    lines.append("### Description")
    lines.append(str(group["description"]))
    lines.append("")
    lines.append("### Solution (Nessus)")
    lines.append(str(group["solution"]))
    lines.append("")
    lines.append("### Affected")
    lines.append("")
    lines.append("| Host | Hostname | Port | OS |")
    lines.append("|---|---|---|---|")
    row = 0
    for entry in group["affected"]:
        if row >= MAX_TABLE_ROWS:
            lines.append("")
            lines.append("_" + str(len(group["affected"]) - row) + " more entries in findings.json._")
            break
        lines.append("| " + entry["host_ip"] + " | " + str(entry["hostname"]) + " | "
                     + str(entry["port"]) + "/" + entry["protocol"] + " | "
                     + str(entry["operating_system"]) + " |")
        row = row + 1
    lines.append("")
    lines.append("### Plugin output (sample)")
    sample = 0
    for entry in group["affected"]:
        if sample >= MAX_OUTPUT_SAMPLES:
            break
        if entry["plugin_output"] is None:
            continue
        text, removed = truncate_lines(entry["plugin_output"], MAX_OUTPUT_LINES)
        lines.append("")
        lines.append("<details><summary>" + entry["host_ip"] + " port " + str(entry["port"])
                     + "</summary>")
        lines.append("")
        lines.append("```")
        lines.append(text)
        lines.append("```")
        if removed > 0:
            lines.append("_" + str(removed) + " more lines in findings.json._")
        lines.append("</details>")
        sample = sample + 1
    if len(group["see_also"]) > 0:
        lines.append("")
        lines.append("### References (Nessus)")
        for url in group["see_also"]:
            lines.append("- " + url)
    return "\n".join(lines) + "\n"


def create_finding_issue(group, run_gh, repo):
    """Open a finding issue for one grouped finding and post the recon-scanner
    handoff. Returns the issue number."""
    if group["severity"] == 0:
        raise ValueError("informational plugins never become issues (triage rule informational_plugin)")
    labels = ["type:finding", "status:needs-verify", "severity:" + group["severity_name"]]
    number = create_issue(finding_title(group), finding_body(group), labels, run_gh, repo)
    handoff = {
        "agent": "recon-scanner", "issue": number, "verdict": "needs-verify",
        "rule": "nessus_import",
        "evidence": [
            "plugin " + str(group["plugin_id"]) + " in the imported .nessus file",
            str(group["host_count"]) + " affected host(s), all confirmed in scope by scope.py",
        ],
        "confidence": "high", "next_owner": "verifier",
        "notes": "Grouped from " + str(len(group["affected"])) + " Nessus result(s) with the same plugin ID.",
    }
    post_handoff(handoff, run_gh, repo)
    return number


# --- CLI ---------------------------------------------------------------------------

def read_body(args):
    """Comment/issue text from --body or --body-file (exactly one)."""
    if args.body is not None and args.body_file is not None:
        raise ValueError("give --body or --body-file, not both")
    if args.body is not None:
        return args.body
    if args.body_file is not None:
        with open(args.body_file, "r", encoding="utf-8") as handle:
            return handle.read()
    raise ValueError("give --body or --body-file")


def handoff_from_args(args, agent, issue, verdict):
    return {
        "agent": agent, "issue": issue, "verdict": verdict, "rule": args.rule,
        "evidence": args.evidence, "confidence": args.confidence,
        "next_owner": args.next_owner, "notes": args.notes,
    }


def add_handoff_arguments(parser):
    parser.add_argument("--rule", required=True)
    parser.add_argument("--evidence", action="append", required=True, help="repeat for each item")
    parser.add_argument("--confidence", required=True, choices=CONFIDENCE_LEVELS)
    parser.add_argument("--next-owner", required=True, choices=NEXT_OWNERS)
    parser.add_argument("--notes", required=True)


def load_issue_map(output_dir):
    """Return the plugin_id -> issue number mapping ({} before the first issue).
    Keys are strings because JSON object keys are always strings."""
    path = os.path.join(output_dir, "board", "issue_map.json")
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        mapping = json.load(handle)
    if type(mapping) is not dict:
        raise ValueError(path + " must contain a JSON object")
    return mapping


def check_not_opened(output_dir, plugin_id):
    """Refuse to open a second issue for the same plugin. This matters when
    recon-scanner is re-run after a partial failure: the plugins that already
    have an issue must be skipped, not duplicated."""
    mapping = load_issue_map(output_dir)
    if str(plugin_id) in mapping:
        raise ValueError(
            "plugin " + str(plugin_id) + " already has issue #" + str(mapping[str(plugin_id)])
        )
    return True


def save_issue_map(output_dir, plugin_id, number):
    """Record plugin_id -> issue number in engagement/output/board/issue_map.json,
    so later steps (report, audit) can find each finding's issue."""
    folder = os.path.join(output_dir, "board")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "issue_map.json")
    mapping = load_issue_map(output_dir)
    mapping[str(plugin_id)] = number
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(mapping, handle, indent=2)
    return path


def main():
    parser = argparse.ArgumentParser(description="Safe helpers for the GitHub issue board.")
    parser.add_argument("--repo", default=None, help="OWNER/REPO (default: current folder's repo)")
    parser.add_argument("--output-dir", default="engagement/output")
    sub = parser.add_subparsers(dest="command", required=True)

    view = sub.add_parser("view", help="show one issue as JSON")
    view.add_argument("--issue", type=int, required=True)

    listing = sub.add_parser("list", help="list open issues with a label")
    listing.add_argument("--label", required=True)

    finding = sub.add_parser("create-finding", help="open the issue for one grouped finding")
    finding.add_argument("--plugin-id", type=int, required=True)
    finding.add_argument("--grouped", default="engagement/output/to_open.json")

    create = sub.add_parser("create-issue", help="open a kickoff, handoff or blocker issue")
    create.add_argument("--title", required=True)
    create.add_argument("--label", action="append", required=True)
    create.add_argument("--body", default=None)
    create.add_argument("--body-file", default=None)

    note = sub.add_parser("comment", help="post a plain comment (no state change)")
    note.add_argument("--issue", type=int, required=True)
    note.add_argument("--body", default=None)
    note.add_argument("--body-file", default=None)

    handoff = sub.add_parser("handoff", help="post a handoff block without a status change")
    handoff.add_argument("--issue", type=int, required=True)
    handoff.add_argument("--agent", required=True, choices=AGENTS)
    handoff.add_argument("--verdict", required=True)
    add_handoff_arguments(handoff)

    claim_parser = sub.add_parser("claim", help="claim an issue for an agent")
    claim_parser.add_argument("--issue", type=int, required=True)
    claim_parser.add_argument("--agent", required=True, choices=AGENTS)

    release_parser = sub.add_parser("release", help="release an agent's claim")
    release_parser.add_argument("--issue", type=int, required=True)
    release_parser.add_argument("--agent", required=True, choices=AGENTS)

    move = sub.add_parser("transition", help="change a finding's status (posts a handoff)")
    move.add_argument("--issue", type=int, required=True)
    move.add_argument("--actor", required=True, choices=AGENTS)
    move.add_argument("--from", dest="from_status", required=True, choices=STATUSES)
    move.add_argument("--to", dest="to_status", required=True, choices=STATUSES)
    add_handoff_arguments(move)

    stage = sub.add_parser("set-stage", help="move the kickoff issue to a new stage")
    stage.add_argument("--issue", type=int, required=True)
    stage.add_argument("--stage", required=True, choices=STAGES)
    add_handoff_arguments(stage)

    decision = sub.add_parser("decision", help="show the human's latest Decision on an issue")
    decision.add_argument("--issue", type=int, required=True)

    relay = sub.add_parser("relay-decision", help="apply the human's decision on a needs-human finding")
    relay.add_argument("--issue", type=int, required=True)

    review_parser = sub.add_parser("review-pr", help="post the auditor's verdict on the report PR")
    review_parser.add_argument("--pr", type=int, required=True)
    review_parser.add_argument("--verdict", required=True, choices=["audited", "audit-rejected"])
    add_handoff_arguments(review_parser)

    secrets = sub.add_parser("check-secrets", help="scan a file (e.g. report.md) for credential patterns")
    secrets.add_argument("--file", required=True)

    close = sub.add_parser("close", help="close a resolved blocker or a finished finding (orchestrator)")
    close.add_argument("--issue", type=int, required=True)
    add_handoff_arguments(close)

    args = parser.parse_args()
    run_gh = setup_labels.live_run_gh
    repo = args.repo

    if args.command == "view":
        print(json.dumps(get_issue(args.issue, run_gh, repo), indent=2))
    elif args.command == "list":
        print(json.dumps(list_issues(args.label, run_gh, repo), indent=2))
    elif args.command == "create-finding":
        check_not_opened(args.output_dir, args.plugin_id)
        group = group_findings.load_groups(args.grouped, args.plugin_id)[0]
        number = create_finding_issue(group, run_gh, repo)
        save_issue_map(args.output_dir, args.plugin_id, number)
        print(json.dumps({"plugin_id": args.plugin_id, "issue": number}))
    elif args.command == "create-issue":
        number = create_issue(args.title, read_body(args), args.label, run_gh, repo)
        print(json.dumps({"issue": number}))
    elif args.command == "comment":
        print(comment(args.issue, read_body(args), run_gh, repo))
    elif args.command == "handoff":
        print(post_handoff(handoff_from_args(args, args.agent, args.issue, args.verdict), run_gh, repo))
    elif args.command == "claim":
        url = claim(args.issue, args.agent, run_gh, repo)
        print(json.dumps({"issue": args.issue, "claimed_by": args.agent, "comment": url}))
    elif args.command == "release":
        release(args.issue, args.agent, run_gh, repo)
        print(json.dumps({"issue": args.issue, "released_by": args.agent}))
    elif args.command == "transition":
        handoff = handoff_from_args(args, args.actor, args.issue, args.to_status)
        url = transition(args.issue, args.actor, args.from_status, args.to_status, handoff, run_gh, repo)
        print(json.dumps({"issue": args.issue, "status": args.to_status, "comment": url}))
    elif args.command == "set-stage":
        handoff = handoff_from_args(args, "orchestrator", args.issue, args.stage)
        url = set_stage(args.issue, args.stage, handoff, run_gh, repo)
        print(json.dumps({"issue": args.issue, "stage": args.stage, "comment": url}))
    elif args.command == "decision":
        print(json.dumps(latest_decision(args.issue, run_gh, repo), indent=2))
    elif args.command == "relay-decision":
        # Read the plugin ID before relaying, so a non-finding issue is refused
        # before any label changes. The file is written only after the board
        # change succeeded, so disk never claims a decision the board lacks.
        plugin_id = plugin_id_of(get_issue(args.issue, run_gh, repo))
        decision = relay_decision(args.issue, run_gh, repo)
        decision["triage_file"] = record_human_decision(args.output_dir, plugin_id, decision)
        print(json.dumps(decision, indent=2))
    elif args.command == "review-pr":
        handoff = handoff_from_args(args, "auditor", "PR #" + str(args.pr), args.verdict)
        print(json.dumps({"pr": args.pr, "verdict": args.verdict,
                          "review": review_pr(args.pr, handoff, run_gh, repo)}))
    elif args.command == "check-secrets":
        with open(args.file, "r", encoding="utf-8") as handle:
            found = find_secrets(handle.read())
        print(json.dumps({"file": args.file, "secrets_found": found}))
        if len(found) > 0:
            raise ValueError(args.file + " contains text that looks like a credential: " + ", ".join(found))
    elif args.command == "close":
        handoff = handoff_from_args(args, "orchestrator", args.issue, "closed")
        print(json.dumps({"issue": args.issue, "closed": True, "comment": close_issue(args.issue, handoff, run_gh, repo)}))


if __name__ == "__main__":
    main()
