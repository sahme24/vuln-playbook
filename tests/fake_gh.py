"""A tiny stand-in for the GitHub CLI, shared by test_board.py and
test_setup_labels.py. It is a helper module, not a test file.

It keeps a fake board in plain module-level dicts and lists and understands
just the gh commands board.py and setup_labels.py send. run_gh() has the same
signature as setup_labels.live_run_gh, so the scripts cannot tell the
difference. Tests then check what ended up on the fake board.

Call reset() at the start of every test.
"""

import json

ISSUES = {}         # number -> {"title", "state", "labels": [...], "body", "comments": [...]}
CALLS = []          # every gh argument list, in order
STATE = {"next_number": 1, "visibility": "PRIVATE", "fail_next": False}
LABELS_CREATED = []
PR_REVIEWS = []     # (pr number, review kind flag, body)


def reset():
    ISSUES.clear()
    CALLS.clear()
    LABELS_CREATED.clear()
    PR_REVIEWS.clear()
    STATE["next_number"] = 1
    STATE["visibility"] = "PRIVATE"
    STATE["fail_next"] = False


def add_issue(title, labels, body):
    """Put an issue directly on the fake board (as if created earlier)."""
    number = STATE["next_number"]
    STATE["next_number"] = number + 1
    label_copy = []
    for label in labels:
        label_copy.append(label)
    ISSUES[number] = {"title": title, "state": "OPEN", "labels": label_copy, "body": body, "comments": []}
    return number


def add_human_comment(number, body):
    ISSUES[number]["comments"].append({
        "author": {"login": "the-human"}, "body": body, "createdAt": "2026-12-02T10:00:00Z",
        "url": "https://github.com/OWNER/REPO/issues/" + str(number) + "#issuecomment-" + str(len(CALLS) + 1),
    })


def ok(stdout):
    return {"returncode": 0, "stdout": stdout, "stderr": ""}


def flag_values(args, flag):
    """All values that follow `flag` in an argument list."""
    values = []
    position = 0
    while position < len(args):
        if args[position] == flag and position + 1 < len(args):
            values.append(args[position + 1])
        position = position + 1
    return values


def run_gh(args, stdin_text):
    CALLS.append(args)
    if STATE["fail_next"]:
        STATE["fail_next"] = False
        return {"returncode": 1, "stdout": "", "stderr": "simulated gh failure"}

    if args[0] == "repo" and args[1] == "view":
        return ok(json.dumps({"visibility": STATE["visibility"], "nameWithOwner": "OWNER/REPO"}))

    if args[0] == "pr" and args[1] == "review":
        PR_REVIEWS.append((int(args[2]), args[3], stdin_text))
        return ok("")

    if args[0] == "label" and args[1] == "create":
        LABELS_CREATED.append(args[2])
        return ok("")

    if args[0] == "issue" and args[1] == "create":
        number = add_issue(flag_values(args, "--title")[0], flag_values(args, "--label"), stdin_text)
        return ok("https://github.com/OWNER/REPO/issues/" + str(number) + "\n")

    if args[0] == "issue" and args[1] == "list":
        wanted = flag_values(args, "--label")[0]
        result = []
        for number in ISSUES:
            issue = ISSUES[number]
            if issue["state"] == "OPEN" and wanted in issue["labels"]:
                names = []
                for label in issue["labels"]:
                    names.append({"name": label})
                result.append({"number": number, "title": issue["title"], "labels": names})
        return ok(json.dumps(result))

    number = int(args[2])
    issue = ISSUES[number]

    if args[1] == "view":
        fields = flag_values(args, "--json")[0]
        if fields == "comments":
            return ok(json.dumps({"comments": issue["comments"]}))
        names = []
        for label in issue["labels"]:
            names.append({"name": label})
        return ok(json.dumps({"number": number, "title": issue["title"], "state": issue["state"],
                              "labels": names, "body": issue["body"]}))

    if args[1] == "edit":
        for label in flag_values(args, "--remove-label"):
            if label in issue["labels"]:
                issue["labels"].remove(label)
        for label in flag_values(args, "--add-label"):
            if label not in issue["labels"]:
                issue["labels"].append(label)
        return ok("https://github.com/OWNER/REPO/issues/" + str(number) + "\n")

    if args[1] == "comment":
        issue["comments"].append({"author": {"login": "agent-via-gh"}, "body": stdin_text,
                                  "createdAt": "2026-12-02T09:00:00Z", "url": None})
        return ok("https://github.com/OWNER/REPO/issues/" + str(number) + "#issuecomment-1\n")

    if args[1] == "close":
        issue["state"] = "CLOSED"
        return ok("")

    raise AssertionError("fake gh does not understand: " + " ".join(args))
