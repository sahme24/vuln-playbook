import json
import os
import tempfile

import pytest

import board
import fake_gh
import group_findings
import parse_nessus
import scope

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def make_handoff(agent, issue, verdict, next_owner):
    return {
        "agent": agent, "issue": issue, "verdict": verdict, "rule": "kev_match",
        "evidence": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "confidence": "high", "next_owner": next_owner, "notes": "Test note.",
    }


def finding_on_board(status, extra_labels):
    """Put a finding issue with the given status on the fake board."""
    labels = ["type:finding", "status:" + status, "severity:critical"]
    for label in extra_labels:
        labels.append(label)
    return fake_gh.add_issue("[900104] Log4Shell", labels, "<!-- vuln-playbook: plugin_id=900104 -->\nbody")


def fixture_group(plugin_id):
    engagement = scope.load_engagement(os.path.join(FIXTURES, "engagement_test.yaml"))
    parsed = parse_nessus.parse_nessus_file(os.path.join(FIXTURES, "sample.nessus"), scope.build_scope(engagement))
    for group in group_findings.group_findings(parsed["findings"]):
        if group["plugin_id"] == plugin_id:
            return group
    raise AssertionError("no group " + str(plugin_id))


def status_labels(number):
    return board.labels_with_prefix(fake_gh.ISSUES[number]["labels"], "status:")


# --- handoff blocks ----------------------------------------------------------------

def test_render_then_parse_round_trip():
    # The orchestrator and auditor parse what agents post. Whatever is
    # rendered must parse back to the same data, or the board can't be read.
    handoff = make_handoff("verifier", 42, "verified", "report-writer")
    handoff["evidence"].append("KEV catalog entry, date added 2021-12-10")
    text = board.render_handoff(handoff)
    assert text.startswith("### Handoff\n- Agent: verifier\n- Issue: #42\n")
    assert board.parse_handoff(text) == handoff


def test_parse_ignores_free_text_after_block():
    # Agents may add an explanation below the block. The parser must stop at
    # the end of the block, not choke on the extra text.
    text = board.render_handoff(make_handoff("verifier", 42, "verified", "report-writer"))
    parsed = board.parse_handoff(text + "\nLonger explanation here.\n- not a field\n")
    assert parsed["verdict"] == "verified"


def test_parse_pr_reference():
    # The auditor's handoff refers to a PR, not an issue number.
    handoff = make_handoff("auditor", "PR #30", "audit-rejected", "report-writer")
    assert board.parse_handoff(board.render_handoff(handoff))["issue"] == "PR #30"


def test_parse_rejects_text_without_block():
    # A comment that does not start with the block is not a handoff. Treating
    # it as one would invent state changes.
    with pytest.raises(ValueError):
        board.parse_handoff("Just a normal comment.")
    with pytest.raises(ValueError):
        board.parse_handoff("### Handoff\n- Agent: verifier\n")


def test_handoff_validation_rules():
    # Each field is restricted (handoff-format.md). A wrong agent/verdict
    # pair, missing evidence or a multi-line note would break parsing or
    # traceability.
    bad = make_handoff("report-writer", 42, "verified", "auditor")
    with pytest.raises(ValueError, match="not allowed"):
        board.validate_handoff(bad)
    bad = make_handoff("verifier", 42, "verified", "report-writer")
    bad["evidence"] = []
    with pytest.raises(ValueError, match="evidence"):
        board.validate_handoff(bad)
    bad = make_handoff("verifier", 42, "verified", "report-writer")
    bad["notes"] = "two\nlines"
    with pytest.raises(ValueError):
        board.validate_handoff(bad)
    bad = make_handoff("verifier", 0, "verified", "report-writer")
    with pytest.raises(ValueError):
        board.validate_handoff(bad)


# --- posting safety -------------------------------------------------------------

def test_decision_line_is_refused():
    # Only the human may write "Decision:". Agents post through the same gh
    # login, so this ban is the only thing that makes a decision trustworthy.
    fake_gh.reset()
    number = finding_on_board("needs-human", [])
    with pytest.raises(ValueError, match="Decision"):
        board.comment(number, "I think so.\nDecision: false-positive\n", fake_gh.run_gh, None)
    assert fake_gh.ISSUES[number]["comments"] == []


def test_credentials_are_refused():
    # Credentials must never land in issues. Plugin output sometimes holds
    # them, so posting is blocked until they are redacted.
    fake_gh.reset()
    number = finding_on_board("needs-verify", [])
    with pytest.raises(ValueError, match="credential"):
        board.comment(number, "Found config: password = hunter2", fake_gh.run_gh, None)
    with pytest.raises(ValueError):
        board.comment(number, "-----BEGIN RSA PRIVATE KEY-----", fake_gh.run_gh, None)


def test_normal_security_text_is_not_flagged():
    # The secret check must not block ordinary findings text, or agents could
    # not describe SSH settings at all.
    assert board.find_secrets("PasswordAuthentication yes is enabled on the SSH server") == []
    assert board.find_secrets("Token-based authentication is recommended.") == []


# --- claims ----------------------------------------------------------------------------

def test_claim_adds_label_and_posts_handoff():
    # A claim is a state change, so it gets a label AND a handoff block.
    fake_gh.reset()
    number = finding_on_board("needs-verify", [])
    board.claim(number, "verifier", fake_gh.run_gh, None)
    assert "claimed:verifier" in fake_gh.ISSUES[number]["labels"]
    parsed = board.parse_handoff(fake_gh.ISSUES[number]["comments"][0]["body"])
    assert parsed["verdict"] == "claimed"
    assert parsed["rule"] == "claim"


def test_second_claim_is_refused():
    # Two verifiers on one finding would post two verdicts. The second claim
    # must fail and leave the first one untouched.
    fake_gh.reset()
    number = finding_on_board("needs-verify", ["claimed:verifier"])
    with pytest.raises(ValueError, match="already claimed"):
        board.claim(number, "verifier", fake_gh.run_gh, None)
    with pytest.raises(ValueError):
        board.claim(number, "report-writer", fake_gh.run_gh, None)


def test_release_only_by_holder():
    # Releasing someone else's claim would let two agents work on one issue.
    fake_gh.reset()
    number = finding_on_board("needs-verify", ["claimed:verifier"])
    with pytest.raises(ValueError):
        board.release(number, "auditor", fake_gh.run_gh, None)
    board.release(number, "verifier", fake_gh.run_gh, None)
    assert "claimed:verifier" not in fake_gh.ISSUES[number]["labels"]


def test_orchestrator_cannot_claim():
    # The orchestrator dispatches work but never does it itself.
    fake_gh.reset()
    number = finding_on_board("needs-verify", [])
    with pytest.raises(ValueError):
        board.claim(number, "orchestrator", fake_gh.run_gh, None)


# --- transitions ---------------------------------------------------------------------

def test_verifier_verdict_swaps_status_in_one_call_and_releases_claim():
    # Invariant: exactly one status label at all times. The old label goes and
    # the new one arrives in the same gh call, together with the claim release.
    fake_gh.reset()
    number = finding_on_board("needs-verify", ["claimed:verifier"])
    handoff = make_handoff("verifier", number, "verified", "report-writer")
    board.transition(number, "verifier", "needs-verify", "verified", handoff, fake_gh.run_gh, None)
    assert status_labels(number) == ["status:verified"]
    assert "claimed:verifier" not in fake_gh.ISSUES[number]["labels"]
    edit_calls = []
    for call in fake_gh.CALLS:
        if call[1] == "edit":
            edit_calls.append(call)
    assert len(edit_calls) == 1
    assert "--add-label" in edit_calls[0]
    assert "--remove-label" in edit_calls[0]
    assert board.parse_handoff(fake_gh.ISSUES[number]["comments"][0]["body"])["verdict"] == "verified"


def test_verdict_without_claim_is_refused():
    # A verdict from an agent that never claimed the issue might collide with
    # a verifier that did.
    fake_gh.reset()
    number = finding_on_board("needs-verify", [])
    handoff = make_handoff("verifier", number, "verified", "report-writer")
    with pytest.raises(ValueError, match="claim"):
        board.transition(number, "verifier", "needs-verify", "verified", handoff, fake_gh.run_gh, None)
    assert status_labels(number) == ["status:needs-verify"]


def test_stale_from_status_is_refused():
    # If someone already moved the issue, acting on the old status would
    # overwrite their verdict. The expected "from" must match reality.
    fake_gh.reset()
    number = finding_on_board("verified", [])
    handoff = make_handoff("report-writer", number, "reported", "auditor")
    board.transition(number, "report-writer", "verified", "reported", handoff, fake_gh.run_gh, None)
    with pytest.raises(ValueError, match="re-read the board"):
        board.transition(number, "report-writer", "verified", "reported", handoff, fake_gh.run_gh, None)


def test_actor_not_allowed_for_transition():
    # Only the verifier gives verdicts and only the auditor audits. The table
    # in labels.md is enforced, not just documented.
    fake_gh.reset()
    number = finding_on_board("needs-verify", [])
    handoff = make_handoff("report-writer", number, "reported", "auditor")
    with pytest.raises(ValueError, match="may not move"):
        board.transition(number, "report-writer", "needs-verify", "reported", handoff, fake_gh.run_gh, None)
    with pytest.raises(ValueError):
        board.check_transition_allowed("verifier", "verified", "audited")


def test_auditor_can_reject_from_any_status():
    # "any -> audit-rejected": the auditor can send back even a
    # false-positive whose reasoning does not hold up.
    fake_gh.reset()
    number = finding_on_board("false-positive", [])
    handoff = make_handoff("auditor", number, "audit-rejected", "verifier")
    board.transition(number, "auditor", "false-positive", "audit-rejected", handoff, fake_gh.run_gh, None)
    assert status_labels(number) == ["status:audit-rejected"]


def test_issue_with_two_status_labels_is_refused():
    # A corrupted issue (two statuses) cannot be moved safely. Stop and let a
    # human fix it.
    fake_gh.reset()
    number = finding_on_board("verified", ["status:reported"])
    handoff = make_handoff("report-writer", number, "reported", "auditor")
    with pytest.raises(ValueError, match="exactly one status"):
        board.transition(number, "report-writer", "verified", "reported", handoff, fake_gh.run_gh, None)


def test_refused_handoff_text_leaves_labels_unchanged():
    # If the handoff cannot be posted (it contains a secret), the label must
    # not move either. A state change without its handoff breaks traceability.
    fake_gh.reset()
    number = finding_on_board("needs-verify", ["claimed:verifier"])
    handoff = make_handoff("verifier", number, "verified", "report-writer")
    handoff["notes"] = "Config shows password: hunter2"
    with pytest.raises(ValueError):
        board.transition(number, "verifier", "needs-verify", "verified", handoff, fake_gh.run_gh, None)
    assert status_labels(number) == ["status:needs-verify"]


def test_handoff_must_match_actor_and_issue():
    # A handoff signed by another agent, or for another issue, would put
    # false information on the board.
    fake_gh.reset()
    number = finding_on_board("needs-verify", ["claimed:verifier"])
    handoff = make_handoff("verifier", number + 1, "verified", "report-writer")
    with pytest.raises(ValueError):
        board.transition(number, "verifier", "needs-verify", "verified", handoff, fake_gh.run_gh, None)


# --- stages ------------------------------------------------------------------------------

def test_set_stage_swaps_single_stage_label():
    # The kickoff issue shows the run's phase. It must carry exactly one stage.
    fake_gh.reset()
    number = fake_gh.add_issue("Run kickoff", ["type:handoff", "stage:recon"], "kickoff")
    handoff = make_handoff("orchestrator", number, "stage:verify", "verifier")
    handoff["rule"] = "stage_change"
    board.set_stage(number, "stage:verify", handoff, fake_gh.run_gh, None)
    assert board.labels_with_prefix(fake_gh.ISSUES[number]["labels"], "stage:") == ["stage:verify"]


def test_set_stage_refuses_same_or_unknown_stage():
    # Re-entering the same stage or an unknown one is a logic error in the
    # orchestration loop, so it must be surfaced.
    fake_gh.reset()
    number = fake_gh.add_issue("Run kickoff", ["type:handoff", "stage:recon"], "kickoff")
    handoff = make_handoff("orchestrator", number, "stage:recon", "recon-scanner")
    with pytest.raises(ValueError, match="already"):
        board.set_stage(number, "stage:recon", handoff, fake_gh.run_gh, None)
    with pytest.raises(ValueError):
        board.set_stage(number, "stage:party", handoff, fake_gh.run_gh, None)


# --- human decisions ------------------------------------------------------------

def test_parse_decision():
    # The human answers with "Decision:" and "Reason:" lines. Ordinary
    # comments must give None, not a decision.
    parsed = board.parse_decision("Checked the server.\nDecision: False-Positive\nReason: patched build installed.")
    assert parsed == {"decision": "false-positive", "reason": "patched build installed."}
    assert board.parse_decision("Looking into it") is None


def test_relay_decision_applies_and_links_comment():
    # The orchestrator applies exactly what the human decided and links the
    # comment as evidence, so the auditor can trace the verdict to a person.
    fake_gh.reset()
    number = finding_on_board("needs-human", [])
    fake_gh.add_human_comment(number, "Decision: false-positive\nReason: Fixed package 3ubuntu0.5 is installed.")
    applied = board.relay_decision(number, fake_gh.run_gh, None)
    assert applied["decision"] == "false-positive"
    assert status_labels(number) == ["status:false-positive"]
    handoff = board.parse_handoff(fake_gh.ISSUES[number]["comments"][-1]["body"])
    assert handoff["rule"] == "human_decision"
    assert handoff["evidence"][0].startswith("https://github.com/OWNER/REPO/issues/")


def test_relay_without_decision_or_reason_is_refused():
    # No decision yet means keep waiting. A decision without a reason is not
    # auditable, so the human is asked for one.
    fake_gh.reset()
    number = finding_on_board("needs-human", [])
    with pytest.raises(ValueError, match="no 'Decision:'"):
        board.relay_decision(number, fake_gh.run_gh, None)
    fake_gh.add_human_comment(number, "Decision: verified")
    with pytest.raises(ValueError, match="Reason"):
        board.relay_decision(number, fake_gh.run_gh, None)
    assert status_labels(number) == ["status:needs-human"]


def test_relay_invalid_decision_is_refused():
    # "Decision: maybe" is not a verdict. Applying it would break the state machine.
    fake_gh.reset()
    number = finding_on_board("needs-human", [])
    fake_gh.add_human_comment(number, "Decision: maybe\nReason: not sure")
    with pytest.raises(ValueError, match="not one of"):
        board.relay_decision(number, fake_gh.run_gh, None)


def test_latest_decision_wins():
    # If the human changes their mind, the most recent decision is the one applied.
    fake_gh.reset()
    number = finding_on_board("needs-human", [])
    fake_gh.add_human_comment(number, "Decision: false-positive\nReason: first look")
    fake_gh.add_human_comment(number, "Decision: verified\nReason: second look, still vulnerable")
    assert board.latest_decision(number, fake_gh.run_gh, None)["decision"] == "verified"


# --- writing the human decision back to the triage file ------------------------------

def write_triage_file(folder, plugin_id, verdict):
    """Create engagement/output/triage/<plugin_id>.json the way triage.py
    would, with just the fields record_human_decision looks at."""
    triage_folder = os.path.join(folder, "triage")
    os.makedirs(triage_folder, exist_ok=True)
    path = os.path.join(triage_folder, str(plugin_id) + ".json")
    data = {"plugin_id": plugin_id, "verdict": verdict, "rule": "banner_only_backport"}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return path


def read_json_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


DECISION = {"decision": "verified", "reason": "banner revision older than the fix",
            "url": "https://github.com/OWNER/REPO/issues/4#issuecomment-1",
            "author": "operator", "created_at": "2026-11-24T10:00:00Z"}


def test_record_human_decision_keeps_verifier_verdict():
    # The dry run left triage/900101.json saying "needs-human" after the human
    # had decided, so the file on disk contradicted the board. The decision
    # must be added, but the verifier's verdict and rule must survive next to
    # it, or the history of why a human was asked is lost.
    with tempfile.TemporaryDirectory() as folder:
        path = write_triage_file(folder, 900101, "needs-human")
        returned = board.record_human_decision(folder, 900101, DECISION)
        data = read_json_file(path)
        assert returned == path
        assert data["verdict"] == "needs-human"
        assert data["rule"] == "banner_only_backport"
        assert data["human_decision"]["verdict"] == "verified"
        assert data["human_decision"]["reason"] == "banner revision older than the fix"
        assert data["human_decision"]["url"] == DECISION["url"]
        assert data["human_decision"]["author"] == "operator"


def test_record_same_decision_twice_is_harmless():
    # If the command is re-run after a crash, writing the same decision again
    # must not fail, otherwise the operator gets stuck on a harmless retry.
    with tempfile.TemporaryDirectory() as folder:
        path = write_triage_file(folder, 900101, "needs-human")
        board.record_human_decision(folder, 900101, DECISION)
        board.record_human_decision(folder, 900101, DECISION)
        assert read_json_file(path)["human_decision"]["url"] == DECISION["url"]


def test_record_different_decision_is_refused():
    # A second, different decision would silently overwrite the first one and
    # erase the record of what the human originally decided.
    with tempfile.TemporaryDirectory() as folder:
        path = write_triage_file(folder, 900101, "needs-human")
        board.record_human_decision(folder, 900101, DECISION)
        other = dict(DECISION)
        other["url"] = "https://github.com/OWNER/REPO/issues/4#issuecomment-2"
        other["decision"] = "false-positive"
        with pytest.raises(ValueError, match="already records a different"):
            board.record_human_decision(folder, 900101, other)
        assert read_json_file(path)["human_decision"]["verdict"] == "verified"


def test_record_on_finding_not_sent_to_human_is_refused():
    # Only "needs-human" findings can carry a human decision. A decision on a
    # file that says "verified" means the wrong plugin or issue was used, and
    # writing it would attach a person's verdict to an unrelated finding.
    with tempfile.TemporaryDirectory() as folder:
        write_triage_file(folder, 900104, "verified")
        with pytest.raises(ValueError, match="not 'needs-human'"):
            board.record_human_decision(folder, 900104, DECISION)


def test_record_without_triage_file_is_refused():
    # A missing file must be reported loudly: the board has already changed,
    # so the operator needs to know the disk record could not be updated.
    with tempfile.TemporaryDirectory() as folder:
        with pytest.raises(ValueError, match="no triage file"):
            board.record_human_decision(folder, 900101, DECISION)


def test_record_rejects_bad_plugin_id_and_decision():
    # A zero, negative or text plugin ID would build a nonsense file path,
    # and a decision without its comment URL could not be traced to a person.
    with tempfile.TemporaryDirectory() as folder:
        write_triage_file(folder, 900101, "needs-human")
        with pytest.raises(ValueError, match="positive integer"):
            board.record_human_decision(folder, 0, DECISION)
        with pytest.raises(ValueError, match="positive integer"):
            board.record_human_decision(folder, -5, DECISION)
        with pytest.raises(ValueError, match="positive integer"):
            board.record_human_decision(folder, "900101", DECISION)
        with pytest.raises(ValueError, match="dict"):
            board.record_human_decision(folder, 900101, "verified")
        missing_url = {"decision": "verified", "reason": "x"}
        with pytest.raises(ValueError, match="missing 'url'"):
            board.record_human_decision(folder, 900101, missing_url)


# --- creating and closing issues -----------------------------------------------------

def test_create_finding_issue_from_fixture_group():
    # recon-scanner opens one issue per finding with the right labels, a
    # plugin marker the verifier can read back, and its handoff block.
    fake_gh.reset()
    number = board.create_finding_issue(fixture_group(900104), fake_gh.run_gh, None)
    issue = fake_gh.ISSUES[number]
    assert issue["labels"] == ["type:finding", "status:needs-verify", "severity:critical"]
    assert issue["title"] == "[900104] Apache Log4j Remote Code Execution (Log4Shell) (critical, 2 hosts)"
    assert board.plugin_id_of(board.get_issue(number, fake_gh.run_gh, None)) == 900104
    assert "192.0.2.20" in issue["body"]
    assert board.parse_handoff(issue["comments"][0]["body"])["rule"] == "nessus_import"


def test_issue_body_is_sent_on_stdin():
    # Long bodies go through stdin (--body-file -), because Windows caps a
    # command line at about 32,000 characters.
    fake_gh.reset()
    board.create_finding_issue(fixture_group(900102), fake_gh.run_gh, None)
    create_call = fake_gh.CALLS[0]
    assert "--body-file" in create_call
    assert "--body" not in create_call


def test_plugin_output_is_truncated():
    # Plugin output can be huge. Issues show a capped sample, and the rest
    # stays in findings.json on the operator's machine.
    group = fixture_group(900104)
    long_output = ""
    for number in range(50):
        long_output = long_output + "line " + str(number) + "\n"
    group["affected"][0]["plugin_output"] = long_output
    body = board.finding_body(group)
    assert "line 19" in body
    assert "line 20\n" not in body
    assert "30 more lines" in body


def test_informational_group_cannot_become_issue():
    # Severity 0 is excluded by triage. Opening an issue anyway would bypass
    # that rule.
    fake_gh.reset()
    with pytest.raises(ValueError):
        board.create_finding_issue(fixture_group(19506), fake_gh.run_gh, None)


def test_create_issue_rejects_unknown_label():
    # A misspelled label would silently create a new, meaningless label in
    # GitHub. Only catalogue labels are accepted.
    fake_gh.reset()
    with pytest.raises(ValueError, match="unknown label"):
        board.create_issue("Title", "body", ["status:verifed"], fake_gh.run_gh, None)


def test_close_blocker_removes_needs_human():
    # A resolved blocker must stop counting as "waiting on the human", and
    # it is closed with a handoff that says so.
    fake_gh.reset()
    number = fake_gh.add_issue("Needs human: launch Nessus", ["type:blocker", "needs-human"], "Please run it.")
    handoff = make_handoff("orchestrator", number, "closed", "recon-scanner")
    handoff["rule"] = "blocker_resolved"
    board.close_issue(number, handoff, fake_gh.run_gh, None)
    assert fake_gh.ISSUES[number]["state"] == "CLOSED"
    assert "needs-human" not in fake_gh.ISSUES[number]["labels"]


def test_list_issues_by_label():
    # The orchestration loop finds work by listing issues in each trigger state.
    fake_gh.reset()
    first = finding_on_board("needs-verify", [])
    finding_on_board("verified", [])
    found = board.list_issues("status:needs-verify", fake_gh.run_gh, None)
    assert len(found) == 1
    assert found[0]["number"] == first
    with pytest.raises(ValueError):
        board.list_issues("status:nonsense", fake_gh.run_gh, None)


def test_gh_failure_surfaces():
    # A gh failure (network, auth) must raise, never pass as success.
    fake_gh.reset()
    number = finding_on_board("needs-verify", [])
    fake_gh.STATE["fail_next"] = True
    with pytest.raises(RuntimeError):
        board.get_issue(number, fake_gh.run_gh, None)


# --- report PR review -------------------------------------------------------------

def test_review_pr_posts_comment_review_with_handoff():
    # GitHub refuses approve/request-changes on your own PR, and the auditor
    # shares the gh login with the report-writer, so the verdict must go out
    # as a review comment that carries the handoff block.
    fake_gh.reset()
    handoff = make_handoff("auditor", "PR #30", "audited", "human")
    handoff["rule"] = "audit_checklist"
    board.review_pr(30, handoff, fake_gh.run_gh, None)
    assert len(fake_gh.PR_REVIEWS) == 1
    pr_number, kind, body = fake_gh.PR_REVIEWS[0]
    assert pr_number == 30
    assert kind == "--comment"
    assert board.parse_handoff(body)["verdict"] == "audited"


def test_review_pr_refuses_wrong_agent_pr_or_verdict():
    # Only the auditor reviews, the handoff must name the same PR, and only
    # audited/audit-rejected are verdicts on a PR. Anything else would put a
    # misleading review on the deliverable.
    fake_gh.reset()
    with pytest.raises(ValueError):
        board.review_pr(30, make_handoff("report-writer", "PR #30", "reported", "auditor"), fake_gh.run_gh, None)
    with pytest.raises(ValueError):
        board.review_pr(30, make_handoff("auditor", "PR #31", "audited", "human"), fake_gh.run_gh, None)
    with pytest.raises(ValueError):
        board.review_pr(30, make_handoff("auditor", "PR #30", "claimed", "auditor"), fake_gh.run_gh, None)
    assert fake_gh.PR_REVIEWS == []


def test_review_pr_applies_posting_safety():
    # The PR review is posted text like any comment, so the credential ban
    # applies there too.
    fake_gh.reset()
    handoff = make_handoff("auditor", "PR #30", "audit-rejected", "report-writer")
    handoff["notes"] = "Report section 4 leaks password: hunter2"
    with pytest.raises(ValueError, match="credential"):
        board.review_pr(30, handoff, fake_gh.run_gh, None)
    assert fake_gh.PR_REVIEWS == []


# --- issue map ------------------------------------------------------------------------

def test_issue_map_records_and_blocks_duplicates():
    # If recon-scanner is re-run after a crash, plugins that already have an
    # issue must be refused, or the board fills up with duplicate findings.
    with tempfile.TemporaryDirectory() as folder:
        assert board.load_issue_map(folder) == {}
        assert board.check_not_opened(folder, 900104) is True
        board.save_issue_map(folder, 900104, 7)
        board.save_issue_map(folder, 900102, 8)
        assert board.load_issue_map(folder) == {"900104": 7, "900102": 8}
        with pytest.raises(ValueError, match="already has issue #7"):
            board.check_not_opened(folder, 900104)
