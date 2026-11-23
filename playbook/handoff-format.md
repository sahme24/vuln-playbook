# Handoff comment format

Every comment that changes the state of an issue (a label transition, a claim,
a stage change, an audit result) **must** contain this block, exactly as shown.
The fixed shape lets the orchestrator and the auditor parse the board with a
script instead of reading free text. It also means every state change can be
traced back to an agent, a rule and its evidence.

```
### Handoff
- Agent: verifier
- Issue: #42
- Verdict: verified
- Rule fired: kev_match
- Evidence:
  - https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX
  - KEV catalog entry, date added
- Confidence: high
- Next owner: report-writer
- Notes: one or two sentences
```

The block may be followed by free text (for example a longer explanation or a
host table), but nothing may come **before** the `### Handoff` heading. A
parser can then always find the block at the start of the comment.

---

## Field rules

The fields appear in exactly this order, one per line, each starting with
`- ` and a field name followed by `: `.

| Field        | Required value                                                                                     |
|--------------|----------------------------------------------------------------------------------------------------|
| `Agent`      | One of `orchestrator`, `recon-scanner`, `verifier`, `report-writer`, `auditor`.                    |
| `Issue`      | `#` followed by the issue number this comment is posted on (or `PR #N` for the auditor's review).   |
| `Verdict`    | The state the issue moves to. See "Allowed verdicts" below.                                        |
| `Rule fired` | The `name` of the rule in `playbook/triage-rules.yaml` that decided the verdict, or one of the fixed names below when no triage rule applies. |
| `Evidence`   | At least one item. Each item is on its own line, indented two spaces, starting with `- `. An item is a URL or a short factual description of where the evidence lives (file, plugin output line, catalog entry). |
| `Confidence` | Exactly one of `high`, `medium`, `low`.                                                            |
| `Next owner` | The agent whose trigger state the issue is now in, or `human`, or `none` for a terminal state.     |
| `Notes`      | One or two plain sentences. No credentials, ever.                                                  |

### Allowed verdicts

The verdict is written **without** the `status:` prefix, as in the example
above. Stage changes are written with the full `stage:` label so the two
cannot be confused.

| Agent          | Allowed verdicts                                                                             |
|----------------|----------------------------------------------------------------------------------------------|
| recon-scanner  | `claimed`, `needs-verify` (finding opened), `needs-human` (blocker opened, e.g. "launch Nessus") |
| verifier       | `claimed`, `verified`, `false-positive`, `accepted-risk`, `appendix`, `needs-human`           |
| report-writer  | `claimed`, `reported`                                                                        |
| auditor        | `claimed`, `audited`, `audit-rejected`                                                       |
| orchestrator   | `stage:recon`, `stage:verify`, `stage:report`, `stage:audit`; a relayed human decision (`verified`, `false-positive`, `accepted-risk`, `appendix`); `needs-verify` or `verified` when returning an `audit-rejected` issue to its owner; `needs-human` when it opens a blocker; `closed` when it closes a resolved blocker or, after the merge, a finding issue |

`claimed` is posted automatically by `board.py claim`. `scripts/board.py`
checks every handoff against this table before posting it.

### Fixed rule names (when no triage rule applies)

| Name                | Used when                                                           |
|---------------------|---------------------------------------------------------------------|
| `claim`             | An agent claims an issue before working on it (posted by `board.py claim`) |
| `verifier_conflict` | The verifier's own check (plugin page, vendor advisory) contradicts the triage verdict, so it sends the finding to the human instead |
| `nessus_import`     | recon-scanner opens a finding issue from a parsed `.nessus` file     |
| `human_action`      | recon-scanner or the orchestrator opens a blocker for the human      |
| `human_decision`    | The orchestrator relays a human `Decision:` comment                  |
| `stage_change`      | The orchestrator moves the kickoff issue to a new stage              |
| `report_included`   | report-writer marks a finding as included in the report PR           |
| `audit_checklist`   | The auditor approves or rejects (the failing check goes in `Notes`). On the PR itself this is posted with `board.py review-pr` as a review *comment*: GitHub does not allow an account to approve its own PR, and all agents share one gh login |
| `audit_return`      | The orchestrator returns an `audit-rejected` issue to its owner      |
| `blocker_resolved`  | The orchestrator closes a blocker once the human has acted           |
| `run_complete`      | The orchestrator closes finding issues after the report PR is merged |

---

## Examples

**recon-scanner opens a finding**

```
### Handoff
- Agent: recon-scanner
- Issue: #12
- Verdict: needs-verify
- Rule fired: nessus_import
- Evidence:
  - engagement/inbox/scan.nessus, plugin 156860
  - 3 affected hosts, all confirmed in scope by scope.py
- Confidence: high
- Next owner: verifier
- Notes: Grouped from 3 ReportItems with the same plugin ID.
```

**verifier sends a banner-only detection to the human**

```
### Handoff
- Agent: verifier
- Issue: #17
- Verdict: needs-human
- Rule fired: banner_only_backport
- Evidence:
  - https://www.tenable.com/plugins/nessus/XXXXX (detection is version-banner only)
  - https://ubuntu.com/security/CVE-XXXX-XXXX (fix status for the installed release)
- Confidence: low
- Next owner: human
- Notes: Ubuntu backports fixes without changing the upstream version string, so the banner alone cannot prove the host is vulnerable. A credentialed package check is needed.
```

**orchestrator relays a human decision**

```
### Handoff
- Agent: orchestrator
- Issue: #17
- Verdict: false-positive
- Rule fired: human_decision
- Evidence:
  - https://github.com/OWNER/REPO/issues/17#issuecomment-123456789
- Confidence: high
- Next owner: none
- Notes: Applied the human's decision as written; see the linked comment for the reason.
```

**auditor rejects a finding**

```
### Handoff
- Agent: auditor
- Issue: #12
- Verdict: audit-rejected
- Rule fired: audit_checklist
- Evidence:
  - PR #30, report.md section 4.2
  - Nessus CVSS v3 base score 7.5 vs. report 9.8
- Confidence: high
- Next owner: report-writer
- Notes: Failed check "severities match the sources". The report states a CVSS score that does not match the cited source.
```

---

## What never goes in a handoff

- Credentials, tokens, password hashes, private keys or session cookies, even
  if they appear in plugin output. Describe them instead ("plugin output
  contains a cleartext credential; redacted").
- A `Decision:` line. Only the human writes those (see `playbook/labels.md`,
  section 4). `board.py` refuses to post a comment that contains one.
- Guesses. If the evidence does not support a verdict, the verdict is
  `needs-human`.
