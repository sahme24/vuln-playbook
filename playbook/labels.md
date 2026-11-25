# Label state machine

GitHub Issues in the engagement repo are the message board. Labels are how
agents know whose turn it is. Each agent only picks up issues that carry its
**trigger label**, so the label on an issue is the single source of truth for
"what happens next".

`scripts/setup_labels.py` creates every label listed here. `scripts/board.py`
is the only way agents change labels. It enforces the rules in the
"Invariants" section in code, not just in prompts.

---

## 1. Label catalogue

Colors are hex values without the `#`, which is the format `gh label create`
expects.

### Stage labels: on the kickoff issue only

Stage labels mark the phase the whole run is in. Only the kickoff issue carries
one, and it carries exactly one at a time. The orchestrator moves it.

| Label           | Color    | Meaning                                                     |
|-----------------|----------|-------------------------------------------------------------|
| `stage:recon`   | `1d76db` | Discovery and Nessus import in progress (recon-scanner)     |
| `stage:verify`  | `5319e7` | Finding issues exist and are being verified                 |
| `stage:report`  | `0e8a16` | No findings left to verify; the report is being built       |
| `stage:audit`   | `b60205` | The report PR is open and under audit                       |

### Status labels: on finding issues only

Every `type:finding` issue carries exactly one status label at all times.

| Label                   | Color    | Meaning                                                          | Applied by     |
|-------------------------|----------|------------------------------------------------------------------|----------------|
| `status:needs-verify`   | `fbca04` | New finding, waiting for a verifier                              | recon-scanner  |
| `status:verified`       | `0e8a16` | Confirmed real and in scope; goes in the report                  | verifier       |
| `status:false-positive` | `cccccc` | Not actually vulnerable; goes in the false-positive log          | verifier       |
| `status:accepted-risk`  | `c5def5` | Real, but the client has formally accepted the risk              | verifier       |
| `status:appendix`       | `bfd4f2` | Real but low value (hardening note); goes in the report appendix | verifier       |
| `status:needs-human`    | `d93f0b` | Evidence conflicts; a human must decide the verdict              | verifier       |
| `status:reported`       | `006b75` | Included in the report PR                                        | report-writer  |
| `status:audited`        | `0b5394` | Passed audit                                                     | auditor        |
| `status:audit-rejected` | `b60205` | Auditor found a problem; goes back to the owning agent           | auditor        |

### Type labels

| Label           | Color    | Meaning                                                           |
|-----------------|----------|-------------------------------------------------------------------|
| `type:finding`  | `e99695` | One grouped vulnerability (one Nessus plugin, list of hosts)      |
| `type:handoff`  | `c2e0c6` | Coordination issue: the kickoff issue and stage-change notes      |
| `type:blocker`  | `d93f0b` | Something only the human can do or decide                         |

### Human attention

| Label         | Color    | Meaning                                                              |
|---------------|----------|----------------------------------------------------------------------|
| `needs-human` | `d93f0b` | On `type:blocker` issues: the run is waiting for the human to act    |

There are two needs-human labels, and they mean different things:

- `status:needs-human` is a **verdict** on a finding issue. The verifier could
  not decide because the evidence conflicts.
- `needs-human` (no prefix) marks a **blocker** issue: "launch the Nessus scan",
  "two agents disagree, please decide", and so on.

The orchestrator treats both as "waiting on the human" and will not start the
final report while any are open.

### Claim labels

| Label                    | Color    | Meaning                                       |
|--------------------------|----------|-----------------------------------------------|
| `claimed:recon-scanner`  | `ededed` | A recon-scanner instance is working on this   |
| `claimed:verifier`       | `ededed` | A verifier instance is working on this        |
| `claimed:report-writer`  | `ededed` | The report-writer is working on this          |
| `claimed:auditor`        | `ededed` | The auditor is working on this                |

### Severity labels: on finding issues only

Set by recon-scanner from the Nessus risk factor when the issue is opened.
Informational (severity 0) plugins never get an issue, so there is no
`severity:info` label. They are filtered out before any issue is opened (see
section 3).

| Label               | Color    |
|---------------------|----------|
| `severity:critical` | `b60205` |
| `severity:high`     | `d93f0b` |
| `severity:medium`   | `fbca04` |
| `severity:low`      | `0e8a16` |

---

## 2. Finding status flow

```
                       (verifier adds claimed:verifier)
                                     |
  [opened] --> needs-verify ---------+---------> verified --> reported --> audited
                                     |
                                     +---------> false-positive   (terminal)
                                     +---------> accepted-risk    (terminal)
                                     +---------> appendix         (terminal)
                                     +---------> needs-human --(human decision)--> one of the
                                                                                   verdicts above

  any status --> audit-rejected --> back to the owning agent's trigger state
```

### Transition table

Only the listed actor may make each transition. `board.py` removes the old
status label and adds the new one in a **single** `gh issue edit` call, so an
issue is never left with zero or two status labels.

| From                     | To                                                   | Actor                              |
|--------------------------|------------------------------------------------------|------------------------------------|
| (new issue)              | `needs-verify`                                       | recon-scanner                      |
| `needs-verify`           | `verified`, `false-positive`, `accepted-risk`, `appendix`, `needs-human` | verifier (must hold `claimed:verifier`) |
| `needs-human`            | `verified`, `false-positive`, `accepted-risk`, `appendix` | orchestrator, relaying a human decision (section 4) |
| `verified`               | `reported`                                           | report-writer                      |
| `reported`               | `audited`                                            | auditor                            |
| any                      | `audit-rejected`                                     | auditor                            |
| `audit-rejected`         | the owner's trigger state (below)                    | orchestrator                       |

`false-positive`, `accepted-risk` and `appendix` are **terminal** for the
verifier. These issues still appear in the report (false-positive log,
accepted-risk list, appendix) and the auditor still checks them, but their
status label does not move to `reported` / `audited`. Replacing it would erase
the verdict.

### Where an audit-rejected issue goes back to

The auditor names the owning agent in the `Next owner` field of its handoff
block. The orchestrator then moves the issue:

| Owning agent    | Issue returns to        | Typical reason                                        |
|-----------------|-------------------------|-------------------------------------------------------|
| verifier        | `status:needs-verify`   | Verdict not supported by the evidence, rule misapplied |
| report-writer   | `status:verified`       | Report text wrong: severity, hosts, SLA date, wording |
| recon-scanner   | `status:needs-verify`   | Wrong affected-host list or plugin grouping; recon fixes the issue body first |

### Closing issues

Finding issues stay **open** until the report PR is merged. After the merge
the orchestrator closes every finding issue and every resolved blocker, and
posts the run summary on the kickoff issue.

---

## 3. Findings that never become issues

The board only holds work an agent or human must act on. Two kinds of Nessus
output are filtered out **before** any issue is opened. Each is still recorded,
so nothing disappears silently:

| What                                      | Filtered by                           | Recorded in                          |
|-------------------------------------------|---------------------------------------|--------------------------------------|
| Hosts outside scope (in the .nessus file) | `scope.py`, called from `parse_nessus.py` | `rejected_hosts` in the parsed findings JSON, and the recon host summary |
| Informational plugins (severity 0)        | the `exclude` rules in `triage-rules.yaml`, run by recon-scanner after grouping | `engagement/output/excluded.json`, with the rule that fired; counted in the report's methodology section |

---

## 4. Human decisions on `needs-human`

When an issue is waiting on the human (`status:needs-human` on a finding, or
`needs-human` on a blocker), the human answers by **commenting on the issue**
with a line in this form:

```
Decision: false-positive
Reason: Vendor advisory confirms the fix was backported in the installed package.
```

The orchestrator then applies the decision with `board.py`, posting a handoff
block (`Agent: orchestrator`, `Rule fired: human_decision`) whose evidence
links to the human's comment.

Agents post to GitHub through the same `gh` login as the human, so the comment
author cannot tell the two apart. Two layers keep decisions with the human:

1. **`board.py` refuses to post any comment that contains a line starting
   with `Decision:`.**
2. Every agent file and `CLAUDE.md` forbid posting a `Decision:` line by any
   other route (raw `gh issue comment`, the API, the web UI).

This is a rule, not proof. Because the login is shared, nothing in GitHub can
show who typed the line, and a raw `gh` call would get past layer 1. If the
human wants help, an agent may draft the comment text in chat, and the human
posts it.

When `relay-decision` applies the decision, it also writes a `human_decision`
block (verdict, reason, comment URL, author, time) into
`engagement/output/triage/<plugin_id>.json`. The verifier's own verdict and
rule stay in that file next to it, so the record shows both why a human was
asked and what they decided.

---

## 5. Invariants (enforced by `board.py`)

1. A finding issue has **exactly one** `status:*` label. Every transition
   removes the old one and adds the new one in the same call.
2. A transition is refused unless the issue's current status matches the
   expected "from" state the caller passes in. This stops two agents from
   acting on stale information.
3. An issue has **at most one** `claimed:*` label. Claiming an issue that
   already carries any `claimed:*` label is refused.
4. The verifier releases its claim (removes `claimed:verifier`) in the same
   call that applies its verdict.
5. The kickoff issue has **exactly one** `stage:*` label.
6. A finding issue has **exactly one** `severity:*` label.
7. No agent comment may contain a `Decision:` line (section 4).
8. Every state-changing comment carries a handoff block in the format defined
   in `playbook/handoff-format.md`.

Parallel verifiers: the orchestrator gives each verifier instance a different
issue number, so two instances are never sent to the same issue. The claim
label is the second line of defence. GitHub has no atomic "add this label only
if absent" operation, so the claim check is a guard, not a lock. The real
guarantee comes from the orchestrator never dispatching the same issue twice.
