# Audit checklist

The auditor works through every check below, in order, for every report PR.
Each check passes or fails. There is no "mostly passes". **One failing check
means the verdict is `audit-rejected`.** Record every result, with the
evidence you looked at, in your PR review.

"Owner on failure" is the agent the affected issue goes back to (the `Next
owner` in your handoff). The orchestrator then returns the issue to that
agent's trigger state (see `playbook/labels.md`).

Sources referred to below:
- **board**: the issues and their handoff comments (`scripts/board.py list` / `view`)
- **triage file**: `engagement/output/triage/<plugin>.json`
- **enrichment**: `engagement/output/enrichment/<plugin>/` (`kev.json`, `epss.json`, `nvd.json`, `vendor.json`)
- **groups**: `engagement/output/to_open.json`

---

## A. Traceability

| ID | Check | How | Owner on failure |
|---|---|---|---|
| A1 | Every finding in the report links an issue, and that issue is a `type:finding` with the same plugin ID. | Compare each `#N` in section 4, 5, 6 and Appendix A with `board.py view --issue N` (plugin marker). | report-writer |
| A2 | Every `status:reported`, `false-positive`, `accepted-risk` and `appendix` issue appears in the report exactly once, in the right section. | `board.py list` for each status and compare with the report. | report-writer |
| A3 | No `status:needs-verify` or `status:needs-human` issue, and no open `needs-human` blocker, remains. | `board.py list` for each label must be empty. | report-writer (report built too early) |
| A4 | Appendix D (traceability) matches the board for every row. | Row by row against the board. | report-writer |

## B. Evidence

| ID | Check | How | Owner on failure |
|---|---|---|---|
| B1 | Every evidence link in a finding appears in that issue's handoff comments or its triage file. | Compare links. | report-writer |
| B2 | Every verdict on the board names a rule, and the rule's conditions really match the facts in the triage file. | Read `triage-rules.yaml` and the `facts` block of each triage file. | verifier |
| B3 | Every human decision in section 3.2 links a `Decision:` comment that says the same verdict and has a `Reason:`. | Open each link. | report-writer (wrong text) / orchestrator (wrong relay; open a blocker) |
| B4 | Descriptions and remediation are consistent with the NVD / vendor / Nessus text. They don't add claims the sources don't make. | Compare with `nvd.json`, `vendor.json` and the group's `solution`. | report-writer |

## C. Severity and ordering

| ID | Check | How | Owner on failure |
|---|---|---|---|
| C1 | Severity, CVSS v3, VPR and EPSS for each finding match the source files exactly. | `to_open.json`, `nvd.json`, `epss.json`. | report-writer |
| C2 | KEV status ("Listed, added date" / "Not listed") matches `kev.json` for every CVE. | `kev.json`. | report-writer |
| C3 | Findings are ordered KEV first, then VPR (CVSS v3 when there's no VPR), then EPSS, highest first. | Re-sort the section 4 table yourself and compare. | report-writer |
| C4 | Every SLA due date = window end + `severity_sla` days for the finding's severity. | Calculate each one. | report-writer |

## D. Scope

| ID | Check | How | Owner on failure |
|---|---|---|---|
| D1 | Every host named anywhere in the report is in scope. | `python scripts/scope.py --engagement ENGAGEMENT --target <ip> ... --dry-run` with every host from the report. Any error fails. | recon-scanner |
| D2 | Every host in the rejected-hosts table appears in `rejected_hosts` of `findings.json`, and none of them appears in a finding. | Compare. | recon-scanner |
| D3 | The affected-host list of each finding matches the group's `affected` list. | `to_open.json`. | recon-scanner (grouping) / report-writer (copying) |

## E. False positives and accepted risks

| ID | Check | How | Owner on failure |
|---|---|---|---|
| E1 | Every false positive says who decided (rule or human decision link), and the reasoning holds up against the evidence. | Triage file / decision comment. | verifier |
| E2 | No KEV-listed CVE is a false positive unless a human decision says so. | `kev.json` for every false-positive issue. | verifier |
| E3 | Every accepted risk matches an entry in `accepted_risks` of the engagement file, names `accepted_by` and `reference`, and isn't expired on the report date. | Engagement file. | verifier |

## F. Confidentiality and honesty

| ID | Check | How | Owner on failure |
|---|---|---|---|
| F1 | No credentials, hashes, tokens, private keys or session cookies appear in the report. | `python scripts/board.py check-secrets --file <report>`, **and** read for anything the patterns miss. | report-writer |
| F2 | The report doesn't claim it was written or reviewed by a certified professional or a named person, and doesn't claim exploitation was performed. | Read. | report-writer |
| F3 | No `{{placeholder}}` or `<!-- instruction -->` text remains. In a dry run, the dry-run notice is present. In a live run, it's absent. | Search for `{{` and `<!--`. | report-writer |

## G. Executive summary

| ID | Check | How | Owner on failure |
|---|---|---|---|
| G1 | Every count in the summary table matches the board. | Count the issues per status and severity. | report-writer |
| G2 | The KEV statement and priority actions match section 4 (same findings, same order, same due dates). | Compare. | report-writer |
| G3 | The summary makes no claim that the findings section doesn't support. | Read side by side. | report-writer |

## H. Methodology

| ID | Check | How | Owner on failure |
|---|---|---|---|
| H1 | Counts in section 3.1 (results, findings, excluded informational plugins) match `findings.json`, `to_open.json` and `excluded.json`. | Compare. | report-writer |
| H2 | Section 3.3 states the scan type (credentialed or not) correctly from the engagement file. | Engagement file. | report-writer |

---

## Recording the result

In the PR review (`board.py review-pr`), list one evidence item per check:
`A1 pass`, `C3 FAIL: 4.2 (VPR 6.7) is ranked above 4.3 (KEV-listed)`. Failing
checks go first. The Notes field summarizes the verdict in one sentence.
