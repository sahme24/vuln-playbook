# vuln-playbook

A multi-agent **vulnerability assessment playbook** that runs inside Claude
Code. Four subagents (recon-scanner, verifier, report-writer and auditor)
coordinate through **GitHub Issues** in a private engagement repo. A run ends
with an audited report as a pull request that you merge.

- Scope, approval, scan window and label rules are enforced **in code**, not
  only in prompts.
- Every verdict cites evidence (NVD, CISA KEV, EPSS, vendor trackers) and names
  the rule that produced it. When the evidence conflicts, *you* decide.
- Discovery and Nessus scanning only: no exploitation, brute forcing or DoS.
- Everything also runs in **dry-run mode** against bundled synthetic data, so
  you can demo it safely.

New here? Read **[GUIDE.md](GUIDE.md)** for how everything fits together.

---

## Requirements

| | Dry run | Live run |
|---|---|---|
| Python 3.11+ and `pip install -r requirements.txt` | ✔ | ✔ |
| [Claude Code](https://claude.com/claude-code) | ✔ | ✔ |
| [GitHub CLI](https://cli.github.com/) `gh`, logged in (`gh auth login`) | ✔ | ✔ |
| Nmap | | ✔ |
| Nessus with a saved scan policy | | ✔ |
| NVD API key in `.env` (optional, faster lookups) | | optional |

## Setup (once per engagement)

1. **Create a private engagement repo from this template.** The repo must be
   private: the playbook refuses to run in a public one.
   ```
   gh repo create my-engagement --private --template OWNER/vuln-playbook --clone
   cd my-engagement
   pip install -r requirements.txt
   ```
   (Or use **Use this template → Create a new repository → Private** on GitHub.)
2. *Optional:* `cp .env.example .env` and add your `NVD_API_KEY`.
3. Open Claude Code in the repo folder (`claude`).

---

## Dry-run demo (no scanning)

In a fresh private repo made from the template, paste **Prompt 2, dry-run
variant** (below). No packets are sent. Discovery and Nessus results come from
`tests/fixtures/`, and API lookups use recorded responses. The fixture
engagement file `tests/fixtures/engagement_test.yaml` is already approved, so
you skip the intake.

What happens:

1. The orchestrator creates 25 labels and a **kickoff issue** (`stage:recon`).
2. recon-scanner posts a host summary (4 live, 1 filtered, 1 unresponsive; one
   host found only by the second Nmap pass) and an import summary: **2 hosts
   rejected** (203.0.113.50 out of scope, 192.0.2.250 excluded) and **4
   informational plugins excluded**. It then opens **6 finding issues**.
3. Verifiers run in parallel and post verdicts with evidence:

   | Finding | Verdict | Rule |
   |---|---|---|
   | Log4Shell (KEV-listed) | `verified` | `kev_match` |
   | SWEET32 (high) and SWEET32 (medium) | `verified` | `direct_detection` |
   | OpenSSH version banner on Ubuntu | **`needs-human`** | `banner_only_backport` |
   | TLS 1.0 | `accepted-risk` | `accepted_risk_listed` |
   | SSH CBC ciphers | `appendix` | `low_severity_hardening` |

   Two verifiers will note that the Ubuntu lookup for CVE-2023-51385 and
   CVE-2008-5161 failed. That is expected: those canned responses are
   deliberately missing, so the demo also shows how a vendor outage is handled
   (see `tests/fixtures/api/README.md`). It doesn't change any verdict.

4. **The run pauses for you.** Open the `needs-human` issue and comment, for example:
   ```
   Decision: verified
   Reason: Banner shows package 1:8.9p1-3ubuntu0.1, older than the fixed 1:8.9p1-3ubuntu0.5.
   ```
   Then tell Claude Code to continue. The banner in the fixture really is older
   than the fixed package, so `verified` matches the evidence. (`Decision:
   false-positive` also works if you want to see the false-positive log; give
   your own `Reason:`.)
5. The report-writer opens a **report PR** with Log4Shell ranked first, and the
   auditor posts its checklist verdict on the PR.
6. **You merge the PR.** The orchestrator closes the issues and posts a run summary.

Want to see the pipeline without GitHub at all? [GUIDE.md section 4](GUIDE.md)
runs every script by hand against the fixtures.

---

## Prompt 1: Intake

Paste this into Claude Code in your engagement repo. It asks what the agents
need to know and writes `engagement.yaml`.

```
Run the intake for a new vulnerability assessment engagement in this repository. Follow these steps in order.

1. Pre-checks. Run `gh auth status` and `gh repo view --json visibility,nameWithOwner`. If gh is not logged in, stop and tell me to run `gh auth login`. If the visibility is not PRIVATE, stop and tell me the repo must be made private before any engagement data goes into it. If `python -c "import yaml, requests"` fails, run `pip install -r requirements.txt`.

2. Read engagement.example.yaml and playbook/rules-of-engagement.md.

3. Ask me the following questions ONE GROUP AT A TIME, and wait for my answers before moving to the next group. Never invent an answer. If I am unsure, keep the question open.
   A. Engagement and authorization: engagement name; client; who authorized the testing (name and role); the authorization reference (ticket, email subject or document ID). If there is no written authorization, stop the intake.
   B. Scope: the IP addresses or CIDR ranges in scope, and any to exclude. IPs and CIDRs only, no hostnames.
   C. Window: start and end date-time with a UTC offset (for example 2026-12-01T09:00:00-05:00), and the Nmap profile: "standard", or "quiet" for fragile networks.
   D. Nessus: the saved policy name, and whether the scan is credentialed. If credentialed, ask what kind of account is available. I will DESCRIBE it only; never ask me for, and never record, a password, key or token.
   E. Reporting: audience (technical, executive or both); framework (none, NIST 800-53, CIS, PCI DSS or ISO 27001); remediation SLA in days for critical, high and medium (default 15, 30, 90); and any formally accepted risks (plugin ID or CVE, who accepted it, reference, optional expiry date).

4. Write engagement.yaml with exactly the structure of engagement.example.yaml. Set approval.scope_approved to false and approval.approved_at to "".

5. Validate it: `python scripts/scope.py --engagement engagement.yaml --validate`. If it reports an error, explain it in plain words, ask me for the corrected answer, fix the file and validate again until it passes.

6. Show me a scope summary: authorization (who and reference), include, exclude, window (also converted to my local time), Nmap profile, Nessus policy, credentialed or not, audience, framework, SLAs and accepted risks.

7. Finish by telling me: "Review this scope. If it is correct, open engagement.yaml and set approval.scope_approved: true and approval.approved_at to the current date-time with UTC offset. Then paste Prompt 2." You must NOT set scope_approved or approved_at yourself, even if I ask you to in this chat. Only I edit that flag, directly in the file.
```

## Approve the scope

Open `engagement.yaml`, check every line of the scope summary against your
written authorization, then set:

```yaml
approval:
  scope_approved: true
  approved_at: "2026-12-01T08:30:00-05:00"   # now, with your UTC offset
```

No live scan can start without this. `scope.py` checks it in code.

## Prompt 2: Run

**Live run:**

```
Run this engagement in LIVE mode. Follow CLAUDE.md exactly: do every pre-run check (gh logged in, repo private, approval.scope_approved is true in engagement.yaml, current time inside the window), run scripts/setup_labels.py, open or resume the kickoff issue, and run the orchestration loop, dispatching recon-scanner, verifiers in parallel (one issue each), report-writer and auditor, until the auditor's verdict on the report PR is "audited". Stop and tell me clearly whenever the run needs me: launching Nessus, deciding needs-human findings, and merging the PR. Never change approval.scope_approved.
```

**Dry-run variant** (fixtures only, no scanning, no API calls):

```
Run this engagement in DRY-RUN mode. Follow CLAUDE.md exactly, using the dry-run column of its Modes table: ENGAGEMENT is tests/fixtures/engagement_test.yaml, every script that accepts --dry-run gets it, the Nessus step uses tests/fixtures/sample.nessus with no Nessus blocker, and the verifier does not fetch web pages. Do the pre-run checks (gh logged in, repo private, approval in the fixture file; skip the window check), run scripts/setup_labels.py, open the kickoff issue, and run the orchestration loop until the auditor's verdict on the report PR is "audited". When the run needs my decision on a needs-human finding, stop and tell me which issue and what is being decided.
```

## What you do during a live run

| When | You |
|---|---|
| A "Needs human: run the Nessus scan" issue appears | Run the named policy against `engagement/output/targets.txt`, export as `.nessus`, put the file in `engagement/inbox/`, and tell Claude Code it's there. |
| A finding gets `status:needs-human` | Read the verifier's notes on the issue and comment `Decision: <verified / false-positive / accepted-risk / appendix>` plus a `Reason:` line. |
| The auditor posts `audited` on the PR | Review and **merge** the PR. The merge is the release of the report. |
| Anything goes wrong | Every stop condition is in [playbook/rules-of-engagement.md](playbook/rules-of-engagement.md). The orchestrator stops and tells you. |

Only you write `Decision:` lines. `scripts/board.py` refuses to post one, and
every agent file forbids posting one by any other route. Be aware this is a
rule, not proof: agents use your `gh` login, so GitHub shows the same author
either way, and a raw `gh issue comment` would get past `board.py`. If you
want Claude's help deciding, ask it to *draft* the comment, then post it
yourself.

---

## Repository layout

| Path | What |
|---|---|
| `CLAUDE.md` | orchestrator rules (the main Claude Code session) |
| `.claude/agents/` | recon-scanner, verifier, report-writer, auditor |
| `playbook/` | rules of engagement, label state machine, handoff format, triage rules, report template, audit checklist |
| `scripts/` | Python CLIs: scope, Nmap discovery, Nessus parsing, enrichment, triage, the issue board |
| `tests/` | pytest suite and **synthetic** fixtures (documentation IP ranges only) |
| `engagement/inbox/` | where you drop the `.nessus` export (gitignored) |
| `engagement/output/` | every script's JSON output (gitignored, except `report.md`) |

## Development

```
pip install -r requirements.txt
ruff check .
pytest -v
```

CI (`.github/workflows/ci.yml`) runs both on every push and pull request.
The tests never touch the network or GitHub.

## Safety

- Use only with written authorization for every target in scope.
- The template holds synthetic data only. Real scan data belongs in the
  private engagement repo, and `.gitignore` keeps raw outputs, `.env` and
  `cache.db` out of git.
- Credentials never go in the repo, issues or report. `credential_notes`
  describes what exists, never the secret itself.
- Reports are produced by AI agents and checked by an automated audit. You
  review and merge them, so you remain responsible for what is delivered.
