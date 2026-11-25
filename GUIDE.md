# vuln-playbook: a plain-language guide

This guide explains how the whole repository fits together, what every file
is for, and how to run each piece yourself. The [README](README.md) is the
short "get started" page with the two prompts you paste into Claude Code. This guide is the "how does it all work" page.

> **Build status:** steps 1–7 are built: everything except the final
> end-to-end dry run in a real GitHub repo (step 8). This guide is updated at
> every checkpoint.

---

## 1. What this is, in one paragraph

vuln-playbook runs a **vulnerability assessment** with a team of AI agents
inside Claude Code. One agent discovers hosts, one checks every finding
against outside sources, one writes the report, and one audits it. They don't
talk to each other directly. They coordinate through **GitHub Issues**, the
way a human team would use a ticket board. Every important rule (stay in
scope, stay in the time window, wait for your approval, never dismiss an
actively exploited CVE without a human) is enforced **in Python code**, not
just in instructions to the AI.

---

## 2. The big picture

### Two repositories

| Repo | Visibility | What's in it |
|---|---|---|
| **vuln-playbook** (this one) | public template | the playbook: rules, agent definitions, scripts, *synthetic* test data, docs. **Never real scan data.** |
| **your engagement repo** | **private** | created from the template once per engagement. Holds `engagement.yaml`, the Issues board, and the final report. |

### The flow of one engagement

```
 YOU                          AGENTS (Claude Code)                    GITHUB ISSUES
 ───                          ────────────────────                    ─────────────
 Prompt 1: Intake  ─────────▶ asks questions, writes engagement.yaml
 review scope, set
 scope_approved: true
 Prompt 2: Run     ─────────▶ orchestrator ──▶ kickoff issue  ──────▶ [stage:recon]
                              recon-scanner:
                                Nmap pass 1 + pass 2 ─▶ targets.txt
                                "please run Nessus"  ───────────────▶ [needs-human] blocker
 run Nessus, drop the
 .nessus export in
 engagement/inbox/  ────────▶ recon-scanner:
                                parse ─▶ group ─▶ recon triage
                                one issue per finding ──────────────▶ [status:needs-verify] x N
                              verifier (several in parallel):
                                enrich (NVD, KEV, EPSS, vendor)
                                verify triage ─▶ verdict ───────────▶ [status:verified] ...
                                                                      [status:needs-human] ...
 answer needs-human
 issues with a
 "Decision:" comment ───────▶ orchestrator relays your decision
                              report-writer ─▶ report PR ───────────▶ [status:reported]
                              auditor ─▶ PR review ─────────────────▶ [status:audited]
                              orchestrator ─▶ run summary on kickoff issue
```

---

## 3. Folder map

```
vuln-playbook/
├── GUIDE.md                     ← you are here
├── README.md                    setup, Prompt 1 (intake), Prompt 2 (run / dry run), dry-run demo
├── CLAUDE.md                    rules for the orchestrator (the main Claude Code session)
├── .claude/agents/              the four subagents: recon-scanner, verifier, report-writer, auditor
├── .github/ISSUE_TEMPLATE/      issue forms: finding, handoff (kickoff), blocker
├── .github/workflows/ci.yml     runs ruff + pytest on every push and pull request
├── playbook/
│   ├── labels.md                label state machine: who may move an issue where
│   ├── handoff-format.md        the exact comment block agents post on every state change
│   ├── triage-rules.yaml        the ordered rules that decide every verdict
│   ├── rules-of-engagement.md   what is allowed, stop conditions, data handling (read before every engagement)
│   ├── report-template.md       the skeleton the report-writer fills in
│   └── audit-checklist.md       the 26 numbered checks (A1–H2) the auditor runs on the report
├── scripts/                     all the Python (each one is also a command-line tool)
├── engagement/
│   ├── inbox/                   you drop the Nessus .nessus export here (gitignored)
│   └── output/                  every script writes its JSON here (gitignored, except report.md)
├── tests/
│   ├── fixtures/                SYNTHETIC scan data + canned API responses for the dry run
│   ├── fake_gh.py               a pretend GitHub used by the board tests (not a test file)
│   └── test_*.py                one test file per script
├── engagement.example.yaml      what an engagement file looks like
├── .env.example                 copy to .env and add your NVD API key (optional)
├── pyproject.toml               pytest + ruff settings
└── requirements.txt             requests, PyYAML, pytest, ruff
```

### What each script does

| Script | Job | Reads | Writes (in `engagement/output/`) |
|---|---|---|---|
| `scope.py` | The safety gate: is this IP/range allowed? Is the window open? Did the human approve? With `--validate`, checks a whole engagement file (used by the intake prompt) | `engagement.yaml` | `scope_check.json` / `engagement_check.json` |
| `nmap_discovery.py` | Host discovery: pass 1 (ping-style probes) and pass 2 (`-Pn` port sweep of hosts pass 1 missed) | `engagement.yaml` | `discovery_pass1.json`, `discovery_pass2.json` |
| `build_targets.py` | Merges both passes into the Nessus target list | the two pass files | `targets.txt`, `host_summary.json` |
| `parse_nessus.py` | Turns the `.nessus` XML into flat findings; rejects out-of-scope hosts | `.nessus` file | `findings.json` |
| `group_findings.py` | One finding per plugin, with the list of affected hosts | `findings.json` | `grouped.json` |
| `triage.py --stage recon` | Removes informational plugins before any issue is opened | `grouped.json` | `to_open.json`, `excluded.json` |
| `enrich_kev.py` | Is the CVE actively exploited? (CISA KEV catalog) | grouped/to_open | `enrichment/<plugin>/kev.json` |
| `enrich_epss.py` | How likely is exploitation? (EPSS score, batched) | grouped/to_open | `enrichment/<plugin>/epss.json` |
| `enrich_nvd.py` | Official CVSS score, description, references (NVD) | grouped/to_open | `enrichment/<plugin>/nvd.json` |
| `enrich_vendor.py` | Did the OS vendor fix it? (Ubuntu, Red Hat, Microsoft) | grouped/to_open | `enrichment/<plugin>/vendor.json` |
| `triage.py --stage verify` | Applies the rules → verdict + evidence for one finding | grouped + enrichment | `triage/<plugin>.json` |
| `cache.py` | SQLite cache of every API answer (so lookups aren't repeated) | n/a | `cache.db` |
| `http_client.py` | One shared GET function + retry with backoff | n/a | n/a |
| `setup_labels.py` | Checks the repo is **private**, then creates all 25 labels | `--repo` | `labels_setup.json` |
| `board.py` | The only way agents touch GitHub: create issues, claim, change status, comment, relay your decisions | `to_open.json`, issue numbers | issues/comments, `board/issue_map.json` |

---

## 4. Try it yourself: the dry run (what exists so far)

The dry run uses only the synthetic fixtures and canned API data. **No packets
are sent and no API is called.** Run these from the `vuln-playbook` folder, one
line at a time (they work in PowerShell and in Git Bash):

```
python scripts/nmap_discovery.py --pass 1 --dry-run --engagement tests/fixtures/engagement_test.yaml
python scripts/nmap_discovery.py --pass 2 --dry-run --engagement tests/fixtures/engagement_test.yaml
python scripts/build_targets.py --engagement tests/fixtures/engagement_test.yaml

python scripts/parse_nessus.py --nessus tests/fixtures/sample.nessus --engagement tests/fixtures/engagement_test.yaml
python scripts/group_findings.py
python scripts/triage.py --stage recon

python scripts/enrich_kev.py    --dry-run --grouped engagement/output/to_open.json
python scripts/enrich_epss.py   --dry-run --grouped engagement/output/to_open.json
python scripts/enrich_nvd.py    --dry-run --grouped engagement/output/to_open.json
python scripts/enrich_vendor.py --dry-run --grouped engagement/output/to_open.json

python scripts/triage.py --stage verify --plugin-id 900104 --engagement tests/fixtures/engagement_test.yaml
```

Repeat the last line for plugins `900101 900102 900103 900105 900106`.
Then open the files in `engagement/output/` to see each step's result.

### What you should see

| Step | Result |
|---|---|
| Discovery | 4 live hosts (192.0.2.30 was found **only** by pass 2), 1 filtered, 1 unresponsive. The pass 1 command includes `--exclude 192.0.2.250/32`. |
| Parse | 20 findings from 4 hosts. **2 hosts rejected:** 203.0.113.50 (outside scope), 192.0.2.250 (excluded). |
| Group | 10 findings, one per plugin. 900102 and 900105 cross-reference each other (same CVE). |
| Recon triage | 6 to open as issues, 4 informational plugins excluded (rule `informational_plugin`). |
| Verify triage | see the table below |

| Plugin | Finding | Verdict | Rule that fired |
|---|---|---|---|
| 900104 | Log4Shell (CVE-2021-44228) | **verified** | `kev_match` |
| 900102 | SWEET32, high | verified | `direct_detection` |
| 900105 | SWEET32, medium (same CVE) | verified | `direct_detection` |
| 900101 | OpenSSH banner on Ubuntu | **needs-human** | `banner_only_backport` |
| 900106 | TLS 1.0 | accepted-risk | `accepted_risk_listed` |
| 900103 | SSH CBC ciphers, low | appendix | `low_severity_hardening` |

To start over, delete everything in `engagement/output/` except `.gitkeep`.

---

## 5. How a verdict is decided

`playbook/triage-rules.yaml` is a list of rules. **The first rule that matches
wins**, and its name is recorded. That name goes into the handoff comment, so
every verdict traces back to one rule.

The script first boils the finding down to a few plain **facts**:

| Fact | Meaning |
|---|---|
| `kev` | at least one CVE is in CISA's Known Exploited Vulnerabilities list |
| `banner_only` | Nessus only read a version string ("self-reported version"), it did not test the flaw |
| `backport_distro` | an affected host runs Ubuntu/Debian/Red Hat/... (they patch without changing version numbers) |
| `vendor_status` | what the OS vendor says: `fixed`, `not-affected`, `affected` (no fix), `unknown` |
| `accepted_risk` | the client formally accepted this risk (listed in `engagement.yaml`) |

Then the rules are checked in order:

```
recon:  1 informational_plugin   severity 0                      -> exclude (never becomes an issue)
verify: 2 accepted_risk_listed   client accepted it              -> accepted-risk
        3 kev_on_backport_banner KEV + banner + backport distro  -> needs-human
        4 kev_match              KEV                             -> verified
        5 backport_not_affected  banner + backport + vendor "not affected"  -> false-positive
        6 backport_no_fix_yet    banner + backport + vendor "affected"      -> verified
        7 banner_only_backport   banner + backport (vendor fixed/unknown)   -> needs-human
        8 low_severity_hardening severity 1                      -> appendix
        9 direct_detection       not banner-only                 -> verified
       10 banner_only_vendor_version banner on non-backport OS   -> verified
       11 fallback_needs_human   anything else                   -> needs-human
```

**Why the Ubuntu banner goes to a human:** the server says `OpenSSH_8.9p1`,
which is older than the fixed 9.6. But Ubuntu fixed the bug *inside* its
8.9p1 package (build `3ubuntu0.5`), without changing the version number. The
banner alone can't tell whether that build is installed. Only a person with
access to the server (or a credentialed scan) can.

**Why Red Hat's "not affected" does not clear Log4Shell:** Red Hat says
RHEL 8's *own* log4j package is not affected. But the vulnerable copy lives
inside the application, and Nessus confirmed it directly with a harmless DNS
callback. Vendor data only judges **banner-only** detections. A direct
observation always wins.

**Built-in protections** (checked when the rules file is loaded, so a bad edit
fails immediately):
- every `false-positive` rule must include `kev: false`, so a KEV CVE can never
  be dismissed automatically
- the last rule must match everything, so every finding gets a verdict
- recon rules may not use facts that need enrichment (that data doesn't exist yet)

---

## 5b. How the GitHub board works

Agents never run `gh issue edit` themselves. Every change goes through
`scripts/board.py`, which checks the rules of `playbook/labels.md` **in code**
before anything reaches GitHub. That's why the board stays correct even if an
agent gets confused.

### The labels (25 in total, created by `setup_labels.py`)

| Group | Labels | Rule |
|---|---|---|
| stage | `stage:recon` → `stage:verify` → `stage:report` → `stage:audit` | only on the kickoff issue, exactly one at a time |
| status | `status:needs-verify`, `verified`, `false-positive`, `accepted-risk`, `appendix`, `needs-human`, `reported`, `audited`, `audit-rejected` | every finding has **exactly one** |
| type | `type:finding`, `type:handoff`, `type:blocker` | what kind of issue it is |
| blocker flag | `needs-human` | on blockers: the run waits for you |
| claim | `claimed:recon-scanner`, `claimed:verifier`, `claimed:report-writer`, `claimed:auditor` | at most one, "I'm working on this" |
| severity | `severity:critical`, `high`, `medium`, `low` | from Nessus; informational never becomes an issue |

### What board.py refuses (and why)

| It refuses to... | Because |
|---|---|
| change a status unless the issue is currently in the status the agent expects | the agent may be acting on old information, which would overwrite someone else's verdict |
| let an agent make a move it doesn't own (e.g. report-writer marking something verified) | the transition table in `labels.md` is enforced, not just documented |
| claim an issue that already has any `claimed:` label | two verifiers on one finding would post two verdicts |
| accept a verifier verdict without the verifier's claim | same reason; the claim is removed in the same call as the verdict |
| post any comment or issue containing a line starting with `Decision:` | agents use the same GitHub login as you, so GitHub can't show who wrote a decision. This ban plus the agent rules keep decisions with you. It is a rule, not proof: a raw `gh issue comment` would get past it (see `playbook/labels.md` section 4) |
| post text that looks like a credential (a password written out with its value, private keys, AWS/GitHub tokens) | credentials must never land in issues |
| create an issue with a label that isn't in the catalog | a typo would silently create a new, meaningless label |
| open an issue for an informational (severity 0) plugin | triage already excluded those |
| run `setup_labels.py` on a public repo | engagement data may only live in a private repo |

Status changes happen in **one** `gh issue edit` call (`--add-label new
--remove-label old`), so an issue is never left with zero or two statuses. The
handoff comment is checked *before* the label moves, so a refused comment
can't leave a status change without its explanation.

### How you make a decision

When the evidence conflicts, a finding gets `status:needs-human`. You comment
on that issue in GitHub:

```
Decision: false-positive
Reason: The fixed package 1:8.9p1-3ubuntu0.5 is installed (checked with dpkg -l).
```

Allowed decisions: `verified`, `false-positive`, `accepted-risk`, `appendix`.
The orchestrator then runs `board.py relay-decision --issue N`, which finds
your latest `Decision:` comment, applies it and posts a handoff with rule
`human_decision` that links to your comment. A decision without a `Reason:`
line is refused, because the auditor needs to know why.

After the board change, it also adds a `human_decision` block to
`engagement/output/triage/<plugin_id>.json`. The verifier's original verdict
(`needs-human`) and rule stay in the file, so you can see both what the rules
concluded and what you decided. Running it twice with the same comment is
harmless, but a different decision already on file is refused rather than
overwritten.

Want Claude's help? Ask it to draft the `Decision:` and `Reason:` text, then
post it yourself. Agents never post a `Decision:` line by any route.

### Useful board commands (run inside the engagement repo)

```
python scripts/setup_labels.py --dry-run          # show the gh commands without running them
python scripts/setup_labels.py                    # create the labels (repo must be private)
python scripts/board.py list --label status:needs-human
python scripts/board.py view --issue 12
python scripts/board.py decision --issue 12       # what did the human decide?
```

Agents use the other commands (`create-finding`, `claim`, `transition`,
`set-stage`, `relay-decision`, `close`). `python scripts/board.py --help` lists
them all.

---

## 5c. The agents: who does what

There are five roles. The **orchestrator** is the main Claude Code session,
and its rules are in `CLAUDE.md`. The other four are **subagents**, each
defined in `.claude/agents/<name>.md`. A subagent file has a small header
(`name`, `description`, `tools`) and then its instructions, always in the same
seven sections: Role, Trigger labels, Duties, Rules, Must never, Handoff,
Definition of done.

| Agent | Picks up | Does | Tools (hard limit) | Can never |
|---|---|---|---|---|
| **orchestrator** (`CLAUDE.md`) | the whole board | checks approval and that the repo is private, opens the kickoff issue, dispatches agents, moves the stage, relays your decisions, posts the run summary | everything in the main session | change `scope_approved`, scan, give verdicts, edit the report, merge the PR |
| **recon-scanner** | `stage:recon` | Nmap pass 1 + 2, `targets.txt`, host summary, the "run Nessus" blocker, import → one issue per finding, warms the enrichment cache | Bash, Read, Write, Grep, Glob | scan outside scope or window, run nmap by hand, exploit anything |
| **verifier** (several at once) | one `status:needs-verify` issue | claims it, runs the 4 enrichers + verify triage, reads the Tenable page (live), posts the verdict | Bash, Read, Grep, WebFetch | dismiss a KEV CVE, override the rules (it can only send a finding *to you*) |
| **report-writer** | `status:verified` / `stage:report` | writes `report.md` from the template, opens the PR, marks findings `reported` | Read, Write, Edit, Bash | invent evidence, claim a certified author, leave out a verified finding |
| **auditor** | the report PR | works through the audit checklist, relabels `audited` / `audit-rejected`, posts the verdict on the PR | Read, Grep, Bash (**no Write/Edit**) | edit the report, approve with a failing check |

### Points worth knowing

- **The verifier follows the rules, it doesn't overrule them.** The verdict
  comes from `triage.py`. If the verifier's own reading of the Tenable plugin
  page or vendor advisory contradicts the rules' facts, it can only send the
  finding to you (`needs-human`, rule `verifier_conflict`). It can never
  upgrade, downgrade or dismiss one on its own.
- **Parallel verifiers.** The orchestrator gives each verifier a different
  issue (at most 5 at a time). Before that, recon-scanner runs every enricher
  once over all findings. That means one KEV download, one batched EPSS
  query and one NVD rate limiter, so the verifiers mostly read from
  `cache.db` and don't compete for the NVD limit.
- **The audit verdict is a PR comment, not a GitHub "Approve".** GitHub
  doesn't let an account approve its own pull request, and every agent uses
  your `gh` login. So the auditor posts a review comment with a handoff block
  saying `audited` or `audit-rejected` (`board.py review-pr`), and **you merge**.
- **Rejections loop back.** An `audit-rejected` issue goes back to the agent
  the auditor names: verifier or recon-scanner → `needs-verify`,
  report-writer → `verified`. If the same issue is rejected twice, the
  orchestrator stops looping and asks you.
- **Dry run = same agents, different inputs.** In dry run the orchestrator
  uses `tests/fixtures/engagement_test.yaml`, every script gets `--dry-run`,
  the Nessus step uses `tests/fixtures/sample.nessus`, and the verifier skips
  web pages. Human decisions are still real: the run pauses for you on the
  Ubuntu banner finding.

---

## 5d. The report and the audit

**The report** (`engagement/output/report.md`) is built from
`playbook/report-template.md`: executive summary, scope and authorization,
methodology (with every human decision linked), findings, accepted risks, the
false-positive log, and appendices (low-severity items, excluded
informational plugins, host discovery, a traceability table). Findings are
ordered **KEV-listed first, then VPR (or CVSS v3), then EPSS**. Each one shows
its issue number, hosts, CVE, scores, evidence links, impact, remediation and
SLA due date (window end + the `severity_sla` days for its severity). The
report-writer may only use numbers that are in the output files or on the
board.

**The audit** follows `playbook/audit-checklist.md`: 26 checks in 8 groups
(A traceability, B evidence, C severity and ordering, D scope, E false
positives and accepted risks, F confidentiality and honesty, G executive
summary, H methodology). Each check names how to verify it and which agent
fixes a failure. One failed check means `audit-rejected`. The auditor lists
every result in its PR review, e.g. `C3 FAIL: 4.2 ranked above a KEV finding`.

**The rules of engagement** (`playbook/rules-of-engagement.md`) are the
human-readable contract: authorization, scope, approval, window, what is
permitted and prohibited, the seven stop conditions, and data handling. Each
rule that is enforced in code names the script that enforces it.

---

## 6. Safety: where each rule is enforced

| Rule | Enforced in |
|---|---|
| Only scan in-scope IPs/ranges | `scope.check_in_scope` / `check_network_in_scope`, called by every scan script; excluded hosts are passed to nmap `--exclude` |
| No scan before you approve | `scope.check_approved`: needs `scope_approved: true` (a real YAML boolean) **and** `approved_at` |
| Only inside the engagement window | `scope.check_in_window`, called before every live scan |
| Out-of-scope hosts in a Nessus file never reach the board | `parse_nessus.py` (listed in `rejected_hosts` with a reason) |
| Nmap can't be tricked into running shell commands | it's run as an argument list, never through a shell |
| KEV never auto-dismissed | `triage.validate_rule` (false-positive rules need `kev: false`) |
| No guessing when data is missing | triage raises an error if enrichment hasn't run |
| Real scan data never committed | `.gitignore` (inbox, output, any stray `.nessus`) |
| Only the human can write `Decision:` | `board.check_postable` refuses any comment or issue containing such a line |
| No credentials in issues | `board.find_secrets` blocks password assignments, private keys, AWS/GitHub tokens |
| Exactly one status per finding; no stale or unauthorized moves | `board.transition` (one-call swap, expected from-state, actor table) |
| Engagement repo must be private | `setup_labels.check_repo_private` runs before any label is created; the orchestrator checks it before the run |
| No duplicate finding issues on a re-run | `board.check_not_opened` (uses `engagement/output/board/issue_map.json`) |
| The auditor can't change the report | its agent file has no Write/Edit tool (checked by `test_agents.py`) |
| No credentials in the report | `board.py check-secrets` is run by the report-writer and again by the auditor |
| gh can't be tricked into running shell commands | run as an argument list; long text goes on stdin (`--body-file -`) |

---

## 7. Common tasks

**Run an engagement.** Follow the [README](README.md): create a private repo
from the template, paste Prompt 1 (intake), approve the scope yourself in
`engagement.yaml`, paste Prompt 2. The intake runs `python scripts/scope.py
--validate`, which refuses, among other things, an exclude entry that sits
outside every include range (probably a typo for a host the client wanted
protected).

**Accept a risk for the client.** Add an entry to `accepted_risks` in
`engagement.yaml` (name a `plugin_id` *or* a `cve`, plus `accepted_by`,
`reference`, and an optional `expires` date). After the expiry date it stops
applying automatically.

**Add or change a triage rule.** Edit `playbook/triage-rules.yaml`. Order
matters, so put specific rules above general ones. Run `pytest`:
`test_rule_order_matches_approved_design` will fail on purpose, so you have to
update it, which makes the change deliberate.

**Use an NVD API key** (faster lookups: 50 instead of 5 requests per 30 s).
Copy `.env.example` to `.env` and fill in `NVD_API_KEY=`. `.env` is gitignored.

**Run live instead of dry-run.** Leave out `--dry-run`. Enrichment then calls
the real APIs and caches answers in `cache.db` (KEV/EPSS/vendor: 1 day, NVD:
7 days). Discovery needs `nmap` installed, an approved scope, and an open
window.

---

## 8. Running the tests

```
pytest -v
ruff check .
```

Every test has a comment explaining **why** that case matters. The tests never
touch the network. The enrichers take their "GET" and "sleep" functions as
arguments, and the tests pass small hand-written stand-ins, so the retry and
rate-limit logic is tested without waiting and without real HTTP calls. The
board scripts work the same way: they take a `run_gh` function, and the tests
pass `tests/fake_gh.py`, a pretend GitHub kept in plain Python lists, so the
tests can check exactly which labels and comments ended up on each issue.

| Test file | Checks |
|---|---|
| `test_scope.py` | scope include/exclude, range edges, IPv6, the window, the approval gate, whole-file validation for the intake |
| `test_readme.py` | the README prompts contain every required step; the files it mentions exist; CI runs ruff and pytest |
| `test_parse_nessus.py` | Nessus parsing, rejected hosts, every malformed-input case |
| `test_group_findings.py` | one group per plugin, host lists, the duplicate-CVE links |
| `test_fixtures.py` | fixtures use only documentation IPs and contain every case the spec requires |
| `test_nmap_discovery.py` | nmap commands, live/filtered/unresponsive, the safety gates |
| `test_build_targets.py` | merging the passes, mismatched files, scope re-check |
| `test_cache.py` | TTL expiry per source, persistence, SQL-safe keys |
| `test_http_client.py` | backoff timing, giving up, 404 as an answer |
| `test_enrich_*.py` | each enricher: parsing real (canned) data, caching, batching, rate limits |
| `test_triage.py` | rule validation, rule order, every dry-run verdict, accepted risks |
| `test_setup_labels.py` | label list matches `labels.md`, private-repo check, re-runnable |
| `test_board.py` | handoff format, claims, status moves, refusals, human decisions, issue bodies |
| `test_issue_templates.py` | the three issue forms are valid and use only catalog labels |
| `test_playbook_docs.py` | the report template, audit checklist and rules of engagement contain every required section; checklist IDs are unique and each has an owner |
| `test_agents.py` | agent files have the right header, tools and sections; every script, board command and rule name they mention really exists |

---

## 9. Glossary

| Term | Meaning |
|---|---|
| **CVE** | a public ID for one specific vulnerability, e.g. CVE-2021-44228 |
| **CVSS** | 0–10 severity score for a CVE (10 = worst), from NVD |
| **VPR** | Tenable's own 0–10 priority score, which weighs current threat activity |
| **EPSS** | probability (0–1) that a CVE gets exploited in the next 30 days |
| **KEV** | CISA's list of CVEs *known* to be exploited in real attacks |
| **NVD** | the US National Vulnerability Database: official CVE details and scores |
| **Plugin** | one Nessus check. Each has an ID (e.g. 900104 in our fixtures) |
| **Banner-only detection** | Nessus read a version string instead of testing the flaw |
| **Backporting** | a distro fixes a bug inside an old version without changing its number |
| **Documentation IP ranges** | 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24: reserved for examples and never routed |
| **Dry run** | the whole flow on synthetic data and canned API answers, with no scanning |
| **Handoff block** | the fixed-format comment an agent posts when it changes an issue's state |
| **Claim** | a `claimed:<agent>` label meaning "this agent is working on it"; prevents double work |
| **gh** | GitHub's command-line tool; every board change goes through it |
| **Orchestrator** | the main Claude Code session; follows `CLAUDE.md` and dispatches the subagents |
| **Subagent** | a helper Claude with its own instructions and a limited tool list (`.claude/agents/`) |
