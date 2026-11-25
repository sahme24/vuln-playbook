# Rules of engagement

These rules apply to every engagement run with this playbook, to the human
operator and to every agent. Where a rule is enforced in code, the enforcing
script is named. Prompts can be misread, code can't, so the most important
rules are in code.

---

## 1. Authorization

- Testing happens only with written authorization from someone entitled to
  give it for the systems in scope. Their name goes in
  `engagement.authorized_by`, and the ticket, email subject or document ID in
  `engagement.authorization_reference`.
- Missing or unclear authorization means **no testing**. The intake prompt
  doesn't write an engagement file without both fields.
- The authorization covers the listed scope and window only. Anything else
  needs a new authorization and a new approval.

## 2. Scope

- Only addresses inside `scope.include` and outside `scope.exclude` may be
  scanned. **Enforced by** `scope.py`, which every scanning script calls
  before sending anything. Excluded hosts are also passed to Nmap as
  `--exclude`.
- Hosts that appear in a Nessus export but are out of scope are dropped at
  import and listed as rejected (`parse_nessus.py`). They're never reported on.
- Scope is changed only by the human, by editing the engagement file and
  approving it again. Agents never edit scope.

## 3. Approval

- No live scan runs until the human has reviewed the scope and set
  `approval.scope_approved: true` with `approval.approved_at`. **Enforced
  by** `scope.check_approved`, called by `nmap_discovery.py` even in dry-run mode.
- Only the human sets the flag. The orchestrator and the agents never change
  it (stated in `CLAUDE.md` and in every agent's "Must never").
- Any change to scope or window resets the approval: set it back to `false`,
  review again, approve again.

## 4. Scan window

- Live scans run only between `window_start` and `window_end`. **Enforced
  by** `scope.check_in_window`, called before every live scan.
- If the window closes mid-run, scanning stops. Verification, reporting and
  audit may continue, because they don't touch the targets.

## 5. Permitted and prohibited activity

| Permitted | Prohibited |
|---|---|
| Nmap host discovery (pass 1) and the `-Pn` common-port check (pass 2) at the configured profile | Exploitation of any vulnerability, including "safe" proof-of-concept checks |
| A Nessus scan with the saved policy named in the engagement file, launched by the human | Brute forcing or password guessing of any kind |
| Lookups in public vulnerability databases (NVD, CISA KEV, EPSS, vendor trackers, Tenable plugin pages) | Denial-of-service checks, or raising scan intensity beyond the profile |
| Credentialed scanning, if `scanning.credentialed` is true, with credentials the client supplied for that purpose | Using credentials for anything except the authorized scan, or storing them anywhere in the repo, issues or report |

The `quiet` Nmap profile exists for fragile networks: slower timing and a
packet-rate cap.

## 6. Stop conditions

Stop scanning immediately and tell the human (a `needs-human` blocker, or
directly in the session) when:

1. Any script raises a scope, window or approval error. Never work around it.
2. The client reports service degradation or asks for testing to stop.
3. A host responds that looks like it belongs to a third party (for example
   a cloud provider's or another organization's system inside the ranges).
4. The engagement window closes.
5. Sensitive data or credentials turn up in scan output. Redact them from
   everything the agents post (`board.py` refuses to post credential-like
   text) and tell the human so the client can rotate them.
6. The engagement repo is found to be public. **Enforced by**
   `setup_labels.py`, which refuses to run on a non-private repo.
7. The same step fails twice in a row.

Resume only after the human has resolved the cause and said to continue.

## 7. Data handling

- Engagement data (scan exports, outputs, issues, the report) lives only in
  the **private** engagement repo and the operator's machine. The public
  template holds synthetic data only.
- `.gitignore` keeps `engagement/inbox/*`, `engagement/output/*` (except the
  report), `cache.db`, `.env` and stray `.nessus` files out of git.
- Credentials never go in the repo, in issues or in the report.
  `scanning.credential_notes` describes what exists ("domain account
  provided by the client's IT team"), never the secret itself.
- After the engagement, the operator archives or deletes the engagement repo
  and local outputs as agreed with the client.

## 8. Decisions and escalation

- Agents coordinate only through the issue board, using the formats in
  `playbook/labels.md` and `playbook/handoff-format.md`.
- When evidence conflicts or agents disagree, the decision goes to the human
  as a `needs-human` issue. Nobody guesses, and no agent overrides another.
- The human decides by commenting `Decision: <verdict>` and `Reason: ...` on
  the issue. Only the human writes that line: `board.py` refuses to post one,
  and no agent may post one by any other route (raw `gh`, API, web UI). An
  agent may draft the text for the human to post.
- The human merges the audited report PR. That merge is the release of the
  report.
