<!--
REPORT TEMPLATE. The report-writer copies this structure into
engagement/output/report.md and fills every {{placeholder}} from the board
and the files in engagement/output/. Rules:
  - Remove every HTML instruction comment and every {{placeholder}}
    from the final report. The auditor checks that none are left.
  - Every number, score, date and host comes from a file or an issue. Never
    re-type from memory, never estimate.
  - Keep the section numbering. The auditor refers to sections by number.
  - Precise, neutral, technical wording. No filler, no exaggeration, no
    statement about the author's certifications.
-->

# {{engagement.name}}: Vulnerability Assessment Report

| | |
|---|---|
| Client | {{engagement.client}} |
| Authorized by | {{engagement.authorized_by}} |
| Authorization reference | {{engagement.authorization_reference}} |
| Assessment window | {{window_start}} to {{window_end}} |
| Report date | {{date the report PR is opened}} |
| Run mode | {{Live / Dry run}} |
| Board | {{link to the kickoff issue}} |

<!-- DRY RUN ONLY: keep this notice. Delete it in a live report. -->
> **Dry run.** This report was produced from synthetic test data (documentation
> IP ranges, fabricated scan results, recorded API responses). It describes no
> real system.

---

## 1. Executive summary

<!-- Audience = executive or both: plain language, no plugin IDs here.
     Audience = technical: this section can stay short. -->

{{Two or three sentences: what was assessed, when, and the overall result.}}

| Severity | Verified | Accepted risk | Appendix | False positive |
|---|---|---|---|---|
| Critical | {{n}} | {{n}} | {{n}} | {{n}} |
| High | {{n}} | {{n}} | {{n}} | {{n}} |
| Medium | {{n}} | {{n}} | {{n}} | {{n}} |
| Low | {{n}} | {{n}} | {{n}} | {{n}} |

**Known exploited vulnerabilities.** {{Number of verified findings listed in the
CISA KEV catalog, with their names. If none: "No verified finding is listed in
the CISA KEV catalog."}}

**Priority actions.**
<!-- 3 to 5 bullets, in report order, each naming the finding number and its SLA due date. -->
1. {{Finding 4.1: action, due {{date}}}}

**Limitations.** {{One or two sentences from section 3.3 that change how the
results should be read, e.g. uncredentialed scan, banner-based detections.}}

---

## 2. Scope and authorization

Testing was authorized by {{authorized_by}} ({{authorization_reference}}).
The scope was approved in the engagement file at {{approval.approved_at}}.

| In scope | Excluded |
|---|---|
| {{each scope.include entry}} | {{each scope.exclude entry}} |

**Discovery result.** {{n}} live, {{n}} filtered, {{n}} unresponsive hosts
(Appendix C).

**Hosts rejected from the scan results** (present in the Nessus file but not
in scope; nothing about them is reported):

| Host | Reason |
|---|---|
| {{ip}} | {{reason from rejected_hosts}} |

---

## 3. Methodology

### 3.1 Phases
1. **Discovery.** Nmap pass 1 (host discovery, profile `{{nmap_profile}}`),
   then pass 2 (`-Pn` check of common ports on hosts pass 1 did not find).
   Every target was checked against the scope before scanning.
2. **Vulnerability scan.** Nessus policy `{{nessus_policy_name}}`,
   {{credentialed / uncredentialed}}, run by the assessor against the {{n}}
   live hosts.
3. **Import and grouping.** {{n}} results grouped into {{n}} findings (one per
   Nessus plugin). {{n}} informational plugins were excluded by rule
   `informational_plugin` (Appendix B).
4. **Verification.** Each finding was checked against NVD (CVSS), the CISA
   KEV catalog, FIRST EPSS and, where relevant, the operating-system vendor's
   security tracker, then classified by the ordered rules in
   `playbook/triage-rules.yaml`. {{n}} findings required a human decision
   (section 3.2).
5. **Independent audit.** The report was checked against the evidence using
   `playbook/audit-checklist.md` before release.

### 3.2 Human decisions
<!-- One row per finding that went to status:needs-human. -->

| Finding | Issue | Decision | Decision record |
|---|---|---|---|
| {{name}} | #{{n}} | {{verdict}} | {{link to the Decision comment}} |

### 3.3 Limitations
- Point-in-time assessment of the window above. Later changes are not covered.
- No exploitation, brute forcing or denial-of-service testing was performed.
  Findings show exposure, not demonstrated compromise.
- {{Uncredentialed scans see only network-visible services; local package
  versions were not inspected. (Delete if credentialed.)}}
- Detections based on version banners can't see fixes a distribution
  backports. Such findings were sent for a human decision rather than reported
  or dismissed automatically.

### 3.4 Ordering and remediation deadlines
Findings are ordered: CISA KEV-listed first, then by Tenable VPR (CVSS v3 base
score where no VPR exists), then by EPSS probability, highest first.
Remediation is due within {{critical}} days (critical), {{high}} days (high)
and {{medium}} days (medium) of the end of the assessment window, per the
engagement's agreed SLA. {{Low: "No SLA is set for low severity; address in
normal maintenance."}}

---

## 4. Findings

| # | Finding | Severity | KEV | VPR | CVSS v3 | EPSS | Hosts | Due | Issue |
|---|---|---|---|---|---|---|---|---|---|
| 4.1 | {{name}} | {{severity}} | {{Yes/No}} | {{vpr}} | {{cvss}} | {{epss}} | {{n}} | {{date}} | #{{n}} |

<!-- Repeat the block below for every status:verified / status:reported
     finding, in the order of the table. -->

### 4.1 {{plugin_name}}

<!-- The last row (framework) only if reporting.framework is not "none":
     name the control(s) the remediation supports, e.g. NIST 800-53 SI-2 / RA-5.
     Delete the row otherwise. -->

| | |
|---|---|
| Issue | #{{n}} |
| Nessus plugin | {{plugin_id}} |
| Severity | {{severity}} (Nessus) |
| CVE | {{CVE IDs, or "none"}} |
| CVSS v3 | {{score}} ({{vector}}), source: {{NVD / Nessus}} |
| VPR | {{vpr or "n/a"}} |
| EPSS | {{probability}} (percentile {{p}}), {{date of score}} |
| CISA KEV | {{"Listed, added YYYY-MM-DD" or "Not listed"}} |
| Verdict basis | rule `{{rule}}`, confidence {{confidence}} |
| Remediation due | {{date}} |
| {{framework}} | {{control IDs}} |

**Affected hosts**

| Host | Port | Operating system |
|---|---|---|
| {{ip}} | {{port/protocol}} | {{os}} |

**Description.** {{What the vulnerability is, from the NVD / Nessus description.}}

**Evidence.**
- {{each evidence link from the verifier's handoff on the issue}}

**Business impact.** {{What an attacker could do on these hosts if this is
exploited, based on the vulnerability description and the affected service.
Don't speculate about the client's business beyond what engagement.yaml says.}}

**Remediation.** {{Specific action: the fixed version, vendor advisory or
configuration change. Cite the vendor where one exists.}}

**References.**
- {{NVD link, vendor advisory, Tenable plugin page}}

---

## 5. Accepted risks

<!-- status:accepted-risk issues. Data from accepted_risks in engagement.yaml. -->

| Finding | Issue | Accepted by | Reference | Expires | Hosts |
|---|---|---|---|---|---|
| {{name}} | #{{n}} | {{accepted_by}} | {{reference}} | {{expires or "no expiry"}} | {{ips}} |

---

## 6. False-positive log

<!-- status:false-positive issues. Every row must say who or what decided. -->

| Finding | Issue | Decided by | Reason | Evidence |
|---|---|---|---|---|
| {{name}} | #{{n}} | {{rule `name` / human decision (link)}} | {{reason}} | {{links}} |

{{If none: "No findings were classified as false positives."}}

---

## Appendix A. Low-severity and hardening items

<!-- status:appendix issues. Shorter format: one row each. -->

| Finding | Issue | Hosts | Recommendation |
|---|---|---|---|
| {{name}} | #{{n}} | {{ips}} | {{solution}} |

## Appendix B. Excluded informational plugins

{{n}} informational (severity 0) plugins were recorded but not reported, by
rule `informational_plugin`:

| Plugin | Name | Hosts |
|---|---|---|
| {{plugin_id}} | {{name}} | {{n}} |

## Appendix C. Host discovery summary

| Host | Status | Found by |
|---|---|---|
| {{ip}} | {{live / filtered / unresponsive}} | {{pass 1 / pass 2}} |

## Appendix D. Traceability

| Section | Issue | Plugin | Final status | Rule / decision |
|---|---|---|---|---|
| {{4.1}} | #{{n}} | {{plugin_id}} | {{status}} | {{rule}} |
