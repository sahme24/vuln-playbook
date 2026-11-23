import os
import re

ROOT = os.path.dirname(os.path.dirname(__file__))
PLAYBOOK = os.path.join(ROOT, "playbook")


def read_doc(name):
    with open(os.path.join(PLAYBOOK, name), "r", encoding="utf-8") as handle:
        return handle.read()


def checklist_rows():
    """Return [(id, owner text)] for every check row in audit-checklist.md."""
    rows = []
    for line in read_doc("audit-checklist.md").splitlines():
        match = re.match(r"\|\s*([A-H]\d+)\s*\|", line)
        if match is not None:
            cells = line.strip().strip("|").split("|")
            rows.append((match.group(1), cells[-1].strip()))
    return rows


def test_report_template_has_required_sections():
    # The report-writer fills in this skeleton and the auditor checks against
    # it. Each section the design requires must be in the template, or it
    # would silently go missing from every report.
    text = read_doc("report-template.md")
    for heading in ["## 1. Executive summary", "## 2. Scope and authorization", "## 3. Methodology",
                    "## 4. Findings", "## 5. Accepted risks", "## 6. False-positive log",
                    "## Appendix A.", "## Appendix B.", "## Appendix D. Traceability"]:
        assert heading in text, "missing " + heading


def test_report_template_per_finding_fields():
    # Every finding must show hosts, CVE, CVSS, evidence, impact, remediation,
    # SLA date and references. A missing field here means it is missing in
    # every finding of every report.
    text = read_doc("report-template.md")
    for field in ["**Affected hosts**", "| CVE |", "| CVSS v3 |", "**Evidence.**", "**Business impact.**",
                  "**Remediation.**", "| Remediation due |", "**References.**", "| CISA KEV |", "| EPSS |"]:
        assert field in text, "missing " + field


def test_report_template_states_risk_order():
    # The order KEV, then VPR/CVSS, then EPSS is a design requirement. The
    # template is where the reader learns it.
    text = read_doc("report-template.md")
    assert "CISA KEV-listed first, then by Tenable VPR" in text
    assert "then by EPSS" in text


def test_checklist_ids_unique_and_owned():
    # The auditor cites checks by ID in its review. Duplicate IDs would make
    # a rejection ambiguous, and every check needs an owner so a failure can
    # be routed back to an agent.
    rows = checklist_rows()
    assert len(rows) >= 20
    seen = []
    for check_id, owner in rows:
        assert check_id not in seen, "duplicate check " + check_id
        seen.append(check_id)
        found_owner = False
        for agent in ["report-writer", "verifier", "recon-scanner"]:
            if agent in owner:
                found_owner = True
        assert found_owner, check_id + " has no owning agent"


def test_checklist_covers_design_requirements():
    # The design lists what the audit must cover. Each topic must appear as
    # a check, or the auditor would not look for it.
    text = read_doc("audit-checklist.md")
    for topic in ["links an issue", "evidence", "match the source files", "in scope",
                  "reasoning holds up", "No credentials", "summary table matches the board"]:
        assert topic in text, "checklist does not cover: " + topic


def test_rules_of_engagement_covers_safety_topics():
    # The rules of engagement are what the operator agrees to. Authorization,
    # approval, window, prohibited activity, stop conditions and data handling
    # must all be stated.
    text = read_doc("rules-of-engagement.md")
    for heading in ["## 1. Authorization", "## 2. Scope", "## 3. Approval", "## 4. Scan window",
                    "## 5. Permitted and prohibited activity", "## 6. Stop conditions", "## 7. Data handling"]:
        assert heading in text, "missing " + heading
    assert "Exploitation" in text
    assert "Brute forcing" in text
    assert "Denial-of-service" in text
