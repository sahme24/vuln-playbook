import os
import re

import yaml

import board

ROOT = os.path.dirname(os.path.dirname(__file__))
AGENT_DIR = os.path.join(ROOT, ".claude", "agents")

REQUIRED_SECTIONS = ["Role", "Trigger labels", "Duties", "Rules", "Must never", "Handoff", "Definition of done"]

# The tool lists the design gives each agent. The auditor deliberately has no
# Write or Edit, so it can never change the report it is auditing.
EXPECTED_TOOLS = {
    "recon-scanner": ["Bash", "Read", "Write", "Grep", "Glob"],
    "verifier": ["Bash", "Read", "Grep", "WebFetch"],
    "report-writer": ["Read", "Write", "Edit", "Bash"],
    "auditor": ["Read", "Grep", "Bash"],
}


def read_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def split_agent_file(name):
    """Return (frontmatter dict, body text) of .claude/agents/<name>.md."""
    text = read_text(os.path.join(AGENT_DIR, name + ".md"))
    parts = text.split("---\n", 2)
    # parts[0] is the empty text before the first ---, parts[1] the frontmatter.
    return yaml.safe_load(parts[1]), parts[2]


def tool_list(frontmatter):
    tools = []
    for piece in frontmatter["tools"].split(","):
        tools.append(piece.strip())
    return tools


def all_instruction_text():
    """CLAUDE.md plus every agent body: the text that tells agents what to run."""
    text = read_text(os.path.join(ROOT, "CLAUDE.md"))
    for name in EXPECTED_TOOLS:
        text = text + "\n" + read_text(os.path.join(AGENT_DIR, name + ".md"))
    return text


def test_every_agent_file_exists_with_frontmatter():
    # Claude Code only loads a subagent if its file has name, description and
    # tools. A missing field means the orchestrator cannot dispatch that agent.
    for name in EXPECTED_TOOLS:
        frontmatter, body = split_agent_file(name)
        assert frontmatter["name"] == name
        assert len(frontmatter["description"]) > 20
        assert body.strip() != ""


def test_agent_tools_match_design():
    # Tools are the hard limit on what an agent can do. Extra tools (e.g.
    # Write for the auditor) would quietly break the separation of duties.
    for name in EXPECTED_TOOLS:
        frontmatter, body = split_agent_file(name)
        assert tool_list(frontmatter) == EXPECTED_TOOLS[name]
    auditor_tools = tool_list(split_agent_file("auditor")[0])
    assert "Write" not in auditor_tools
    assert "Edit" not in auditor_tools


def test_every_agent_has_required_sections():
    # Every agent prompt must spell out its trigger, its limits and when it is
    # done. A missing "Must never" section would leave the safety rules unsaid.
    for name in EXPECTED_TOOLS:
        frontmatter, body = split_agent_file(name)
        for section in REQUIRED_SECTIONS:
            assert "\n## " + section + "\n" in body, name + " is missing section " + section


def test_referenced_scripts_exist():
    # If a prompt tells an agent to run a script that was renamed or never
    # written, the run fails halfway. Every scripts/*.py mentioned must exist.
    names = re.findall(r"scripts/([a-z_]+\.py)", all_instruction_text())
    assert len(names) > 10
    for name in names:
        assert os.path.isfile(os.path.join(ROOT, "scripts", name)), "missing script " + name


def test_referenced_board_commands_exist():
    # Same idea for board.py: every "board.py <command>" in the prompts must be
    # a real subcommand, or the agent gets an argparse error mid-run.
    known = ["view", "list", "create-finding", "create-issue", "comment", "handoff", "claim",
             "release", "transition", "set-stage", "decision", "relay-decision", "review-pr",
             "check-secrets", "close"]
    commands = re.findall(r"board\.py ([a-z-]+)", all_instruction_text())
    assert len(commands) > 10
    for command in commands:
        assert command in known, "unknown board.py command " + command


def test_referenced_rule_names_are_known():
    # A --rule value in a prompt must be a fixed rule name from
    # handoff-format.md, so the auditor can interpret every handoff.
    fixed = read_text(os.path.join(ROOT, "playbook", "handoff-format.md"))
    rules = re.findall(r"--rule ([a-z_]+)", all_instruction_text())
    for rule in rules:
        assert "`" + rule + "`" in fixed, "rule " + rule + " is not documented"


def test_verifier_cannot_reach_other_statuses():
    # The prompt and the code must agree: the verifier only moves issues out
    # of needs-verify. board.py's transition table is the real guard.
    for allowed_from, allowed_to in board.TRANSITIONS["verifier"]:
        assert allowed_from == "needs-verify"


def test_orchestrator_rules_forbid_changing_approval():
    # The approval flag is the human's sign-off on scope. CLAUDE.md must say
    # in plain words that the orchestrator never changes it.
    text = read_text(os.path.join(ROOT, "CLAUDE.md"))
    assert "approval.scope_approved" in text
    assert "You never change that\n   flag" in text
