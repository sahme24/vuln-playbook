import os

import yaml

ROOT = os.path.dirname(os.path.dirname(__file__))


def read_root_file(name):
    with open(os.path.join(ROOT, name), "r", encoding="utf-8") as handle:
        return handle.read()


def section(text, start_heading, end_heading):
    """The README text between two headings."""
    start = text.index(start_heading)
    end = text.index(end_heading, start)
    return text[start:end]


def test_intake_prompt_covers_required_steps():
    # A new user only follows the README. The intake prompt must check the
    # repo is private and gh works, ask every question group, validate in
    # code, and leave approval to the human.
    intake = section(read_root_file("README.md"), "## Prompt 1: Intake", "## Approve the scope")
    for required in ["gh auth status", "visibility", "PRIVATE", "ONE GROUP AT A TIME",
                     "Engagement and authorization", "Scope:", "Window:", "Nessus:", "Reporting:",
                     "scripts/scope.py --engagement engagement.yaml --validate",
                     "scope_approved to false", "must NOT set scope_approved"]:
        assert required in intake, "intake prompt is missing: " + required


def test_run_prompts_have_live_and_dry_run_variants():
    # The design asks for a run prompt plus a dry-run variant that uses the
    # fixtures. Both must point at CLAUDE.md so the orchestrator rules apply.
    run = section(read_root_file("README.md"), "## Prompt 2: Run", "## What you do during a live run")
    assert "LIVE mode" in run
    assert "DRY-RUN mode" in run
    assert run.count("Follow CLAUDE.md") == 2
    assert "tests/fixtures/engagement_test.yaml" in run
    assert "tests/fixtures/sample.nessus" in run


def test_readme_files_it_mentions_exist():
    # Every repo file the README tells a user to open must exist, or the
    # "README only" path breaks.
    for path in ["GUIDE.md", "CLAUDE.md", "engagement.example.yaml", ".env.example",
                 "playbook/rules-of-engagement.md", "tests/fixtures/engagement_test.yaml",
                 "tests/fixtures/sample.nessus", ".github/workflows/ci.yml"]:
        assert os.path.isfile(os.path.join(ROOT, path)), "missing " + path


def test_ci_runs_ruff_and_pytest():
    # The definition of done requires ruff and pytest to pass in CI. The
    # workflow must run on push and pull_request and call both tools.
    workflow = yaml.safe_load(read_root_file(os.path.join(".github", "workflows", "ci.yml")))
    # PyYAML reads the bare key "on" as the boolean True.
    triggers = workflow[True]
    assert "push" in triggers
    assert "pull_request" in triggers
    commands = []
    for step in workflow["jobs"]["test"]["steps"]:
        if "run" in step:
            commands.append(step["run"])
    assert "ruff check ." in commands
    assert "pytest -v" in commands
