import os

import yaml

import setup_labels

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".github", "ISSUE_TEMPLATE")


def load_template(name):
    with open(os.path.join(TEMPLATE_DIR, name), "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_templates_are_valid_issue_forms():
    # GitHub silently ignores a broken issue form. Each one needs a name, a
    # description and a body list, or it never shows up in the "New issue" menu.
    for name in ["finding.yml", "handoff.yml", "blocker.yml"]:
        form = load_template(name)
        assert type(form["name"]) is str
        assert type(form["description"]) is str
        assert type(form["body"]) is list


def test_template_labels_exist_in_catalog():
    # A template label missing from setup_labels.py would never be created,
    # so issues from that form would land without their state label.
    known = setup_labels.label_names()
    for name in ["finding.yml", "handoff.yml", "blocker.yml"]:
        for label in load_template(name)["labels"]:
            assert label in known


def test_template_default_states():
    # A hand-made finding must start in needs-verify so it gets verified like
    # every other finding, and a blocker must carry needs-human so the run waits.
    assert load_template("finding.yml")["labels"] == ["type:finding", "status:needs-verify"]
    assert "needs-human" in load_template("blocker.yml")["labels"]
