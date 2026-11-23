import os
import re

import pytest

import fake_gh
import setup_labels

ROOT = os.path.dirname(os.path.dirname(__file__))
LABELS_DOC = os.path.join(ROOT, "playbook", "labels.md")


def labels_named_in_doc():
    """Every `label` in the first column of a table row of labels.md."""
    with open(LABELS_DOC, "r", encoding="utf-8") as handle:
        text = handle.read()
    names = []
    for line in text.splitlines():
        match = re.match(r"\|\s*`([a-z]+:[a-z-]+|needs-human)`\s*\|", line)
        if match is not None and match.group(1) not in names:
            names.append(match.group(1))
    return names


def test_catalog_matches_labels_doc():
    # labels.md is what people read and setup_labels.py is what runs. If they
    # drift apart, agents would try to use labels that were never created.
    doc = labels_named_in_doc()
    code = setup_labels.label_names()
    doc.sort()
    code.sort()
    assert doc == code


def test_catalog_has_expected_size_and_valid_entries():
    # 4 stages + 9 statuses + 3 types + needs-human + 4 claims + 4 severities.
    # Every color must be 6 hex digits, or gh label create fails halfway through.
    assert len(setup_labels.LABELS) == 25
    for label in setup_labels.LABELS:
        assert re.fullmatch(r"[0-9a-f]{6}", label["color"]) is not None
        assert len(label["description"]) <= 100


def test_setup_creates_every_label_in_private_repo():
    # Happy path: all 25 labels created, each with --force so a re-run
    # updates instead of failing.
    fake_gh.reset()
    created = setup_labels.setup_labels(fake_gh.run_gh, None)
    assert len(created) == 25
    assert fake_gh.LABELS_CREATED == setup_labels.label_names()
    for call in fake_gh.CALLS:
        if call[0] == "label":
            assert "--force" in call


def test_setup_refuses_public_repo_before_creating_anything():
    # Engagement data must never go to a public repo. The check must happen
    # before the first label, so a public repo is left completely untouched.
    fake_gh.reset()
    fake_gh.STATE["visibility"] = "PUBLIC"
    with pytest.raises(ValueError, match="PRIVATE"):
        setup_labels.setup_labels(fake_gh.run_gh, None)
    assert fake_gh.LABELS_CREATED == []


def test_gh_failure_raises():
    # If gh is not logged in, the error must surface, not be skipped.
    fake_gh.reset()
    fake_gh.STATE["fail_next"] = True
    with pytest.raises(RuntimeError):
        setup_labels.setup_labels(fake_gh.run_gh, None)


def test_repo_argument_is_validated_and_passed():
    # --repo must look like OWNER/REPO. A bare name would make gh act on the
    # wrong repository, or fail confusingly.
    assert setup_labels.repo_args("OWNER/REPO") == ["--repo", "OWNER/REPO"]
    assert setup_labels.repo_args(None) == []
    with pytest.raises(ValueError):
        setup_labels.repo_args("just-a-name")
