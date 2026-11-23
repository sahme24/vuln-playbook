import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

import scope

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
ENGAGEMENT_FILE = os.path.join(FIXTURES, "engagement_test.yaml")

# The fixture window is 2026-12-01 09:00 to 2026-12-05 17:00 at UTC-5.
EST = timezone(timedelta(hours=-5))


def make_scope(include, exclude):
    """Build a scope dict the same way the scripts do, from plain lists."""
    return scope.build_scope({"scope": {"include": include, "exclude": exclude}})


def make_window(start, end):
    """A minimal engagement dict holding only the window fields."""
    return {"engagement": {"window_start": start, "window_end": end}}


def write_temp_file(folder, name, text):
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


# --- load_engagement ---------------------------------------------------------

def test_load_engagement_reads_all_sections():
    # Every script starts by loading engagement.yaml. If the happy path broke,
    # nothing else in the pipeline could run.
    data = scope.load_engagement(ENGAGEMENT_FILE)
    assert data["engagement"]["client"] == "Example Corp"
    assert data["scope"]["include"] == ["192.0.2.0/24", "198.51.100.0/24"]


def test_load_engagement_missing_file_raises():
    # A typo in the path must stop the run. Carrying on with an empty
    # scope would hide the real problem.
    with pytest.raises(ValueError):
        scope.load_engagement(os.path.join(FIXTURES, "does_not_exist.yaml"))


def test_load_engagement_non_string_path_raises():
    # A wrong-typed argument is a programming mistake. It should fail with
    # a clear ValueError, not a confusing error from inside os.path.
    with pytest.raises(ValueError):
        scope.load_engagement(123)


def test_load_engagement_missing_section_raises():
    # A file without an 'approval' section would let code read a missing
    # approval flag later. Rejecting the file up front closes that gap.
    with tempfile.TemporaryDirectory() as folder:
        path = write_temp_file(
            folder, "e.yaml",
            "engagement: {}\nscope: {include: [], exclude: []}\nscanning: {}\nreporting: {}\n",
        )
        with pytest.raises(ValueError):
            scope.load_engagement(path)


def test_load_engagement_non_mapping_raises():
    # A YAML file holding a list instead of a mapping is not an engagement
    # file at all. It must be refused, not half-read.
    with tempfile.TemporaryDirectory() as folder:
        path = write_temp_file(folder, "e.yaml", "- just\n- a list\n")
        with pytest.raises(ValueError):
            scope.load_engagement(path)


# --- parse_scope_entry -------------------------------------------------------

def test_parse_scope_entry_accepts_ip_and_cidr():
    # Scope lists mix single hosts and ranges. A single IP must become a
    # one-address network so the include/exclude logic treats both the same.
    assert str(scope.parse_scope_entry("192.0.2.0/24")) == "192.0.2.0/24"
    assert str(scope.parse_scope_entry("192.0.2.10")) == "192.0.2.10/32"
    assert str(scope.parse_scope_entry("2001:db8::/32")) == "2001:db8::/32"


def test_parse_scope_entry_rejects_hostname():
    # A hostname can resolve to a different, unauthorized address later. Scope
    # is only safe when it is pinned to IPs, so hostnames are refused.
    with pytest.raises(ValueError):
        scope.parse_scope_entry("web01.example.test")


def test_parse_scope_entry_rejects_host_bits_set():
    # "192.0.2.5/24" is ambiguous: the whole /24, or just .5? Guessing wrong
    # could authorize 255 extra hosts, so we refuse instead.
    with pytest.raises(ValueError):
        scope.parse_scope_entry("192.0.2.5/24")


def test_parse_scope_entry_rejects_wrong_types_and_empty():
    # YAML turns unquoted values into numbers or None. Those must not slip
    # through as "no restriction". Each one is an error.
    with pytest.raises(ValueError):
        scope.parse_scope_entry(24)
    with pytest.raises(ValueError):
        scope.parse_scope_entry(None)
    with pytest.raises(ValueError):
        scope.parse_scope_entry("   ")


def test_parse_scope_entry_rejects_invalid_octet():
    # 192.0.2.256 is not a real address. A typo like this must be caught
    # when the scope is loaded, not discovered halfway through a scan.
    with pytest.raises(ValueError):
        scope.parse_scope_entry("192.0.2.256")


# --- build_scope -------------------------------------------------------------

def test_build_scope_from_fixture():
    # The scope built from the fixture is what every other test and the dry
    # run depend on, so check its exact contents.
    built = scope.build_scope(scope.load_engagement(ENGAGEMENT_FILE))
    assert len(built["include"]) == 2
    assert len(built["exclude"]) == 1
    assert str(built["exclude"][0]) == "192.0.2.250/32"


def test_build_scope_empty_include_raises():
    # An empty include list means "nothing is authorized". That is always a
    # mistake in the file, never a real engagement, so it must be loud.
    with pytest.raises(ValueError):
        make_scope([], [])


def test_build_scope_exclude_none_raises():
    # In YAML, "exclude:" with nothing after it becomes None. Refusing it
    # forces the user to write [] and say plainly that nothing is excluded.
    with pytest.raises(ValueError):
        scope.build_scope({"scope": {"include": ["192.0.2.0/24"], "exclude": None}})


def test_build_scope_missing_key_raises():
    # A scope with no 'exclude' key might mean the user forgot the
    # exclusions the client asked for. Refuse rather than assume there are none.
    with pytest.raises(ValueError):
        scope.build_scope({"scope": {"include": ["192.0.2.0/24"]}})


def test_build_scope_bad_entry_raises():
    # One bad entry poisons the whole scope. Silently skipping it could
    # drop an exclude entry and put a forbidden host back in scope.
    with pytest.raises(ValueError):
        make_scope(["192.0.2.0/24"], ["printer01"])


# --- check_in_scope ----------------------------------------------------------

def test_check_in_scope_accepts_included_ip():
    # Happy path: a host inside an include range and not excluded is allowed.
    allowed = make_scope(["192.0.2.0/24", "198.51.100.0/24"], ["192.0.2.250"])
    assert scope.check_in_scope("192.0.2.10", allowed) is True
    assert scope.check_in_scope("198.51.100.20", allowed) is True


def test_check_in_scope_range_boundaries():
    # Off-by-one bugs live at range edges. The first and last addresses of
    # the /24 are in, and the very next address after it is out.
    allowed = make_scope(["192.0.2.0/24"], [])
    assert scope.check_in_scope("192.0.2.0", allowed) is True
    assert scope.check_in_scope("192.0.2.255", allowed) is True
    with pytest.raises(ValueError):
        scope.check_in_scope("192.0.3.0", allowed)


def test_check_in_scope_outside_include_raises():
    # This is the core safety rule: a host the client never authorized must
    # be refused before any packet is sent.
    allowed = make_scope(["192.0.2.0/24"], [])
    with pytest.raises(ValueError, match="not inside any include"):
        scope.check_in_scope("203.0.113.50", allowed)


def test_check_in_scope_exclude_wins_over_include():
    # Exclusions usually protect fragile or third-party devices inside an
    # authorized range. Exclude must override include, or that protection is gone.
    allowed = make_scope(["192.0.2.0/24"], ["192.0.2.250"])
    with pytest.raises(ValueError, match="exclude"):
        scope.check_in_scope("192.0.2.250", allowed)


def test_check_in_scope_rejects_hostname_and_wrong_type():
    # A hostname cannot be checked against IP ranges, and a number is not an
    # IP. Both must fail instead of being treated as "probably fine".
    allowed = make_scope(["192.0.2.0/24"], [])
    with pytest.raises(ValueError):
        scope.check_in_scope("web01.example.test", allowed)
    with pytest.raises(ValueError):
        scope.check_in_scope(3221225994, allowed)


def test_check_in_scope_rejects_raw_yaml_scope():
    # Passing the raw YAML section (strings, not networks) by mistake must fail
    # loudly. Comparing an address to strings would give wrong answers.
    raw = {"include": ["192.0.2.0/24"], "exclude": []}
    with pytest.raises(ValueError):
        scope.check_in_scope("192.0.2.10", raw)


def test_check_in_scope_ipv6():
    # IPv6 is supported, and an IPv4 address must never match an IPv6-only
    # scope (or the reverse) just because the comparison was skipped.
    allowed = make_scope(["2001:db8::/32"], [])
    assert scope.check_in_scope("2001:db8::10", allowed) is True
    with pytest.raises(ValueError):
        scope.check_in_scope("192.0.2.10", allowed)


# --- check_network_in_scope --------------------------------------------------

def test_check_network_returns_overlapping_excludes():
    # nmap scans ranges. Excluded hosts inside an allowed range must be passed
    # back so the caller can give them to nmap --exclude.
    allowed = make_scope(["192.0.2.0/24"], ["192.0.2.250", "198.51.100.7"])
    assert scope.check_network_in_scope("192.0.2.0/24", allowed) == ["192.0.2.250/32"]


def test_check_network_with_no_overlap_returns_empty_list():
    # When no exclude entry touches the range, the answer is an empty list,
    # a real value meaning "nothing to skip", not None.
    allowed = make_scope(["198.51.100.0/24"], ["198.51.100.200"])
    assert scope.check_network_in_scope("198.51.100.0/25", allowed) == []


def test_check_network_partly_outside_include_raises():
    # 192.0.2.0/23 also covers 192.0.3.0/24, which is not authorized. A range
    # that is only half in scope must be refused as a whole.
    allowed = make_scope(["192.0.2.0/24"], [])
    with pytest.raises(ValueError):
        scope.check_network_in_scope("192.0.2.0/23", allowed)


def test_check_network_entirely_excluded_raises():
    # If every address in the range is excluded, there is nothing we may
    # scan. Starting nmap anyway would be a scope violation waiting to happen.
    allowed = make_scope(["192.0.2.0/24"], ["192.0.2.128/25"])
    with pytest.raises(ValueError):
        scope.check_network_in_scope("192.0.2.192/26", allowed)


def test_check_network_rejects_non_string():
    # Same type discipline as single IPs: a non-string range is a bug in the
    # caller and must not be quietly converted.
    allowed = make_scope(["192.0.2.0/24"], [])
    with pytest.raises(ValueError):
        scope.check_network_in_scope(None, allowed)


# --- check_in_window ---------------------------------------------------------

def test_check_in_window_inside():
    # Happy path: a time in the middle of the window is allowed.
    engagement = scope.load_engagement(ENGAGEMENT_FILE)
    now = datetime(2026, 12, 2, 12, 0, tzinfo=EST)
    assert scope.check_in_window(engagement, now) is True


def test_check_in_window_boundaries_are_inclusive():
    # The authorization covers the stated start and end moments themselves.
    # Refusing at exactly 09:00 would surprise the operator.
    engagement = scope.load_engagement(ENGAGEMENT_FILE)
    assert scope.check_in_window(engagement, datetime(2026, 12, 1, 9, 0, tzinfo=EST)) is True
    assert scope.check_in_window(engagement, datetime(2026, 12, 5, 17, 0, tzinfo=EST)) is True


def test_check_in_window_before_and_after_raise():
    # Scanning outside the agreed window can trigger the client's incident
    # response or break a change freeze. One second outside is already a violation.
    engagement = scope.load_engagement(ENGAGEMENT_FILE)
    with pytest.raises(ValueError, match="starts"):
        scope.check_in_window(engagement, datetime(2026, 12, 1, 8, 59, 59, tzinfo=EST))
    with pytest.raises(ValueError, match="ended"):
        scope.check_in_window(engagement, datetime(2026, 12, 5, 17, 0, 1, tzinfo=EST))


def test_check_in_window_compares_across_timezones():
    # An operator in UTC and a client in UTC-5 must agree on what "inside"
    # means. 14:00 UTC is 09:00 at UTC-5, the exact window start.
    engagement = scope.load_engagement(ENGAGEMENT_FILE)
    now = datetime(2026, 12, 1, 14, 0, tzinfo=timezone.utc)
    assert scope.check_in_window(engagement, now) is True


def test_check_in_window_end_before_start_raises():
    # A window that ends before it starts is a typo (often swapped dates).
    # Every scan would be refused anyway, so say exactly what is wrong.
    engagement = make_window("2026-12-05T09:00:00-05:00", "2026-12-01T09:00:00-05:00")
    with pytest.raises(ValueError, match="after"):
        scope.check_in_window(engagement, datetime(2026, 12, 2, tzinfo=EST))


def test_check_in_window_requires_utc_offset():
    # "2026-12-01T09:00" without an offset means a different moment in every
    # timezone, so the window would be ambiguous. It must be refused.
    engagement = make_window("2026-12-01T09:00:00", "2026-12-05T17:00:00")
    with pytest.raises(ValueError, match="offset"):
        scope.check_in_window(engagement, datetime(2026, 12, 2, tzinfo=EST))


def test_check_in_window_rejects_naive_now_and_garbage():
    # A naive "now" or an unparseable window would make the comparison
    # meaningless. Both are errors, never a pass.
    engagement = scope.load_engagement(ENGAGEMENT_FILE)
    with pytest.raises(ValueError):
        scope.check_in_window(engagement, datetime(2026, 12, 2, 12, 0))
    with pytest.raises(ValueError):
        scope.check_in_window(make_window("next tuesday", "2026-12-05T17:00:00-05:00"),
                              datetime(2026, 12, 2, tzinfo=EST))


def test_check_in_window_accepts_unquoted_yaml_datetimes():
    # If the user forgets the quotes, PyYAML hands us datetime objects instead
    # of strings. That is still a valid window and must work the same way.
    start = datetime(2026, 12, 1, 9, 0, tzinfo=EST)
    end = datetime(2026, 12, 5, 17, 0, tzinfo=EST)
    assert scope.check_in_window(make_window(start, end), datetime(2026, 12, 3, tzinfo=EST)) is True


# --- check_approved ----------------------------------------------------------

def make_approval(flag, approved_at):
    return {"approval": {"scope_approved": flag, "approved_at": approved_at}}


def test_check_approved_accepts_true_with_timestamp():
    # Happy path: the human set the flag and recorded when. Scans may proceed.
    assert scope.check_approved(make_approval(True, "2026-11-30T16:00:00-05:00")) is True


def test_check_approved_refuses_false():
    # The core safety gate: until the human approves the scope, no scan may
    # run, whatever a prompt or agent says.
    with pytest.raises(ValueError, match="not approved"):
        scope.check_approved(make_approval(False, ""))


def test_check_approved_refuses_string_true():
    # "true" in quotes is a string, not a YAML boolean. Accepting it would let
    # a hand-edit that skipped the documented process pass the gate.
    with pytest.raises(ValueError, match="boolean"):
        scope.check_approved(make_approval("true", "2026-11-30T16:00:00-05:00"))


def test_check_approved_requires_approval_time():
    # Every approval needs a recorded time for the audit trail. A true flag
    # with an empty approved_at is incomplete and refused.
    with pytest.raises(ValueError):
        scope.check_approved(make_approval(True, ""))


def test_check_approved_missing_section_raises():
    # No approval section at all must never be read as "approved".
    with pytest.raises(ValueError):
        scope.check_approved({"engagement": {}})


# --- validate_engagement (intake) ---------------------------------------------

def fixture_engagement():
    """A fresh copy of the fixture engagement each call, so one test's edits
    can never leak into another test."""
    return scope.load_engagement(ENGAGEMENT_FILE)


def test_validate_engagement_accepts_fixture():
    # The intake prompt runs this on every file it writes. A valid file must
    # pass and come back as a summary the human can review.
    summary = scope.validate_engagement(fixture_engagement())
    assert summary["include"] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert summary["exclude"] == ["192.0.2.250/32"]
    assert summary["window_start"] == "2026-12-01T09:00:00-05:00"


def test_validate_engagement_requires_authorization():
    # No named authorizer or reference means no proof testing was allowed.
    # That must stop the intake, not be discovered after the scan.
    data = fixture_engagement()
    data["engagement"]["authorized_by"] = "  "
    with pytest.raises(ValueError, match="authorized_by"):
        scope.validate_engagement(data)
    data = fixture_engagement()
    del data["engagement"]["authorization_reference"]
    with pytest.raises(ValueError, match="authorization_reference"):
        scope.validate_engagement(data)


def test_validate_engagement_window_order():
    # A window that ends before it starts can never be satisfied. Catch it at
    # intake instead of at the first scan attempt.
    data = fixture_engagement()
    data["engagement"]["window_end"] = "2026-11-30T17:00:00-05:00"
    with pytest.raises(ValueError, match="after window_start"):
        scope.validate_engagement(data)


def test_validate_engagement_exclude_same_as_include():
    # An entry in both lists is contradictory: the client can't both
    # authorize and forbid the same range.
    data = fixture_engagement()
    data["scope"]["exclude"] = ["198.51.100.0/24"]
    with pytest.raises(ValueError, match="both include and exclude"):
        scope.validate_engagement(data)


def test_validate_engagement_exclude_swallows_include():
    # An exclude that contains a whole include entry leaves that entry with
    # nothing to test, which is almost certainly a mistake.
    data = fixture_engagement()
    data["scope"]["include"] = ["192.0.2.0/25"]
    data["scope"]["exclude"] = ["192.0.2.0/24"]
    with pytest.raises(ValueError, match="covers the whole include"):
        scope.validate_engagement(data)


def test_validate_engagement_exclude_outside_include():
    # An exclude outside every include does nothing. Usually it's a typo
    # for a host the client wanted protected, which would then get scanned.
    data = fixture_engagement()
    data["scope"]["exclude"] = ["203.0.113.5"]
    with pytest.raises(ValueError, match="not inside any include"):
        scope.validate_engagement(data)


def test_validate_engagement_choice_fields():
    # Agents branch on these values (Nmap profile, report audience). An
    # unknown value would fail later in a less obvious place.
    data = fixture_engagement()
    data["scanning"]["nmap_profile"] = "aggressive"
    with pytest.raises(ValueError, match="nmap_profile"):
        scope.validate_engagement(data)
    data = fixture_engagement()
    data["reporting"]["framework"] = "SOC 2"
    with pytest.raises(ValueError, match="framework"):
        scope.validate_engagement(data)
    data = fixture_engagement()
    data["scanning"]["credentialed"] = "no"
    with pytest.raises(ValueError, match="credentialed"):
        scope.validate_engagement(data)


def test_validate_engagement_sla_values():
    # SLA days produce the due dates in the report. Zero, negative, or True
    # (which Python treats as 1) would give wrong deadlines.
    for bad in [0, -5, True, "30"]:
        data = fixture_engagement()
        data["reporting"]["severity_sla"]["high"] = bad
        with pytest.raises(ValueError, match="severity_sla.high"):
            scope.validate_engagement(data)


def test_validate_engagement_approval_must_be_boolean():
    # "true" in quotes is a string, not approval. The intake must flag it
    # now, because the scan gate would refuse it later anyway.
    data = fixture_engagement()
    data["approval"]["scope_approved"] = "false"
    with pytest.raises(ValueError, match="scope_approved"):
        scope.validate_engagement(data)


def test_nmap_profiles_match_discovery_script():
    # scope.py keeps its own copy of the profile names (to avoid a circular
    # import). It must stay in step with nmap_discovery.py.
    import nmap_discovery
    names = []
    for name in nmap_discovery.PROFILES:
        names.append(name)
    assert names == scope.NMAP_PROFILES
