import os
import tempfile

import pytest

import cache

DAY = 24 * 60 * 60
START = 1796134200.0   # an arbitrary fixed "now" (2026-12-01)


def test_put_then_get_returns_same_body():
    # Happy path: whatever we store must come back unchanged, or cached
    # answers would differ from live ones.
    connection = cache.open_cache(":memory:")
    body = {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}
    assert cache.cache_put(connection, "nvd", "CVE-2021-44228", body, START) is True
    assert cache.cache_get(connection, "nvd", "CVE-2021-44228", START + 60) == body


def test_missing_entry_is_a_miss():
    # A CVE never looked up must give None, so the caller knows to fetch it.
    connection = cache.open_cache(":memory:")
    assert cache.cache_get(connection, "nvd", "CVE-2021-44228", START) is None


def test_ttl_expiry_per_source():
    # KEV and EPSS change daily, NVD more slowly. Serving a 2-day-old KEV
    # catalog could miss a CVE added yesterday, while a 2-day-old NVD record
    # is still fine.
    connection = cache.open_cache(":memory:")
    cache.cache_put(connection, "kev", "catalog", {"vulnerabilities": []}, START)
    cache.cache_put(connection, "nvd", "CVE-2021-44228", {"vulnerabilities": []}, START)
    two_days_later = START + 2 * DAY
    assert cache.cache_get(connection, "kev", "catalog", two_days_later) is None
    assert cache.cache_get(connection, "nvd", "CVE-2021-44228", two_days_later) is not None
    assert cache.cache_get(connection, "nvd", "CVE-2021-44228", START + 8 * DAY) is None


def test_ttl_boundary_is_inclusive():
    # Exactly at the TTL the entry is still fresh, and one second later it is
    # not. This pins the off-by-one behaviour so it cannot drift.
    connection = cache.open_cache(":memory:")
    cache.cache_put(connection, "epss", "CVE-2021-44228", {"epss": "0.9"}, START)
    assert cache.cache_get(connection, "epss", "CVE-2021-44228", START + DAY) is not None
    assert cache.cache_get(connection, "epss", "CVE-2021-44228", START + DAY + 1) is None


def test_put_replaces_older_copy():
    # Refreshing an expired entry must overwrite it, not keep two rows where
    # the stale one might be read.
    connection = cache.open_cache(":memory:")
    cache.cache_put(connection, "epss", "CVE-2021-44228", {"epss": "0.1"}, START)
    cache.cache_put(connection, "epss", "CVE-2021-44228", {"epss": "0.9"}, START + 2 * DAY)
    assert cache.cache_get(connection, "epss", "CVE-2021-44228", START + 2 * DAY) == {"epss": "0.9"}


def test_sources_are_kept_apart():
    # The same CVE key under two sources must not overwrite each other. NVD
    # and EPSS data for CVE-X are different things.
    connection = cache.open_cache(":memory:")
    cache.cache_put(connection, "nvd", "CVE-2021-44228", {"from": "nvd"}, START)
    cache.cache_put(connection, "epss", "CVE-2021-44228", {"from": "epss"}, START)
    assert cache.cache_get(connection, "nvd", "CVE-2021-44228", START) == {"from": "nvd"}


def test_cache_survives_reopening_file():
    # The point of cache.db is to persist between runs, so data written
    # by one process must be readable after reopening the file.
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "cache.db")
        first = cache.open_cache(path)
        cache.cache_put(first, "nvd", "CVE-2021-44228", {"ok": True}, START)
        first.close()
        second = cache.open_cache(path)
        assert cache.cache_get(second, "nvd", "CVE-2021-44228", START) == {"ok": True}
        second.close()


def test_unknown_source_raises():
    # A typo like "nvdd" would otherwise create a source with no TTL rule.
    connection = cache.open_cache(":memory:")
    with pytest.raises(ValueError):
        cache.cache_put(connection, "nvdd", "CVE-2021-44228", {}, START)
    with pytest.raises(ValueError):
        cache.cache_get(connection, "nvdd", "CVE-2021-44228", START)


def test_bad_key_body_and_time_raise():
    # Empty keys, non-JSON bodies and a string "now" are caller bugs that
    # would corrupt the cache or break expiry maths.
    connection = cache.open_cache(":memory:")
    with pytest.raises(ValueError):
        cache.cache_put(connection, "nvd", "", {}, START)
    with pytest.raises(ValueError):
        cache.cache_put(connection, "nvd", "CVE-2021-44228", "not a dict", START)
    with pytest.raises(ValueError):
        cache.cache_get(connection, "nvd", "CVE-2021-44228", "now")


def test_key_with_quote_is_stored_safely():
    # Keys go into SQL through placeholders. A quote in a key must be stored
    # as data, not break (or alter) the SQL statement.
    connection = cache.open_cache(":memory:")
    cache.cache_put(connection, "nvd", "x' OR '1'='1", {"safe": True}, START)
    assert cache.cache_get(connection, "nvd", "x' OR '1'='1", START) == {"safe": True}
    assert cache.cache_get(connection, "nvd", "CVE-2021-44228", START) is None
