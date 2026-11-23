"""SQLite cache for every external API response.

Why cache at all:
  - The NVD API allows only 5 requests per 30 seconds without a key. Looking
    up the same CVE twice (two verifiers, a re-run, a second plugin with the
    same CVE) should not cost a second request.
  - The KEV catalog is a ~2 MB download. The spec says to fetch it once per
    run and match locally.
  - Re-running a step gives the same answer as long as the cached data is
    fresh, which makes results easier to reproduce.

Layout: one table, one row per (source, key).
    source   which API, e.g. "nvd", "kev", "epss", "vendor_ubuntu"
    key      what was looked up, usually a CVE ID ("catalog" for the KEV feed)
    fetched  when the response was stored, in seconds since the epoch
    body     the raw response, as JSON text

Each source has a time-to-live (TTL). A row older than its TTL counts as a
miss, so it is fetched again. The raw response is stored, not our parsed
version. If the parser changes, cached data can be re-parsed without
fetching it again.

The functions take `now` as an argument instead of reading the clock
themselves, so expiry can be tested with fixed times.

Several verifier instances may run at once and share cache.db. SQLite
handles this with file locking. The `timeout` makes a writer wait for
another writer to finish instead of failing straight away.
"""

import json
import sqlite3

DAY = 24 * 60 * 60

# KEV and EPSS are republished daily. NVD records change more slowly. Vendor
# fix status can change the day a patch ships, so it gets one day too.
TTL_SECONDS = {
    "nvd": 7 * DAY,
    "kev": 1 * DAY,
    "epss": 1 * DAY,
    "vendor_ubuntu": 1 * DAY,
    "vendor_redhat": 1 * DAY,
    "vendor_msrc": 1 * DAY,
}


def validate_source(source):
    if type(source) is not str or source not in TTL_SECONDS:
        raise ValueError(
            "unknown cache source " + repr(source) + "; expected one of: " + ", ".join(TTL_SECONDS)
        )


def validate_key(key):
    if type(key) is not str or key.strip() == "":
        raise ValueError("cache key must be a non-empty string, got " + repr(key))


def validate_now(now):
    if type(now) is not float and type(now) is not int:
        raise ValueError("now must be a number of seconds since the epoch, got " + repr(now))


def open_cache(path):
    """Open (or create) the cache database and return the connection.
    Pass ":memory:" for a throwaway in-memory cache, which the tests use."""
    if type(path) is not str or path == "":
        raise ValueError("cache path must be a non-empty string")
    connection = sqlite3.connect(path, timeout=30)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS api_cache ("
        " source TEXT NOT NULL,"
        " key TEXT NOT NULL,"
        " fetched REAL NOT NULL,"
        " body TEXT NOT NULL,"
        " PRIMARY KEY (source, key))"
    )
    connection.commit()
    return connection


def cache_get(connection, source, key, now):
    """Return the cached response for (source, key), or None on a miss.

    A miss means either "never stored" or "stored but older than the TTL".
    Here None is the normal answer to "is it cached?", not an error. The
    caller fetches the data and calls cache_put().
    """
    validate_source(source)
    validate_key(key)
    validate_now(now)
    # The "?" placeholders let sqlite3 insert the values safely. Building the
    # SQL with string concatenation would break on (or be exploitable by)
    # unusual characters in the key.
    row = connection.execute(
        "SELECT fetched, body FROM api_cache WHERE source = ? AND key = ?", (source, key)
    ).fetchone()
    if row is None:
        return None
    fetched = row[0]
    age = now - fetched
    if age > TTL_SECONDS[source]:
        return None
    return json.loads(row[1])


def cache_put(connection, source, key, body, now):
    """Store a response, replacing any older copy. Returns True."""
    validate_source(source)
    validate_key(key)
    validate_now(now)
    if type(body) is not dict and type(body) is not list:
        raise ValueError("cached body must be a JSON object or array (dict or list)")
    connection.execute(
        "INSERT OR REPLACE INTO api_cache (source, key, fetched, body) VALUES (?, ?, ?, ?)",
        (source, key, float(now), json.dumps(body)),
    )
    connection.commit()
    return True
