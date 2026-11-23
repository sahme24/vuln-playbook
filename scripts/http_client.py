"""Shared HTTP helpers for the enrichers: one GET function and one retry loop.

How the enrichers use this:
    Each enricher's fetch function takes `http_get` and `sleep_fn` as plain
    arguments. In real use they are live_get() below and time.sleep. The
    tests pass small hand-written functions instead (a fake GET that returns
    canned JSON, a fake sleep that only records how long it was asked to
    wait), so the retry and rate-limit logic is tested without any network
    access and without waiting.

Every http_get function returns a dict:
    {"status": <HTTP status code, or 0 if no response arrived>,
     "body":   <parsed JSON when status is 200, otherwise None>}

Status 0 stands for "no response at all" (connection refused, DNS failure,
timeout). It is retried like a server error. Both are usually temporary.
"""

import requests

# 403 and 429 are how NVD (and other APIs) say "slow down". The 5xx codes
# are temporary server problems (the Ubuntu CVE API often answers 504 under
# load). 0 means no response arrived. All of these are worth retrying.
RETRY_STATUSES = [0, 403, 429, 500, 502, 503, 504]

# 200 = found. 404 = "this API has no record of that CVE", which is a real
# answer (for example, Ubuntu does not track every CVE), not a failure.
ANSWER_STATUSES = [200, 404]

# Identify the tool honestly, without any personal details.
USER_AGENT = "vuln-playbook/1.0 (vulnerability assessment enrichment)"


def live_get(url, params, headers, timeout):
    """Perform a real HTTP GET. Only this function touches the network."""
    all_headers = {"User-Agent": USER_AGENT}
    if headers is not None:
        for name in headers:
            all_headers[name] = headers[name]
    try:
        response = requests.get(url, params=params, headers=all_headers, timeout=timeout)
    except requests.RequestException:
        return {"status": 0, "body": None}

    body = None
    if response.status_code == 200:
        try:
            body = response.json()
        except ValueError:
            raise RuntimeError("expected JSON from " + url + " but the response was not JSON")
    return {"status": response.status_code, "body": body}


def get_with_retry(url, params, headers, http_get, sleep_fn, max_attempts, base_delay):
    """GET a URL, retrying temporary failures with exponential backoff.

    Waits base_delay, then 2 x base_delay, then 4 x base_delay, ... between
    attempts. Doubling the wait gives a rate-limited or overloaded server
    more time to recover on each try, without hammering it.

    Returns the response dict for 200 and 404. Raises RuntimeError when the
    retries run out, or at once for a status that retrying cannot fix
    (for example 400 Bad Request, which means our request itself is wrong).
    """
    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")
    if (type(base_delay) is not float and type(base_delay) is not int) or base_delay < 0:
        raise ValueError("base_delay must be a non-negative number")

    attempt = 1
    delay = base_delay
    while True:
        response = http_get(url, params, headers, 30)
        status = response["status"]

        if status in ANSWER_STATUSES:
            return response
        if status not in RETRY_STATUSES:
            raise RuntimeError("GET " + url + " failed with HTTP " + str(status) + " (not retryable)")
        if attempt >= max_attempts:
            raise RuntimeError(
                "GET " + url + " still failing with HTTP " + str(status)
                + " after " + str(max_attempts) + " attempts"
            )
        sleep_fn(delay)
        delay = delay * 2
        attempt = attempt + 1
