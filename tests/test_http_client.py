import pytest

import http_client

# The fake GET below answers from this list, one response per call, in
# order. Each test fills it first. SLEPT records every sleep request.
PLANNED = []
SLEPT = []


def fake_get(url, params, headers, timeout):
    return PLANNED.pop(0)


def fake_sleep(seconds):
    SLEPT.append(seconds)


def reset(responses):
    PLANNED.clear()
    SLEPT.clear()
    for response in responses:
        PLANNED.append(response)


def test_success_on_first_try_does_not_sleep():
    # Happy path: a 200 is returned straight away, with no needless waiting.
    reset([{"status": 200, "body": {"ok": True}}])
    response = http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 3, 6.0)
    assert response["body"] == {"ok": True}
    assert SLEPT == []


def test_429_then_success_backs_off():
    # NVD answers 429/403 when we go too fast. We must wait and retry, not fail
    # the whole verification over a temporary rate limit.
    reset([{"status": 429, "body": None}, {"status": 403, "body": None}, {"status": 200, "body": {}}])
    response = http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 5, 6.0)
    assert response["status"] == 200
    assert SLEPT == [6.0, 12.0]


def test_backoff_doubles_each_time():
    # Doubling gives an overloaded server more room on each try. A constant
    # short delay would keep hitting it during the outage.
    reset([
        {"status": 503, "body": None},
        {"status": 503, "body": None},
        {"status": 503, "body": None},
        {"status": 200, "body": {}},
    ])
    http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 4, 2.0)
    assert SLEPT == [2.0, 4.0, 8.0]


def test_gives_up_after_max_attempts():
    # An API that never recovers must end in a clear error, not an endless
    # loop or a silent "no data".
    reset([
        {"status": 504, "body": None},
        {"status": 504, "body": None},
        {"status": 504, "body": None},
    ])
    with pytest.raises(RuntimeError, match="after 3 attempts"):
        http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 3, 1.0)


def test_404_is_an_answer_not_an_error():
    # Ubuntu and Red Hat return 404 for CVEs they do not track. That is
    # information ("no record"), so it must not be retried or raised.
    reset([{"status": 404, "body": None}])
    response = http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 3, 1.0)
    assert response["status"] == 404
    assert SLEPT == []


def test_non_retryable_status_fails_immediately():
    # 400 means our request is wrong. Retrying cannot fix it and would only
    # waste rate-limit budget.
    reset([{"status": 400, "body": None}])
    with pytest.raises(RuntimeError, match="not retryable"):
        http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 3, 1.0)


def test_no_response_is_retried():
    # Status 0 (timeout, DNS failure) is usually a short network blip and
    # deserves the same retries as a server error.
    reset([{"status": 0, "body": None}, {"status": 200, "body": {}}])
    response = http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 3, 1.0)
    assert response["status"] == 200


def test_invalid_retry_settings_raise():
    # Zero attempts would never call the API, and a negative delay makes no
    # sense. Both are caller bugs.
    reset([])
    with pytest.raises(ValueError):
        http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 0, 1.0)
    with pytest.raises(ValueError):
        http_client.get_with_retry("https://x", None, None, fake_get, fake_sleep, 3, -1)
