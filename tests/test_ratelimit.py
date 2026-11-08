import pytest

from haris.net.ratelimit import TokenBucket

from .fake_transport import FakeClock


def test_rate_limit_spaces_requests():
    """Scenario: Rate limit (bucket half; client half is in test_scoped_client)."""
    clock = FakeClock()
    bucket = TokenBucket(2.0, clock, clock.sleep)
    start = clock()
    times = []
    for _ in range(10):
        bucket.acquire()
        times.append(clock() - start)

    assert times[:2] == [0.0, 0.0]
    assert times[9] == pytest.approx(4.0)


@pytest.mark.parametrize(("rate", "burst"), [(0.5, 1), (1.0, 1), (2.0, 2), (2.5, 3)])
def test_capacity_is_ceil_of_rate_with_minimum_one(rate, burst):
    clock = FakeClock()
    bucket = TokenBucket(rate, clock, clock.sleep)
    for _ in range(burst):
        bucket.acquire()
    assert clock.sleeps == []
    bucket.acquire()
    assert clock.sleeps == [pytest.approx(1 / rate)]


def test_idle_time_refills_up_to_capacity_only():
    clock = FakeClock()
    bucket = TokenBucket(2.0, clock, clock.sleep)
    clock.now += 3600
    for _ in range(2):
        bucket.acquire()
    assert clock.sleeps == []
    bucket.acquire()
    assert clock.sleeps == [pytest.approx(0.5)]


def test_halve_rate_has_a_floor():
    bucket = TokenBucket(4.0)
    bucket.halve_rate()
    assert bucket.rate == 2.0
    for _ in range(10):
        bucket.halve_rate()
    assert bucket.rate == pytest.approx(0.1)
