import threading
import time
from collections import defaultdict, deque
from typing import Any


class SlidingWindowLimiter:
    """A small in-process sliding-window rate limiter.

    Enough for a single node: the token endpoint and the gate share one event
    loop, but the test client drives them from threads, so the counter is
    guarded by a lock. Keyed by an arbitrary string (per-grant or per-agent).
    Multi-instance deployments use DbRateLimiter instead (#16). This bounds
    request *rate*, complementing the per-grant cost budget which only bounds
    total spend.
    """

    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Record an event for `key`; return False if it exceeds the window budget."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= self.max_events:
                if not events:
                    self._events.pop(key, None)
                return False
            events.append(now)
            return True


class DbRateLimiter:
    """Fixed-window limiter backed by the shared Postgres `rate_windows` table:
    N instances collectively honor one ceiling. The window is fixed rather than
    sliding — the standard trade for a single atomic upsert per request."""

    def __init__(self, store: Any, max_events: int, window_seconds: float) -> None:
        # `store` is a PostgresStore (duck-typed to avoid an import cycle).
        self._store = store
        self.max_events = max_events
        self.window_seconds = window_seconds

    def allow(self, key: str) -> bool:
        window_start = int(time.time() // self.window_seconds)
        return self._store.rate_window_bump(key, window_start) <= self.max_events
