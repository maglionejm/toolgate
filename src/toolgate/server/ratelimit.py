import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    """A small in-process sliding-window rate limiter.

    Enough for a single-node MVP: the token endpoint and the gate share one
    event loop, but the test client drives them from threads, so the counter is
    guarded by a lock. Keyed by an arbitrary string (per-grant or per-agent).
    A distributed deployment would move this to Redis; see issue #16's scale
    path. This bounds request *rate*, complementing the per-grant cost budget
    which only bounds total spend.
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
