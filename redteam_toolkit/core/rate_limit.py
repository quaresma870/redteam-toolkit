"""
Simple fixed-interval rate limiter shared by recon modules that send many
requests in a loop (port scanning, DNS wordlist brute forcing, endpoint
discovery). Conservative defaults everywhere — a higher rate requires
explicit opt-in (e.g. --aggressive), never a silent default.
"""

from __future__ import annotations

import time


class RateLimiter:
    def __init__(self, max_per_second: float):
        self.max_per_second = max_per_second
        self._min_interval = 1.0 / max_per_second if max_per_second > 0 else 0.0
        self._last_call: float | None = None

    def wait(self) -> None:
        """Block just long enough to keep the call rate at or below the configured ceiling."""
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        if self._last_call is not None:
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
        self._last_call = time.monotonic()
