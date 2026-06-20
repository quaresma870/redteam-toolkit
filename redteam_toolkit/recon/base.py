"""
Base class for recon modules. Every module's scan() must call
self.engagement.authorize_action(...) before any network action — the gate
lives in Engagement, but each module is responsible for actually calling it.

run() wraps scan() so a refused action (ScopeViolation) or any other error
becomes a reported ModuleResult.error rather than crashing whatever is
orchestrating multiple modules — the refusal itself was already logged by
the gate before it raised, so nothing about safety depends on what happens
to the exception afterward.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from redteam_toolkit.core.engagement import Engagement
from redteam_toolkit.core.models import Finding, ModuleResult


class BaseReconModule(ABC):
    name: str = "base"
    category: str = "recon"

    def __init__(self, engagement: Engagement):
        self.engagement = engagement

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        start = time.monotonic()
        try:
            findings = self.scan(target, **kwargs)
            result = ModuleResult(module=self.name, findings=findings)
        except Exception as exc:
            result = ModuleResult(module=self.name, error=str(exc))
        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    @abstractmethod
    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        """Implement the actual scan. Must call
        self.engagement.authorize_action(...) before any network action."""
