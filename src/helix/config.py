"""Runtime configuration, loaded from the HELIX_-prefixed environment.

The HELIX_ prefix is deliberate (provisioning.md): a bare ANTHROPIC_API_KEY in
a generic name in the environment could collide with another tool's
    credentials. We read only our own keys,
pass them explicitly to the client, and never print them. Missing live config
is a first-class state (live evaluation BLOCKED), never a reason to fake a pass.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

try:  # dotenv is optional at runtime; tests never rely on a .env
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass


@dataclass
class Settings:
    provider: str = os.environ.get("HELIX_LLM_PROVIDER", "anthropic")
    model: str = os.environ.get("HELIX_MODEL", "")
    api_key: str = os.environ.get("HELIX_ANTHROPIC_API_KEY", "")
    timezone: str = os.environ.get("HELIX_TIMEZONE", "UTC")
    max_steps: int = int(os.environ.get("HELIX_MAX_STEPS", "12"))
    # HELIX_TIMEOUT_SECONDS is the *model* client timeout (LivePlanner). The
    # adapter knobs below are separate on purpose: a hung Okta call and a slow
    # model reply are different failure budgets.
    timeout: float = float(os.environ.get("HELIX_TIMEOUT_SECONDS", "30"))
    # Two optional knobs for the same Anthropic-SDK planner. An org-level key
    # that is not scoped to a workspace is refused by the API unless every call
    # carries the workspace id header, so we let the operator supply it rather
    # than mint a new key. A base URL points the identical client at any
    # Messages-API-compatible host (a local Ollama serving a cloud model, a
    # gateway), "any LLM may be used" in the brief, and the planner code path
    # stays one thing. Neither is required; blank means api.anthropic.com.
    anthropic_base_url: str = os.environ.get("HELIX_ANTHROPIC_BASE_URL", "")
    anthropic_workspace_id: str = os.environ.get("HELIX_ANTHROPIC_WORKSPACE_ID", "")
    # Retry schedule for mutating adapter calls (R-59). Base 0.0 by default so
    # the test suite never sleeps; production sets something like 0.5. Jitter is
    # additive seconds on top of each delay, 0 keeps the schedule exact.
    backoff_base_seconds: float = float(os.environ.get("HELIX_BACKOFF_BASE_SECONDS", "0"))
    backoff_jitter_seconds: float = float(os.environ.get("HELIX_BACKOFF_JITTER_SECONDS", "0"))
    # Per-attempt wall-clock budget for one adapter call. 0 disables the
    # watchdog, and that is the right default for the in-process mock: its
    # single sqlite connection is bound to the creating thread, so running the
    # adapter on a watchdog thread would fail every call. Turn it on for real
    # network adapters.
    adapter_timeout_seconds: float = float(os.environ.get("HELIX_ADAPTER_TIMEOUT_SECONDS", "0"))

    @property
    def live_ready(self) -> bool:
        return bool(self.api_key and self.model)


def load_settings() -> Settings:
    return Settings()
