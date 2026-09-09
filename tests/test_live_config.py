"""The live planner's two optional knobs, workspace header and base URL,
reach the Anthropic client exactly as configured, and never touch the
network in the suite. We record the constructor call instead of calling it,
because the failure this guards against was silent: an org-level key that
is not workspace-scoped gets a 400 on every call, the workflow's safe
fallback turns that into DEFER_HUMAN, and a whole live run reads as "the
model defers everything" unless the header actually went out."""

from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture()
def recorded_client(monkeypatch):
    calls: list[dict] = []

    class FakeAnthropic:
        def __init__(self, **kwargs):
            calls.append(kwargs)

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    return calls


def test_workspace_header_and_base_url_reach_the_client(recorded_client):
    from helix.planner import LivePlanner

    LivePlanner("k", "m", timeout=5, base_url="http://127.0.0.1:11434", workspace_id="wrkspc_x")
    (kw,) = recorded_client
    assert kw["base_url"] == "http://127.0.0.1:11434"
    assert kw["default_headers"] == {"anthropic-workspace-id": "wrkspc_x"}
    assert kw["api_key"] == "k" and kw["timeout"] == 5


def test_defaults_send_neither_knob(recorded_client):
    from helix.planner import LivePlanner

    LivePlanner("k", "m")
    (kw,) = recorded_client
    assert "base_url" not in kw and "default_headers" not in kw


def test_settings_read_the_env_names(monkeypatch):
    monkeypatch.setenv("HELIX_ANTHROPIC_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("HELIX_ANTHROPIC_WORKSPACE_ID", "wrkspc_x")
    import helix.config as cfg

    cfg = importlib.reload(cfg)
    try:
        s = cfg.load_settings()
        assert s.anthropic_base_url == "http://127.0.0.1:11434"
        assert s.anthropic_workspace_id == "wrkspc_x"
    finally:
        monkeypatch.delenv("HELIX_ANTHROPIC_BASE_URL")
        monkeypatch.delenv("HELIX_ANTHROPIC_WORKSPACE_ID")
        importlib.reload(sys.modules["helix.config"])
