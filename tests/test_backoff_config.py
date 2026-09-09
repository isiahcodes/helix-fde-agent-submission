"""R-59 plumbing: the retry knobs are read from the HELIX_ environment and
reach the executor without anyone constructing a policy by hand.

Settings evaluates os.environ in its dataclass field defaults, i.e. once at
import. That is fine for a CLI process, but it means a test that wants to
prove the *names* of the variables has to reload the module after setting the
env. We do that here and nowhere else; the behavioural tests in
tests/test_recovery.py set the policy on the executor directly."""

from __future__ import annotations

import importlib

import pytest

import helix.config as config_module
from helix.executor import Executor, RetryPolicy


@pytest.fixture()
def reloaded_settings(monkeypatch):
    """Reload helix.config under a patched environment, then reload it again on
    teardown so the import-time defaults other tests rely on are restored."""

    def _load(*unset: str, **env: str):
        for k in unset:
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return importlib.reload(config_module).load_settings()

    yield _load
    monkeypatch.undo()
    importlib.reload(config_module)


def test_defaults_keep_tests_fast_and_mock_safe(reloaded_settings):
    # Base 0.0 (no sleeping in the suite) and timeout 0 (disabled) are the
    # defaults on purpose: the in-process mock owns a single sqlite connection
    # bound to the creating thread, so the thread-based watchdog stays off
    # unless someone opts in for a real network adapter.
    s = reloaded_settings("HELIX_BACKOFF_BASE_SECONDS", "HELIX_BACKOFF_JITTER_SECONDS",
                          "HELIX_ADAPTER_TIMEOUT_SECONDS")
    assert s.backoff_base_seconds == 0.0
    assert s.backoff_jitter_seconds == 0.0
    assert s.adapter_timeout_seconds == 0.0


def test_env_names_are_read(reloaded_settings):
    s = reloaded_settings(
        HELIX_BACKOFF_BASE_SECONDS="0.25",
        HELIX_BACKOFF_JITTER_SECONDS="0.05",
        HELIX_ADAPTER_TIMEOUT_SECONDS="7.5",
    )
    assert s.backoff_base_seconds == 0.25
    assert s.backoff_jitter_seconds == 0.05
    assert s.adapter_timeout_seconds == 7.5


def test_retry_policy_is_built_from_settings(reloaded_settings):
    s = reloaded_settings(
        HELIX_BACKOFF_BASE_SECONDS="0.25",
        HELIX_BACKOFF_JITTER_SECONDS="0.05",
        HELIX_ADAPTER_TIMEOUT_SECONDS="7.5",
    )
    policy = RetryPolicy.from_settings(s)
    assert policy == RetryPolicy(
        max_attempts=3, base_seconds=0.25, jitter_seconds=0.05, adapter_timeout_seconds=7.5
    )


def test_executor_default_policy_comes_from_settings(harness):
    # Agent builds Executor(world, audit) with no policy argument; the executor
    # must still carry a real RetryPolicy so the CLI path is config-driven too.
    ex = Executor(harness.world, harness.audit)
    assert isinstance(ex.retry, RetryPolicy)
    assert ex.retry.max_attempts == 3


def test_retry_policy_delay_schedule_is_exponential():
    # Pure function, no world needed: delay for attempt n is base * 2**(n-1)
    # plus jitter in [0, jitter]. Zero jitter gives the exact doubling series.
    p = RetryPolicy(base_seconds=0.1)
    assert [p.delay_for(a) for a in (1, 2, 3)] == pytest.approx([0.1, 0.2, 0.4])


def test_retry_policy_rejects_nonsense():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(base_seconds=-1)
    with pytest.raises(ValueError):
        RetryPolicy(jitter_seconds=-0.1)
    with pytest.raises(ValueError):
        RetryPolicy(adapter_timeout_seconds=-5)
