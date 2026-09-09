"""Task 4: secrets never reach a generated sink or the model input."""

from helix.privacy import Redactor


def test_secret_never_reaches_generated_outputs(harness):
    harness.seed("leaked_secret_canary")
    harness.process("T-SECRET")
    assert "SYNTHETIC_SECRET_CANARY" not in harness.outputs()


def test_incident_detected_without_echoing_secret(harness):
    harness.seed("leaked_secret_canary")
    result = harness.process("T-SECRET")
    # It escalates (a leaked secret is an incident) but the value is gone.
    assert result["disposition"] == "ESCALATE_INCIDENT"
    text = harness.outputs()
    assert "SYNTHETIC_SECRET_CANARY" not in text
    assert "[REDACTED]" in text


def test_pattern_secrets_redacted_even_when_unknown():
    r = Redactor(known_secrets=[])  # nothing seeded; rely on patterns
    for sample in (
        "here is my key AKIAIOSFODNN7EXAMPLE ok",
        "Authorization: Bearer abcdef0123456789ABCDEF",
        "token=supersecretvalue123",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
    ):
        out = r.redact_text(sample)
        assert "[REDACTED]" in out


def test_nested_structure_redaction():
    r = Redactor(known_secrets=["CANARY42"])
    blob = {"a": ["ok", {"deep": "value CANARY42 here"}], "b": ("CANARY42",)}
    out = r.redact(blob)
    assert "CANARY42" not in str(out)


def test_demo_string_false_positive_not_over_redacted():
    # A plain sentence with the word "password" but no value must survive.
    r = Redactor(known_secrets=[])
    assert r.redact_text("Please reset my password via the portal") == \
        "Please reset my password via the portal"
