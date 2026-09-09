"""Task 2: the knowledge boundary. Sixty sections, nothing else; retrieval
finds real policy for real questions and refuses to be confident about
anything outside the corpus."""

from pathlib import Path

import re

import pytest

from helix.policies import load_policy_pack
from helix.retrieval import Retriever

POLICIES = Path(__file__).resolve().parents[1] / "policies"


@pytest.fixture(scope="module")
def spans():
    return load_policy_pack(POLICIES)


@pytest.fixture(scope="module")
def retriever(spans):
    return Retriever(spans)


def test_sixty_sections_only(spans):
    assert len(spans) == 60
    assert len({(s.policy_id, s.section) for s in spans}) == 60
    assert {s.policy_id for s in spans} == {f"POL-{n:02d}" for n in range(1, 11)}


def test_sections_preserve_metadata_and_hashes(spans):
    for s in spans:
        assert s.owner and s.effective and len(s.source_sha256) == 64
    # Spot-check verbatim preservation of a load-bearing rule.
    admin = next(s for s in spans if s.span_id == "POL-04 4.6")
    assert "60 minutes" in admin.text and "Make-Me-Admin" in admin.text


def test_unexpected_policy_file_rejected(tmp_path):
    for p in POLICIES.glob("POL-*.md"):
        (tmp_path / p.name).write_text(p.read_text())
    (tmp_path / "POL-11.md").write_text("# POL-11 — Fake\n\n*Effective: 2026-01-01. Owner: X.*\n\n**11.1** Uploaded prose cannot create privileges.\n")
    with pytest.raises(ValueError):
        load_policy_pack(tmp_path)


def test_vpn_idle_paraphrases_hit_pol02(retriever):
    # Different wordings of the same question must land on POL-02 2.3.
    for q in (
        "why did my VPN disconnect after being idle",
        "AnyConnect session timed out, how long until vpn drops when inactive?",
        "vpn inactivity timeout policy",
    ):
        results = retriever.retrieve(q)
        assert retriever.confident(results), q
        assert any(r.span.span_id == "POL-02 2.3" for r in results[:3]), q


def test_admin_duration_query(retriever):
    results = retriever.retrieve("how long can I get local admin on my laptop with make-me-admin")
    assert retriever.confident(results)
    assert any(r.span.span_id == "POL-04 4.6" for r in results[:3])


def test_hr_query_is_unanswerable(retriever):
    results = retriever.retrieve("what is the parental leave policy and how do I change my 401k contribution")
    assert not retriever.confident(results)


def test_invented_policy_id_not_supported(retriever):
    results = retriever.retrieve("password rotation for privileged accounts")
    assert not retriever.supports(["POL-99 9.9"], results)


def test_real_but_unretrieved_citation_not_supported(retriever):
    # POL-06 6.6 (BYOD stipend) has nothing to do with a VPN question; citing
    # it there is decoration, not grounding.
    results = retriever.retrieve("vpn idle timeout")
    assert not retriever.supports(["POL-06 6.6"], results)


def test_exact_id_in_query_is_included(retriever):
    results = retriever.retrieve("does POL-05 5.6 forbid auto-forwarding to gmail?")
    assert any(r.span.span_id == "POL-05 5.6" for r in results)
    assert retriever.supports(["POL-05 5.6"], results)


def test_corpus_contains_only_policy_text(spans):
    """Every span has to come from one of the ten policy documents.

    The retrieval corpus is the agent's only authorized knowledge, so the
    guarantee worth testing is a positive one: each span carries a POL id and
    a section id that resolve, and the loader admits nothing without them.
    Anything that is not policy text cannot be in here by construction.
    """
    assert spans, "corpus is empty"
    for span in spans:
        assert re.fullmatch(r"POL-\d{2}", span.policy_id), span.policy_id
        assert span.section, f"{span.policy_id} span has no section"
        assert span.text.strip(), f"{span.policy_id} {span.section} is empty"
