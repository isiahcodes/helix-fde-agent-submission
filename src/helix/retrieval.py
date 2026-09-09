"""Authorized retrieval and citation-support validation.

Lexical BM25 over the 60 policy sections plus exact span-id matching (D-28).
Deliberately no vector store: the corpus is 60 short paragraphs, and a
transparent scorer makes the confidence threshold explainable at review.
Dense retrieval is a measured-gap upgrade, not a default.

Two distinct jobs live here and must not be conflated:
  1. retrieve(): which sections are worth showing the planner.
  2. supports(): whether a cited section actually backs a claim. Citation
     existence alone is NOT support (implementation plan, Task 2): the cited
     span must also have scored as relevant for this ticket text, otherwise
     the planner is decorating an answer with a plausible-looking id.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rank_bm25 import BM25Okapi

from helix.models import PolicySpan

_SPAN_ID = re.compile(r"\bPOL-\d{2}\s+\d+\.\d+\b")
_TOKEN = re.compile(r"[a-z0-9]+")

# Function words carry no policy meaning but inflate BM25 scores enough to
# make an HR question look answerable. Small, fixed, reviewable list.
_STOPWORDS = frozenset(
    "the a an is are was were be been being do does did how what when where "
    "why who which can could may might will would shall should i my me we our "
    "you your it its to of for in on at by with and or not no from as this "
    "that these those there here get got need needs want wants please help "
    "hi hello thanks about after before long soon too many until again just "
    "still very much leave while keep left over out up down off some any".split()
)


def _stem(t: str) -> str:
    # Poor-man's plural folding: "sessions"->"session", "logins"->"login".
    # Anything smarter (Porter etc.) is more dependency than this corpus needs.
    if len(t) > 3 and t.endswith("s") and not t.endswith("ss"):
        return t[:-1]
    return t

# Tiny synonym bridge for vocabulary the tickets use but the policies don't
# (and vice versa). Kept small and auditable, this is not a language model,
# it is a handful of domain equivalences that showed up in fixture tickets.
_SYNONYMS: dict[str, list[str]] = {
    "wifi": ["wi", "fi"],
    "2fa": ["mfa", "multi", "factor"],
    "admin": ["administrator"],
    "laptop": ["device", "endpoint"],
    "timeout": ["inactivity", "terminate"],
    "timed": ["timeout", "terminate"],
    "idle": ["inactivity"],
    "inactive": ["inactivity"],
    "disconnect": ["terminate"],
    "disconnected": ["terminate"],
    "drops": ["terminate"],
    "forward": ["forwarding"],
    "phone": ["mobile", "byod"],
    "iphone": ["mobile", "byod", "personal"],
}


def _base_tokens(text: str) -> list[str]:
    return [_stem(t) for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS]


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    for t in _base_tokens(text):
        out.append(t)
        out.extend(_stem(s) for s in _SYNONYMS.get(t, []))
    return out


@dataclass
class Retrieved:
    span: PolicySpan
    score: float
    index: int = -1  # position in the corpus, used for coverage lookups


class Retriever:
    # Two-part confidence, both calibrated on the answerable/unanswerable
    # fixtures in tests/test_policies.py (recalibrate there if the corpus
    # changes):
    #  - MIN_SCORE: raw BM25 floor, filters queries with barely any overlap.
    #  - MIN_COVERAGE: IDF-weighted fraction of the query's content tokens
    #    present in the top section. This is the discriminator that raw BM25
    #    lacks, "parental leave 401k" can still nick a mid score off common
    #    words, but its heavy (rare) tokens are absent from the corpus, so
    #    coverage collapses.
    MIN_SCORE = 3.0
    MIN_COVERAGE = 0.55
    TOP_K = 6

    def __init__(self, spans: list[PolicySpan]):
        self.spans = spans
        self.by_id = {s.span_id: s for s in spans}
        corpus = [_tokens(f"{s.title} {s.text}") for s in spans]
        self._bm25 = BM25Okapi(corpus)
        # Document frequency for IDF-style token weights; +1 smoothing keeps
        # out-of-corpus tokens finite while still weighing them heaviest.
        self._df: dict[str, int] = {}
        for doc in corpus:
            for t in set(doc):
                self._df[t] = self._df.get(t, 0) + 1
        self._n_docs = len(corpus)
        self._corpus_sets = [set(doc) for doc in corpus]

    def _idf(self, token: str) -> float:
        import math

        return math.log((self._n_docs + 1) / (self._df.get(token, 0) + 1))

    def _coverage(self, query: str, span_indexes: list[int]) -> float:
        """IDF-weighted fraction of query content tokens found anywhere in the
        given spans. Union over the top few spans, because a legitimate
        question's vocabulary often straddles adjacent sections while an
        off-corpus question's heavy tokens appear in none of them."""
        qt = set(_base_tokens(query))
        if not qt:
            return 0.0
        doc: set[str] = set()
        for i in span_indexes:
            if i >= 0:
                doc |= self._corpus_sets[i]

        def hits(t: str) -> bool:
            # A base token is covered if it, or any registered synonym of it,
            # appears in the spans. Synonyms never inflate the denominator.
            if t in doc:
                return True
            return any(_stem(s) in doc for s in _SYNONYMS.get(t, []))

        total = sum(self._idf(t) for t in qt)
        hit = sum(self._idf(t) for t in qt if hits(t))
        return hit / total if total else 0.0

    def retrieve(self, query: str) -> list[Retrieved]:
        """Top sections for a query; exact span ids mentioned in the text are
        force-included (a requester quoting 'POL-02 2.3' deserves that span
        in context even if the rest of their wording scores poorly)."""
        scores = self._bm25.get_scores(_tokens(query))
        ranked = sorted(
            (Retrieved(span=s, score=float(scores[i]), index=i) for i, s in enumerate(self.spans)),
            key=lambda r: r.score,
            reverse=True,
        )[: self.TOP_K]
        picked = {r.span.span_id: r for r in ranked if r.score > 0}
        for span_id in _SPAN_ID.findall(query):
            if span_id in self.by_id and span_id not in picked:
                span = self.by_id[span_id]
                picked[span_id] = Retrieved(
                    span=span, score=self.MIN_SCORE, index=self.spans.index(span)
                )
        self._last_query = query  # kept for confidence checks on this result set
        return sorted(picked.values(), key=lambda r: r.score, reverse=True)

    def confident(self, results: list[Retrieved]) -> bool:
        """Below-threshold retrieval means the corpus does not cover the ask,
        the agent defers rather than improvising (spec §5.6). Confidence needs
        both a real score and real coverage of the query's content words."""
        if not results:
            return False
        if results[0].score < self.MIN_SCORE:
            return False
        top3 = [r.index for r in results[:3]]
        return self._coverage(getattr(self, "_last_query", ""), top3) >= self.MIN_COVERAGE

    def supports(self, span_ids: list[str], results: list[Retrieved]) -> bool:
        """Every cited id must (a) exist in the corpus and (b) have been
        retrieved as relevant for this ticket. An invented id, or a real id
        the ticket text never pointed at, fails support."""
        if not span_ids:
            return False
        retrieved_ids = {r.span.span_id for r in results}
        return all(sid in self.by_id and sid in retrieved_ids for sid in span_ids)
