"""Source-preserving policy loader.

POL-01..POL-10 are the ONLY authorized runtime knowledge (spec §1.3, CLAUDE.md).
This loader owns that boundary: it reads exactly the ten files under
policies/, splits them into their 60 numbered sections without rewording a
character, and refuses anything unexpected: an eleventh file, a duplicate
section id, an empty body. Only the ten policy documents enter
here, so they can never be cited (D-28, authority map §7).

Section text is kept verbatim; the sha256 of each section ties a citation in
the audit log back to the exact words it was grounded on.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from helix.models import PolicySpan

# "# POL-01, Password & Authentication Policy"
_HEADER = re.compile(r"^#\s+(POL-\d{2})\s+—\s+(.+?)\s*$", re.M)
# "*Effective: 2025-09-01. Owner: Identity & Access Management team.*"
_META = re.compile(r"\*Effective:\s*([0-9-]+)\.\s*Owner:\s*(.+?)\.\*")
# "**1.4** Accounts are locked after..."
_SECTION = re.compile(r"^\*\*(\d+\.\d+)\*\*\s+(.*?)(?=^\*\*\d+\.\d+\*\*|\Z)", re.M | re.S)

EXPECTED_POLICY_IDS = {f"POL-{n:02d}" for n in range(1, 11)}


def load_policy_pack(root: Path) -> list[PolicySpan]:
    """Parse policies/POL-*.md into 60 spans. Fail closed on any surprise."""

    files = sorted(p for p in root.glob("POL-*.md"))
    found_ids = {p.stem for p in files}
    if found_ids != EXPECTED_POLICY_IDS:
        # A file appearing here is a change of knowledge authority; that goes
        # through review (D-42), not through dropping a file in the directory.
        raise ValueError(
            f"policy pack mismatch: expected exactly POL-01..POL-10, got {sorted(found_ids)}"
        )

    spans: list[PolicySpan] = []
    seen: set[tuple[str, str]] = set()
    for path in files:
        raw = path.read_text(encoding="utf-8")
        header = _HEADER.search(raw)
        if not header or header.group(1) != path.stem:
            raise ValueError(f"{path.name}: header missing or id mismatch")
        policy_id, title = header.group(1), header.group(2)
        meta = _META.search(raw)
        if not meta:
            raise ValueError(f"{path.name}: missing Effective/Owner metadata")
        effective, owner = meta.group(1), meta.group(2)

        for m in _SECTION.finditer(raw):
            section, text = m.group(1), m.group(2).strip()
            if not text:
                raise ValueError(f"{policy_id} {section}: empty section body")
            key = (policy_id, section)
            if key in seen:
                raise ValueError(f"duplicate section {policy_id} {section}")
            seen.add(key)
            spans.append(
                PolicySpan(
                    policy_id=policy_id,
                    section=section,
                    title=title,
                    text=text,
                    owner=owner,
                    effective=effective,
                    source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                )
            )
    # Every expected policy must contribute at least one section, and no
    # policy id may appear that we did not expect. The canonical 10-policy pack
    # has exactly 60 sections; that stronger invariant is asserted only for the
    # default set, so onboarding a reviewed content-only 11th policy (with a
    # different section count) is a config change, not a code edit.
    produced = {s.policy_id for s in spans}
    if produced != EXPECTED_POLICY_IDS:
        raise ValueError(f"policy ids {sorted(produced)} != expected {sorted(EXPECTED_POLICY_IDS)}")
    if EXPECTED_POLICY_IDS == {f"POL-{n:02d}" for n in range(1, 11)} and len(spans) != 60:
        raise ValueError(f"canonical pack must have 60 sections, parsed {len(spans)}")
    return spans


def spans_by_id(spans: list[PolicySpan]) -> dict[str, PolicySpan]:
    return {s.span_id: s for s in spans}
