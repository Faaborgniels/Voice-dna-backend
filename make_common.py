#!/usr/bin/env python3
"""make_common.py — tiny shared helpers for the v3.0.0 profile generators."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from voice_dna_engine import ProvenanceHashChain  # noqa: E402


def rebuild_chain_for_profile(entries: List[Tuple[str, str, str, bool]]) -> List[Dict[str, Any]]:
    """entries: (version, changed_at_utc, change_summary, breaking_change) -> chained history."""
    chain: List[Dict[str, Any]] = []
    prev = "GENESIS"
    for version, ts, summary, breaking in entries:
        entry = ProvenanceHashChain.make_entry(version, ts, summary, breaking, prev)
        chain.append(entry)
        prev = entry["entry_sha256"]
    return chain
