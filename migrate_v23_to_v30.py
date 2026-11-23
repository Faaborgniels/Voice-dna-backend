#!/usr/bin/env python3
"""
migrate_v23_to_v30.py — Deterministic Voice DNA v2.3.0 -> v3.0.0 profile migrator.

Performs a loss-free, auditable upgrade of every existing client profile to the
High-Assurance Forensic specification:

  1. schema_version          -> "3.0.0"
  2. privacy_and_data_governance.security_and_adversarial_hardening  (new mandatory block)
  3. forensic_idiolect_signature                                     (computed from gold corpus)
  4. version_history         -> rebuilt as a SHA-256 hash chain + 3.0.0 migration entry
  5. Re-validates against the v3.0.0 schema and the 16 cross-field invariants.

Usage:
  python3 migrate_v23_to_v30.py <input_v23_profile.json> <output_v30_profile.json>
  python3 migrate_v23_to_v30.py --all profiles/            # in-place batch upgrade
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from voice_dna_engine import (  # noqa: E402
    FUNCTION_WORD_FEATURES,
    SCHEMA_VERSION,
    CoreferencePIIScrubber,
    ForensicIdiolectAnalyzer,
    ProvenanceHashChain,
    StylometricAnalyzer,
    VoiceDNASchemaValidator,
)

MIGRATION_TS = "2026-11-07T00:00:00Z"

# Upper bounds enforced by the v3.0.0 schema for each centroid feature.
CENTROID_CEILING = {
    "the": 150.0, "of": 100.0, "and": 100.0, "to": 100.0, "in": 80.0, "a": 90.0,
    "that": 60.0, "for": 60.0, "is": 60.0, "with": 50.0, "on": 50.0, "by": 40.0,
    "from": 40.0, "not": 40.0, "but": 40.0, "this": 40.0, "are": 40.0, "as": 40.0,
    "be": 40.0, "at": 40.0, "or": 40.0, "if": 40.0, "when": 40.0, "we": 60.0,
    "you": 70.0, "i": 60.0,
}


def ensure_adversarial_hardening(dna: Dict[str, Any]) -> None:
    priv = dna["privacy_and_data_governance"]
    hardening = priv.setdefault(
        "security_and_adversarial_hardening",
        {
            "strip_zero_width_and_steganography": True,
            "block_unicode_homoglyph_spoofing": True,
            "prompt_injection_firewall_mode": "QUARANTINE_AND_HALT",
            "hmac_coreference_pseudonymization": True,
        },
    )
    # v3.0.0 mandates HMAC coreference tokens so pseudonyms remain linkable inside a
    # document but unlinkable across documents / key rotations.
    scrub = priv["pre_inference_pii_scrubber"]
    scrub["token_replacement_format"] = "HMAC_DETERMINISTIC_COREFERENCE_TOKENS"
    hardening["hmac_coreference_pseudonymization"] = True
    if dna["compliance_and_risk_guardrails"]["regulatory_regime"] == "PUBLIC_SECTOR_HIGH_ASSURANCE":
        hardening["prompt_injection_firewall_mode"] = "QUARANTINE_AND_HALT"


def compute_forensic_signature(dna: Dict[str, Any]) -> Dict[str, Any]:
    corpus = " ".join(cal["authentic_client_gold_version"] for cal in dna["few_shot_calibration"])
    raw_profile = ForensicIdiolectAnalyzer.function_word_profile(corpus)
    centroid = {
        feat: round(min(raw_profile[feat], CENTROID_CEILING[feat]), 3) for feat in FUNCTION_WORD_FEATURES
    }
    for feat in FUNCTION_WORD_FEATURES:
        if raw_profile[feat] > CENTROID_CEILING[feat]:
            print(
                f"  [WARN] centroid feature {feat!r} = {raw_profile[feat]} exceeds schema ceiling "
                f"{CENTROID_CEILING[feat]}; clamped.",
                file=sys.stderr,
            )

    tokens = __import__("re").findall(r"[a-z']+", corpus.lower())
    mattr = round(ForensicIdiolectAnalyzer.mattr(tokens, 40), 4)
    mattr_lo = round(max(0.55, mattr - 0.08), 3)
    mattr_hi = round(min(0.99, mattr + 0.08), 3)
    if mattr_lo >= mattr_hi:
        mattr_lo, mattr_hi = round(max(0.55, mattr - 0.10), 3), round(min(0.99, mattr + 0.10), 3)

    tel = StylometricAnalyzer.analyze(corpus, dna["stylometric_targets"]["word_count_method"])
    nom = ForensicIdiolectAnalyzer.nominalization_density(corpus, tel.total_words)
    passive = ForensicIdiolectAnalyzer.passive_ratio(corpus)

    return {
        "calibration_method": "BURROWS_COSINE_DELTA_V1",
        "function_word_centroid_per_1k": centroid,
        "mattr_window_40_bounds": {"min_mattr": mattr_lo, "max_mattr": mattr_hi},
        "max_nominalization_density_pct": round(min(14.0, max(1.5, nom + 2.5)), 2),
        "max_passive_voice_ratio": round(min(0.45, max(0.0, passive + 0.12)), 3),
        "min_authorship_attribution_score": 88.0,
    }


def rebuild_hash_chain(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Recompute a clean, verifiable chain from the legacy changelog fields."""
    chain: List[Dict[str, Any]] = []
    prev = "GENESIS"
    for entry in history:
        chained = ProvenanceHashChain.make_entry(
            version=entry["version"],
            changed_at_utc=entry["changed_at_utc"],
            change_summary=entry["change_summary"],
            breaking_change=bool(entry.get("breaking_change", False)),
            prev_version_hash=prev,
        )
        chain.append(chained)
        prev = chained["entry_sha256"]
    return chain


def migrate(dna: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(dna)
    out["schema_version"] = SCHEMA_VERSION
    ensure_adversarial_hardening(out)
    out["forensic_idiolect_signature"] = compute_forensic_signature(out)
    out["version_history"] = rebuild_hash_chain(out["version_history"])
    out = ProvenanceHashChain.append(
        out,
        version="3.0.0",
        changed_at_utc=MIGRATION_TS,
        summary=(
            "Upgraded to v3.0.0 High-Assurance Forensic spec: adversarial sanitizer, HMAC "
            "coreference pseudonymization, Burrows Delta idiolect attribution, SHA-256 chained provenance."
        ),
        breaking=True,
    )
    return out


def migrate_file(src: Path, dst: Path | None = None) -> Dict[str, Any]:
    dna = json.loads(src.read_text(encoding="utf-8"))
    upgraded = migrate(dna)
    validator = VoiceDNASchemaValidator()
    ok, issues = validator.validate(upgraded)
    errs = [i for i in issues if i.severity == "ERROR"]
    warns = [i for i in issues if i.severity == "WARNING"]
    target = dst or src
    if errs:
        print(f"[FAIL] {src.name}: {len(errs)} schema errors", file=sys.stderr)
        for e in errs[:10]:
            print(f"   {e.path}: {e.message}", file=sys.stderr)
        return upgraded
    target.write_text(json.dumps(upgraded, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"[OK] {src.name} -> {target.name} | schema {SCHEMA_VERSION} | "
        f"chain_root={ProvenanceHashChain.chain_root(upgraded)[:12]}... | "
        f"warnings={len(warns)} | pid_or_alias={upgraded['profile_metadata']['pseudonym_token']}"
    )
    for w in warns:
        print(f"   [WARN] {w.path}: {w.message}", file=sys.stderr)
    return upgraded


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    if args[0] == "--all":
        target = Path(args[1]) if len(args) > 1 else Path("profiles")
        for pf in sorted(target.glob("*.dna.json")):
            migrate_file(pf)
        return 0
    src = Path(args[0])
    dst = Path(args[1]) if len(args) > 1 else None
    migrate_file(src, dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
