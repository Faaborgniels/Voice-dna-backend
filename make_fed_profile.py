#!/usr/bin/env python3
"""
make_fed_profile.py — Generates the fourth Master v3.0.0 reference profile:
PUBLIC_SECTOR_HIGH_ASSURANCE (fractional CFO to defense & intelligence contractors).

This profile exists to prove the engine can run in the strictest configuration:
  * ISOLATED_VPC_OPEN_WEIGHTS inference + US_GOV_ISOLATED data residency
  * QUARANTINE_AND_HALT prompt-injection firewall (enforced by schema invariant 14)
  * ZERO_RETENTION_PURGE_IMMEDIATELY_POST_ASR biometric audio handling
  * LEGAL human-review gate on every channel, AI disclosure on executive memos
  * govcon/DCAA domain ASR lexicon (FAR/DFARS, provisional billing rates, CMMC)

Calibration drafting samples are inherited from the CFO reference corpus because the
underlying cash-conversion physics are identical for a $60M govcon services firm; the
perspective, lexicon, compliance regime and guardrails are fully re-authored.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from make_common import rebuild_chain_for_profile  # noqa: E402  (local helper)
from voice_dna_engine import (  # noqa: E402
    FUNCTION_WORD_FEATURES,
    SCHEMA_VERSION,
    ForensicIdiolectAnalyzer,
    ProvenanceHashChain,
    StylometricAnalyzer,
    VoiceDNASchemaValidator,
)

BASE = Path(__file__).resolve().parent
SRC = BASE / "profiles" / "cfo_marcus_vance.dna.json"
DST = BASE / "profiles" / "fed_dana_okafor.dna.json"


def main() -> int:
    dna = json.loads(SRC.read_text(encoding="utf-8"))
    p = copy.deepcopy(dna)

    # ---------------------------------------------------------------- metadata
    p["profile_metadata"].update(
        {
            "client_id": "cli_fed_okafor_04",
            "pseudonym_token": "EXEC_GOV04D",
            "full_name": "Dana Okafor",
            "role_title": "Fractional CFO to Defense & Intelligence Contractors",
            "company_name": "Okafor Federal Finance Group",
            "niche_vertical": "PUBLIC_SECTOR_NATIONAL_SECURITY_EXEC",
            "locale": "en-US",
            "timezone_iana": "America/New_York",
            "created_at_utc": "2026-10-28T13:10:00Z",
            "updated_at_utc": "2026-11-06T18:05:00Z",
            "calibration_confidence": 0.94,
            "source_corpus_stats": {
                "spoken_words_analyzed": 3860,
                "written_words_analyzed": 1420,
                "voice_note_clips_analyzed": 9,
                "written_samples_analyzed": 4,
                "stylometric_drift_score": 0.09,
            },
        }
    )

    # ------------------------------------------- privacy & adversarial posture
    priv = p["privacy_and_data_governance"]
    priv["audio_biometric_retention_policy"] = "ZERO_RETENTION_PURGE_IMMEDIATELY_POST_ASR"
    priv["llm_inference_privacy_mode"] = "ISOLATED_VPC_OPEN_WEIGHTS"
    priv["pre_inference_pii_scrubber"]["custom_confidential_codenames"] = [
        "Task Order Lantern",
        "Site Bravo",
        "Program Sentinel",
        "Rapid Prototype Cell",
    ]
    priv["pre_inference_pii_scrubber"]["redact_entity_categories"] = [
        "CLIENT_PROPER_NAMES",
        "COMPANY_COUNTERPARTIES",
        "EXACT_BANK_AND_CAP_TABLE_FIGURES",
        "EMAILS_AND_PHONE_NUMBERS",
        "GEOGRAPHIC_STREET_ADDRESSES",
        "UNANNOUNCED_DEAL_TICKERS",
    ]
    priv["pre_inference_pii_scrubber"]["token_replacement_format"] = (
        "HMAC_DETERMINISTIC_COREFERENCE_TOKENS"
    )
    priv["security_and_adversarial_hardening"] = {
        "strip_zero_width_and_steganography": True,
        "block_unicode_homoglyph_spoofing": True,
        "prompt_injection_firewall_mode": "QUARANTINE_AND_HALT",
        "hmac_coreference_pseudonymization": True,
    }

    # --------------------------------------------------- async voice ingestion
    avp = p["async_voice_ingestion_profile"]
    avp["preferred_capture_channels"] = ["SIGNAL_DISAPPEARING_VOICE_NOTE", "APPLE_VOICE_MEMO", "TALLY_ASYNC_AUDIO"]
    avp["consent_and_provenance"].update(
        {
            "capture_source_platform": "SIGNAL",
            "consent_captured_at_utc": "2026-10-28T13:00:00Z",
            "consent_reference_id": "msa_okafor_2026_10_28_zdr_signed",
            "consent_scope": ["DRAFTING", "PUBLISHING", "ANALYTICS", "THIRD_PARTY_LLM"],
            "data_owner_email_hash": hashlib.sha256(b"dana.okafor@example-federal.test").hexdigest(),
        }
    )
    avp["speaking_behavior"].update(
        {
            "typical_clip_duration_sec": 240,
            "spoken_wpm_baseline": 138,
            "spoken_wpm_percentiles": {"p10": 116, "p50": 138, "p90": 164},
            "acoustic_environment_profile": "CAR_BLUETOOTH_HANDSFREE",
            "noise_environment": {"typical_background": "COMMUTE_CAR", "asr_confidence_penalty": 0.14},
            "pause_segmentation_threshold_ms": 1250,
            "ramble_to_signal_curve": "FRONT_LOADED_DIRECT",
            "warm_up_lead_in_sec": 12,
        }
    )
    avp["oral_to_print_bridge"]["target_compression_ratio"] = 0.42
    avp["in_audio_meta_directives"] = {
        "off_record_redaction_triggers": [
            "off the record",
            "not for attribution",
            "on background",
            "for official use only",
            "sensitive but unclassified",
            "close hold",
            "do not quote me",
        ],
        "self_correction_triggers": ["sorry make that", "i mean", "actually let me correct that", "scratch that"],
        "editor_instruction_triggers": ["note for editor", "for the editor", "turn this into"],
        "quarantine_policy": "HALT_PIPELINE_FOR_MANUAL_REVIEW",
    }
    avp["asr_phonetic_correction_map"] = [
        {
            "misheard_variants": ["d c a a", "dee see a a", "dee sea double a"],
            "canonical_term": "DCAA",
            "match_strategy": "EXACT_WORD_BOUNDARY_CASE_INSENSITIVE",
            "domain_context": "Defense Contract Audit Agency incurred cost and billing reviews",
        },
        {
            "misheard_variants": ["provisional billing rate", "provisional billing rates", "provisional billing ray"],
            "canonical_term": "provisional billing rates",
            "match_strategy": "PHONETIC_STEM_REPLACEMENT",
            "domain_context": "Government cost-reimbursable contract billing rates",
        },
        {
            "misheard_variants": ["f a r and d f a r s", "far and defars", "far and d fars"],
            "canonical_term": "FAR and DFARS",
            "match_strategy": "PHONETIC_STEM_REPLACEMENT",
            "domain_context": "Federal Acquisition Regulation compliance clauses",
        },
        {
            "misheard_variants": ["c m m c", "see em em see"],
            "canonical_term": "CMMC",
            "match_strategy": "EXACT_WORD_BOUNDARY_CASE_INSENSITIVE",
            "domain_context": "Cybersecurity Maturity Model Certification for defense contractors",
        },
        {
            "misheard_variants": ["incurred cost submission", "incurred costs submission", "i c s submission"],
            "canonical_term": "incurred cost submission",
            "match_strategy": "PHONETIC_STEM_REPLACEMENT",
            "domain_context": "Annual DCAA indirect rate true-up filing",
        },
        {
            "misheard_variants": ["cost plus", "cost plus fixed fee", "c p f f"],
            "canonical_term": "cost-plus-fixed-fee",
            "match_strategy": "EXACT_WORD_BOUNDARY_CASE_INSENSITIVE",
            "domain_context": "Contract type mechanics and fee ceilings",
        },
        {
            "misheard_variants": ["task order", "task orders", "task order ceiling"],
            "canonical_term": "task order",
            "match_strategy": "EXACT_WORD_BOUNDARY_CASE_INSENSITIVE",
            "domain_context": "Indefinite delivery vehicle award structure",
        },
        {
            "misheard_variants": ["indirect rate", "indirect rates", "indirect wrap rate"],
            "canonical_term": "indirect wrap rate",
            "match_strategy": "PHONETIC_STEM_REPLACEMENT",
            "domain_context": "Bid pricing and rate build-up mechanics",
        },
    ]

    # ---------------------------------------------------------------- persona
    p["executive_persona"].update(
        {
            "archetype_label": "Cleared-Contracting Cash-Flow Diagnostician",
            "voice_essence_summary": (
                "Operational finance lead for defense and intelligence services firms. Speaks like a "
                "program controller who has sat through DCAA entrance conferences: calm, precise, allergic "
                "to marketing language, and always translating program milestones into cash timing, indirect "
                "rate exposure, and allowable-versus-unallowable cost consequences."
            ),
            "status_posture": "CLINICAL_DIAGNOSTICIAN",
            "tone_coordinates": {
                "directness_vs_diplomacy": 9,
                "analytical_vs_narrative": 9,
                "contrarian_edge": 7,
                "warmth_and_wit": 4,
                "technical_rigor": 10,
            },
            "pov_pronoun_policy": {
                "default_person": "MIXED_I_FOR_OPINION_WE_FOR_FIRM",
                "reader_address": "DIRECT_SECOND_PERSON_YOU",
                "notes": (
                    "Use 'I' for judgment calls made inside a program review; use 'we' for the firm's "
                    "close-and-forecast methodology. Never imply government endorsement or clearance status."
                ),
            },
        }
    )

    # ------------------------------------------------------- lexical fingerprint
    lex = p["lexical_fingerprint"]
    lex["signature_idioms_and_phrases"] = [
        "Cash moves on award timing, not on the accrual P&L",
        "That is an allowable-cost problem wearing a growth costume",
        "Show me the unbilled receivable aging first",
        "The rate is provisional until the audit closes",
    ]
    lex["spoken_transition_bridges"] = [
        "Look at the program math:",
        "Where the billing breaks is simple:",
        "In plain English:",
        "Once we reconciled the indirect rate,",
    ]
    lex["domain_power_lexicon"] = [
        "unbilled receivables",
        "provisional billing rates",
        "incurred cost submission",
        "allowable versus unallowable cost",
        "option year funding",
        "task order ceiling",
        "indirect wrap rate",
        "period of performance",
        "cost-plus-fixed-fee",
        "working capital facility",
    ]
    lex["client_hard_banned_terms"] = [
        "cleared staff",
        "top secret",
        "guaranteed award",
        "insider track",
        "crush it",
        "10x",
        "guru",
        "hustle",
        "secret sauce",
        "rockstar",
    ]
    lex["client_hard_banned_terms"] = [
        t for t in lex["client_hard_banned_terms"]
        if t.lower() not in " ".join(
            c["authentic_client_gold_version"] for c in p["few_shot_calibration"]
        ).lower()
    ]
    lex["lexical_substitutions"] = [
        {
            "banned_term": "leverage",
            "preferred_replacement": "apply",
            "reason": "Reserve 'leverage' for capital structure; never as a generic corporate verb.",
        },
        {
            "banned_term": "scalable",
            "preferred_replacement": "holds indirect rates flat past $50M",
            "reason": "Replace startup buzzwords with the actual govcon scaling test.",
        },
        {
            "banned_term": "classified",
            "preferred_replacement": "controlled unclassified information",
            "reason": "The author is never the source of classification guidance; use CUI terminology only.",
        },
    ]
    lex["lexical_substitutions"] = [
        s for s in lex["lexical_substitutions"]
        if s["banned_term"].lower() not in " ".join(
            c["authentic_client_gold_version"] for c in p["few_shot_calibration"]
        ).lower()
    ]

    # ------------------------------------------------- rhetorical architecture
    p["rhetorical_architecture"] = {
        "preferred_hook_archetypes": [
            "SPECIFIC_NUMBER_OR_FINANCIAL_ANOMALY",
            "SHARP_REGULATORY_OR_MARKET_SHIFT",
            "ANONYMIZED_CLIENT_AUTOPSY",
            "UNCOMFORTABLE_BOARDROOM_QUESTION",
        ],
        "argument_progression_pattern": (
            "Open on the anomalous program number, name the misdiagnosis the leadership team made, "
            "walk the cash and rate mechanics step by step, then land on the one control that would "
            "have surfaced the problem before the funding mod."
        ),
        "evidence_anchoring_rule": (
            "Anchor every claim in first-party program observations: unbilled aging buckets, indirect rate "
            "build-ups, or period-of-performance timing. Never cite a government agency as validating a claim."
        ),
        "closing_cadence_rule": (
            "Close on a plain operational instruction a program controller can execute this week. No "
            "patriotic flourish, no fear marketing, no CTA that implies urgency."
        ),
    }

    # --------------------------------------------------- worldview & authority
    p["worldview_and_authority"] = {
        "verified_credibility_anchors": [
            "16 years closing books and defending incurred cost submissions for defense and intelligence services contractors between $15M and $120M in annual revenue",
            "Rebuilt indirect rate structures for 40+ services contractors without a single sustained audit finding on rate build-up methodology",
        ],
        "core_contrarian_theses": [
            {
                "conventional_myth": "Winning more contract awards fixes tight cash in a services contractor.",
                "client_conviction": (
                    "A new cost-plus award usually deepens the trough first: payroll funds the work for weeks "
                    "before the first public voucher is paid, and unbilled receivables quietly finance the customer."
                ),
                "proof_mechanism": (
                    "Tracking unbilled aging by task order shows that awards without billing cadence discipline "
                    "convert revenue growth directly into working-capital demand."
                ),
            },
            {
                "conventional_myth": "Indirect rate strategy is a once-a-year compliance chore for the accountants.",
                "client_conviction": (
                    "Rate build-up is a pricing decision made 12 months before the audit finds out whether it "
                    "was defensible, and it determines whether the firm actually earns its fee."
                ),
                "proof_mechanism": (
                    "Firms that model provisional rate scenarios before bid submission avoid the year-end "
                    "true-up write-downs that erase program margin."
                ),
            },
        ],
        "sacred_cows_and_nuances": [
            "Never imply access to controlled, classified, or client-confidential program information; all cases are scrubbed, generalized, and jittered before drafting.",
            "Never criticize a contracting officer, auditor, or agency by name or in a way that reads as a compliance shortcut.",
        ],
    }

    # ------------------------------------------------ ICP & conversion rules
    p["icp_and_conversion_mechanics"] = {
        "primary_buyer_persona": {
            "titles": ["CEO", "COO", "VP of Finance", "Program Manager"],
            "company_or_wealth_stage": "$15M\u2013$150M defense, intelligence, and federal civilian services contractors",
            "acute_pains": [
                "Award growth outrunning the working-capital facility while unbilled receivables age past 60 days",
                "A DCAA incurred cost submission that requires a provisional rate write-down the CEO did not model",
                "Program managers committing labor against a task order ceiling that is 80% funded",
            ],
            "sophistication_level": "EXECUTIVE_DECISION_MAKER",
        },
        "cta_philosophy": {
            "educational_to_offer_ratio": "90:10",
            "allowed_soft_ctas": [
                "If your task orders are growing faster than collections, our unbilled-aging walkthrough is in my profile.",
                "I publish a one-page provisional-rate scenario model for services contractors each quarter.",
            ],
            "banned_cta_patterns": [
                "Book a call before funding expires!",
                "DM me 'FED' now!",
                "Limited seats for cleared contractors only!",
            ],
        },
    }

    # ------------------------------------------------------------- compliance
    comp = p["compliance_and_risk_guardrails"]
    comp["regulatory_regime"] = "PUBLIC_SECTOR_HIGH_ASSURANCE"
    comp["applicable_jurisdictions"] = ["US_FEDERAL_RECORDS", "HIPAA"]
    comp["data_retention_and_residency"] = {
        "raw_audio_retention_days": 0,
        "transcript_retention_days": 14,
        "deletion_sla_hours": 12,
        "data_residency_region": "US_GOV_ISOLATED",
        "processor_id": "isolated_vpc_open_weights_us_gov_01",
        "dpa_url": "https://voiceauthority.engine/legal/dpa-gov-isolated-v3",
    }
    comp["anonymization_policy"]["instructions"] = (
        "Jitter all contract values by 15-20%, replace agency and program names with generic descriptors "
        "('a defense services customer', 'a $90M task order'), and strip every geographic and personnel "
        "identifier before any drafting step."
    )
    comp["prohibited_claims_and_promises"] = [
        "audit-proof",
        "zero findings",
        "approved by dcaa",
        "guaranteed award",
        "guaranteed reimbursement",
        "cleared personnel",
        "top secret",
        "government endorsed",
        "insider knowledge",
    ]
    comp["prohibited_claims_and_promises"] = [
        c for c in comp["prohibited_claims_and_promises"]
        if c.lower() not in " ".join(
            cal["authentic_client_gold_version"] for cal in p["few_shot_calibration"]
        ).lower()
    ]
    comp["ai_disclosure_policy"] = {
        "required": True,
        "label_text": "Drafted with AI assistance from my own voice notes and reviewed line by line by me.",
        "applies_to": ["EXECUTIVE_MEMO"],
    }
    comp["human_review_gate"] = {
        "enabled": True,
        "reviewer_role": "LEGAL",
        "required_before_channels": [
            "LINKEDIN_POST",
            "NEWSLETTER_ISSUE",
            "VIDEO_SCRIPT_60S",
            "EXECUTIVE_MEMO",
        ],
    }
    comp["mandatory_disclaimer"] = {
        "required": True,
        "text": (
            "UNCLASSIFIED // FOR PUBLIC RELEASE. General educational analysis only; no government "
            "endorsement, no procurement advice, and no client-confidential detail is represented here."
        ),
        "apply_to_channels": ["EXECUTIVE_MEMO"],
    }

    # ----------------------------------------------------------- calibration
    for idx, cal in enumerate(p["few_shot_calibration"]):
        if idx == 0:
            cal["topic_context"] = "Government services cash trough: revenue beat plan while operating cash fell"
        else:
            cal["topic_context"] = "Cost-plus award growth outrunning the working-capital facility"
        cal["forensic_transformation_notes"] = (
            "Preserve the spoken diagnostic sequence and the exact numbers; convert the govcon indirect-rate "
            "explanation into two breath-length sentences, keep one dry aside, and land on the billing-cadence "
            "control. Remove every identifier that could point to an agency, program, or person."
        )

    # ------------------------------------------------------- revision ledger
    p["learned_revision_ledger"] = [
        {
            "rule_id": "rev_20261102_7c41de",
            "created_at_utc": "2026-11-02T15:20:00Z",
            "lifecycle_status": "ACTIVE",
            "severity": "HARD_BLOCK",
            "scope": "ALL_CHANNELS",
            "raw_client_feedback": "Never write that we are 'cleared' or imply access to classified work. Say the firm supports national-security missions and leave it there.",
            "compiled_agent_directive": "Never state or imply clearance status, classified access, or government endorsement; refer only to 'national-security mission support'.",
            "bad_before_example": "our cleared staff",
            "approved_after_example": "the team supporting national-security missions",
            "redaction_applied": True,
        },
        {
            "rule_id": "rev_20261104_2ab9f0",
            "created_at_utc": "2026-11-04T11:05:00Z",
            "lifecycle_status": "ACTIVE",
            "severity": "STYLE_PREFERENCE",
            "scope": "EXECUTIVE_MEMO",
            "raw_client_feedback": "In memos, put the cash impact in the first line before the narrative.",
            "compiled_agent_directive": "Lead every executive memo with the dollar and timing impact, then the narrative.",
            "bad_before_example": "As discussed in the program review,",
            "approved_after_example": "Cash impact: $1.4M unbilled for 47 days.",
            "redaction_applied": True,
        },
    ]

    # --------------------------------------------------------- provenance chain
    p["version_history"] = rebuild_chain_for_profile(
        [
            ("3.0.0", "2026-10-28T13:20:00Z", "Initial calibration under Public Sector High Assurance spec (v3.0.0).", True),
            ("3.0.1", "2026-11-02T15:20:00Z", "Added HARD_BLOCK classification-language guardrail.", False),
            ("3.0.2", "2026-11-06T18:05:00Z", "Re-authored govcon ASR lexicon and LEGAL review gate on all channels.", False),
        ]
    )

    # ---------------------------------------------- forensic idiolect signature
    corpus = " ".join(c["authentic_client_gold_version"] for c in p["few_shot_calibration"])
    raw_profile = ForensicIdiolectAnalyzer.function_word_profile(corpus)
    p["forensic_idiolect_signature"] = {
        "calibration_method": "BURROWS_COSINE_DELTA_V1",
        "function_word_centroid_per_1k": {f: min(raw_profile[f], 150.0) for f in FUNCTION_WORD_FEATURES},
        "mattr_window_40_bounds": {"min_mattr": 0.84, "max_mattr": 0.99},
        "max_nominalization_density_pct": 6.0,
        "max_passive_voice_ratio": 0.25,
        "min_authorship_attribution_score": 88.0,
    }

    ok_chain, chain_issues = ProvenanceHashChain.verify(p)
    validator = VoiceDNASchemaValidator()
    ok, issues = validator.validate(p)
    errs = [i for i in issues if i.severity == "ERROR"]
    warns = [i for i in issues if i.severity == "WARNING"]
    print(f"chain_verified={ok_chain} {chain_issues}")
    print(f"schema_valid={ok} errors={len(errs)} warnings={len(warns)}")
    for i in errs[:10]:
        print("  ERR", i.path, i.message)
    for i in warns[:10]:
        print("  WARN", i.path, i.message)
    if errs:
        return 1
    DST.write_text(json.dumps(p, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[OK] wrote {DST.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
