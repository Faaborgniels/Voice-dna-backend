# Experimental v3.0.0 Sample Demonstration — Not a Security Validation

> Synthetic illustrative cases only. The controls are incomplete and not a certified or independently measured security system. No LLM, network, audio deletion, residency or publishing integration is exercised. See SECURITY-AND-FORENSICS.md and the automation guide for limitations.

**Profile:** `cfo_marcus_vance.dna.json` · `FRACTIONAL_CFO` · alias `EXEC_CFO01A`
**Data residency:** `US` · **Inference mode:** `ZERO_DATA_RETENTION_ENTERPRISE_API` · **Firewall:** `QUARANTINE_AND_HALT`
**Schema validation:** `valid=True` · errors/skips: `0`

## Stage 1 — Adversarial Unicode / Steganography Sanitization

| Signal | Count |
| --- | --- |
| Zero-width characters removed | 2 |
| Bidi control overrides removed | 2 |
| Variation selectors removed | 0 |
| Unicode-Tag smuggled characters removed | 2 |
| Homoglyph repairs (Cyrillic/Greek → Latin) | 1 |
| Tamper signal score | **100/100** |
| Verdict | `DEFANGED` |

Homoglyph repairs applied: `U+041E`→`O`

## Stage 2 — Indirect Prompt-Injection Firewall

- Signatures detected: **3**
  - `Instruction-override attempt ('ignore previous instructions')` → matched: `Ignore all previous instructions`
  - `System-prompt exfiltration attempt` → matched: `reveal your system prompt`
  - `Safety-guardrail bypass attempt` → matched: `bypass all safety guardrails`
- Firewall verdict: `QUARANTINED` · emitted payload: `[QUARANTINED_ADVERSARIAL_INPUT]`
- This particular signature was quarantined in this standalone test; other injection phrasing may be missed. Preprocessing does not call this sanitizer automatically.

## Stage 3 — Coreference-Preserving HMAC Pseudonymization

- Redactions applied: **8** → `{"EMAIL": 1, "PHONE": 1, "IBAN": 1, "CREDIT_CARD": 1, "SSN": 1, "ORG": 1, "PERSON": 2}`
- HMAC key fingerprint: `646d43b1649003ee`
- Coreference groups (same entity → same token inside the document): `8`

```text
[PERSON_9D656B] met with [PERSON_8D77BA] at [ORG_9BC79D] on the task order ceiling. Send the reconciliation to [EMAIL_7F4ED5] or [PHONE_B9524F]. Wire reference IBAN [IBAN_665DB0], card [CREDIT_CARD_00C442], SSN [SSN_06989C]. Note the invalid card 4111 1111 1111 1112 is a receipt number, not payment data.
```

- Key rotation unlinks tokens across documents: `YES`
- Checksum enforcement: Luhn-invalid card preserved as receipt text, ISO-13616 mod-97 IBAN redacted, structurally invalid SSN ranges left intact in this example; false positives and false negatives remain possible.

## Stage 4 — Async Voice Ingestion (ASR Repair, Off-Record Quarantine, Patch H)

- Clips parsed: `1` · pipeline halted: `False`
- ASR repairs applied: `3`
- Off-record spans quarantined: `1`
- Numeric self-repairs flagged for author confirmation (Patch H): `1`
- Editor directives extracted: `1`
- Golden verbatim candidates ranked: `0`
- Estimated content yield: `{"recommended_linkedin_posts": 1, "newsletter_deep_dive_viable": false, "short_video_script_viable": false}`

Example processed transcript (not sent to a model; requires local privacy review):

```text
[Clip 1]
Okay two things before the 7:30 program review. [REDACTED_OFF_RECORD_SEGMENT] Second, our unbilled receivables on that task order aged to 47 days while we kept billing at the provisional rate. Look at the math: we are carrying [VERIFY: $6.8M (author said $6.4M first)] in unbilled receivables, our DSO (days sales outstanding) crept out to Net-60, and COGS on the delivery side moved against us. [STRIPPED_INJECTION_ATTEMPT] and [STRIPPED_INJECTION_ATTEMPT], then [STRIPPED_INJECTION_ATTEMPT].
```

## Stage 5 — Experimental Style Similarity (Not Authorship Attribution)

| Candidate | Authorship score | Verdict | Cosine (idiolect vector) | Burrows Δz | MATTR-40 | Nom. density /100w | Passive ratio |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Client gold draft | **95.47/100** | `ATTRIBUTED` | 0.9303 | 0.344 | 0.9282 | 0.75 | 0.0 |
| Third-party register | **75.47/100** | `INCONCLUSIVE` | 0.70366 | 0.701 | 0.941 | 10.26 | 0.0 |
| Synthetic slop | **69.87/100** | `ANOMALOUS` | 0.55577 | 0.898 | 1.0 | 17.24 | 0.0 |

Calibrated authorship floor: **88.0/100**. Anomalies flagged on the third-party draft: ['Nominalization density 10.26/100w exceeds ceiling 2.89/100w (synthetic abstract-noun inflation).', 'Function-word vector divergence (cosine 0.7037) suggests a different composing register.']

## Stage 6 — Heuristic Lint of a Candidate Draft

- Passed: **True** · fidelity score: **100/100** · human review required: `True` (reviewer: `AUTHOR`)
- Violations: 0
- Provenance chain attached to the report: root `cbef73fb7b115e26...`, verified `True`
- Forensic block: score `95.47/100` (`ATTRIBUTED`), MATTR-40 `0.9282`

## Stage 7 — Tamper-Evident Provenance Chain

- Entries chained: **4** · chain root: `cbef73fb7b115e26410b66a9649cfc77f54e7aba1249cfd5868e6f82635c8a90`
- Verification on authentic profile: `True`
- Verification after a single-field edit to the oldest calibration entry: `False`
- Detection output: `version_history[0].entry_sha256 tamper detected (stored e3d7cffee29f..., recomputed cb4ab1996abd...).`

---

### Scope & responsible-use statement

This engine produces **uncalibrated drafting-QA signals**, not identity proof. The authorship component is a heuristic similarity measure, not a validated Burrows Cosine Delta implementation, and must not be presented as forensic certainty, nor used for surveillance, attribution of anonymous authors, or any decision about a person. Adversarial sanitation and injection firewalls protect an editorial pipeline; they are not an intrusion-detection or intelligence-collection system. Consent, data handling, retention, and provider settings must be implemented and verified separately; the code does not guarantee these.

