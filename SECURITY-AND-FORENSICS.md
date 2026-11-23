# v3 Security and Stylometry: Scope and Limitations

**Correction to earlier materials:** v3 is an experimental local editorial prototype, not a government-grade, production-secure, certified, legally compliant, forensic identification or AI-detection system. Its tests demonstrate a few sample cases and do not measure real-world error rates. Do not ingest classified information, CUI, protected health data, or other sensitive regulated data without a separately approved system, legal review and independent security assessment.

## What the code does, and where it falls short

| Component | Observable behavior | Important limitations |
|---|---|---|
| `sanitize` | Separately detects a small set of injection signatures and removes/folds selected Unicode characters. A known injection can return exit 2 with `QUARANTINED`. | Not automatically called by `preprocess-voice`; not a complete prompt-injection defense; transformations may damage valid multilingual text and emoji. A clean result does not prove safety. |
| `preprocess-voice` | Works on transcripts; applies ASR substitutions, off-record rules, number markers and pattern-based PII replacement. | Full JSON includes quarantined off-record segments, editor instructions and corrections. PII detection misses names, organizations, indirect identifiers and formats. Do not pass the entire packet externally. |
| `scrub-coref` | Separate HMAC-based tokenizing experiment with selected regex/checksum detection. | Returns plaintext entity values in `coreference_groups`, and can miss or misclassify identifiers. The fallback key is profile-derived and not secret; key lifecycle must be engineered. Token collisions, cross-document linkage and false negatives require separate evaluation. This command is not automatically used by preprocessing. |
| `attribute` | Computes a function-word similarity and hand-weighted style score. | Not an independently calibrated probability, valid identity/authorship finding, AI detector or genuine validated Burrows Cosine Delta implementation. Short examples and training-set reuse make reported sample scores unreliable. Do not use for consequential decisions about a person. |
| `verify-chain` | Recomputes a hash chain over selected version-history fields. | Anyone able to change entries can recompute the chain. There is no external anchor, signature or protected audit storage; the hashes do not bind the full profile, generated draft or real-world events. It is not a non-repudiation mechanism. |
| `compile-prompt` | Formats profile content as a channel contract. | Free text may include sensitive data or unescaped XML characters; a pseudonymization setting is not a guarantee. Inspect the contract before sending it externally. |
| Schema settings | Express policy choices including retention and human-review intent. | Settings do not provision isolation, residency, provider zero-retention, deletion, compliance gates or legal consent. Execution and enforcement must be implemented and independently verified. |

## Pilot safeguards

Use synthetic data first. For real data, obtain explicit consent and provider permissions; choose approved storage and ASR/LLM services, including contractual retention terms. A human reviews and minimizes both the processed excerpt and contract before sending them externally. Quarantine on any failure or ambiguity. Verify every claim and number; an unverified marker must not be published. Require editor and client approval of the exact final version and any required firm compliance approval. Record reviewer decisions separately.

For implementation steps, data handling, retry behavior and acceptance tests, see `../09-Step-by-Step-v3-Automation-Guide.md`. A production security program would also require threat modeling, strong authentication/authorization, encryption and key management, isolation, secure logging, externally anchored audit records, retention/deletion verification, monitoring, independent testing and legal review. None is established by the sample profile labels.
