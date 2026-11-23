# Async Voice DNA v3.0.0 — Developer Quick Start

This directory contains a **local prototype**: a Draft 2020-12 JSON schema, Python CLI, fictional sample profiles and sample text. It has no audio transcription, model API calls, client portal, scheduler, server, deployment, security certification, actual audio deletion or access-control system. Profile values are configuration claims, not proof that the corresponding environment exists. See `../09-Step-by-Step-v3-Automation-Guide.md` for the complete step-by-step setup, integration design and checks.

## Run the included samples

From the project root:

```bash
python3 code/voice_dna_engine.py selftest
python3 code/voice_dna_engine.py validate code/profiles/cfo_marcus_vance.dna.json
python3 code/voice_dna_engine.py verify-chain code/profiles/cfo_marcus_vance.dna.json
python3 code/voice_dna_engine.py sanitize code/samples/sample_raw_whatsapp_voice_note.txt
python3 code/voice_dna_engine.py preprocess-voice code/profiles/cfo_marcus_vance.dna.json code/samples/sample_raw_whatsapp_voice_note.txt
python3 code/voice_dna_engine.py compile-prompt code/profiles/cfo_marcus_vance.dna.json --channel LINKEDIN_POST
python3 code/voice_dna_engine.py lint-draft code/profiles/cfo_marcus_vance.dna.json code/samples/sample_candidate_linkedin_draft.txt --channel LINKEDIN_POST
```

These use synthetic data. In a real pipeline **run sanitize separately first** and check its result before `preprocess-voice` as explained in the guide. A 0 exit code is not a privacy or safety guarantee. Self-tests are limited regression checks, not independent security or accuracy evaluations.

## Commands and data handling

Run `python3 code/voice_dna_engine.py --help` for all commands. `validate` checks the implemented schema subset and cross-field rules; `preprocess-voice` works on text; `lint-draft` returns `passed`, score, violations and review fields. `compile-prompt` builds a text contract; review it before any external use. `attribute` yields an experimental style score, not proven authorship or an AI detector. `append_revision_rule()` is a Python function, not a CLI command.

**Sensitive-output warning:** `preprocess-voice` returns quarantined off-record segments and editor instructions in the full packet. `scrub-coref` returns plaintext entity surfaces in `coreference_groups`. Do not share those outputs with a third-party LLM. Both PII and prompt-injection detection miss cases; a human must inspect and minimize the data before any external call. The HMAC fallback key is derived from profile data, not a protected secret. The configured HMAC token mode does not automatically integrate `scrub-coref` into preprocessing. Compiler free text may contain identifiers and is not guaranteed valid XML.

`version_history` uses an unkeyed chain over its own entries. An attacker with write access can recompute the chain; it does not authenticate the author, bind the full profile/draft, or prove historical events. The migrator rewrites history and profiles in place in `--all` mode: back up first, run only on appropriate v2.3 profiles, and inspect changes; do not treat migration history as independent evidence.

The historical `demo-forensics-report.md` is illustrative, not evidence of government-grade performance. For detailed limits see `SECURITY-AND-FORENSICS.md` and the automation guide. Human/editor/client and applicable compliance review remain mandatory.
