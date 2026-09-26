# Domain 1: Prompt Injection Protection

**Layer:** `ingress`
**Owner:** <assign teammate name here>
**Status:** Phase 1 — scaffolding only, controls not yet implemented

## What this domain protects against
<!-- Fill in: 2-3 sentences, plain language, what this domain catches -->

## Controls in this domain

| Control ID | File | Description |
|---|---|---|
| PI-001 | `pi_001_blacklist.py` | Blacklist / Pattern Pre-Validation Filter |
| PI-002 | `pi_002_dynamic_analysis.py` | Dynamic LLM-based Prompt Analyzer |
| PI-003 | `pi_003_embedding_similarity.py` | Embedding Similarity Filter (known jailbreaks) |
| PI-004 | `pi_004_risk_scoring.py` | Prompt Risk Scoring Engine |
| PI-005 | `pi_005_multi_phase_validator.py` | Multi-Phase Validator |
| PI-006 | `pi_006_escalation_router.py` | Escalation Router (human/SIEM alert) |
| PI-007 | `pi_007_token_anomaly.py` | Token Anomaly Monitor |
| PI-008 | `pi_008_token_sanitizer.py` | Token Sanitization Engine |

## How to run this domain's demo standalone

```bash
pytest domains/domain1_prompt_injection/tests/test_domain1_prompt_injection.py -v
```

## Demo Package Checklist (fill in as you go)
- [ ] `tests/payloads.csv` has at least 10-15 real attack examples
- [ ] `tests/test_domain1_prompt_injection.py` passes
- [ ] Short demo output / recording showing a malicious prompt being caught
- [ ] This README's "What this domain protects against" section is filled in
