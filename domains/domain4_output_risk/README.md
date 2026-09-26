# Domain 4: Output Risk & Response Control

**Layer:** `egress`
**Owner:** <assign teammate name here>
**Status:** Phase 1 — scaffolding only, controls not yet implemented

## What this domain protects against
<!-- Fill in: 2-3 sentences, plain language, what this domain catches -->

## Controls in this domain

| Control ID | File | Description |
|---|---|---|
| OR-001 | `or_001_jailbreak_output_filter.py` | Jailbroken-Content Output Filter |
| OR-002 | `or_002_hallucination_flag.py` | Hallucinated-Fact Flagging |
| OR-003 | `or_003_output_watermark.py` | Output Token Watermarking |
| OR-004 | `or_004_sensitivity_scoring.py` | Response Sensitivity Scoring |
| OR-005 | `or_005_risky_reroute.py` | Risky Content Block/Reroute |
| OR-006 | `or_006_prompt_response_correlation.py` | Prompt-Response Correlation Check |
| OR-007 | `or_007_tone_deviation.py` | Tone / Sentiment Deviation Monitor |

## How to run this domain's demo standalone

```bash
pytest domains/domain4_output_risk/tests/test_domain4_output_risk.py -v
```

## Demo Package Checklist (fill in as you go)
- [ ] `tests/payloads.csv` has at least 10-15 real attack examples
- [ ] `tests/test_domain4_output_risk.py` passes
- [ ] Short demo output / recording showing a malicious prompt being caught
- [ ] This README's "What this domain protects against" section is filled in
