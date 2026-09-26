# Domain 3: Plugin / Tool Abuse Monitoring

**Layer:** `execution`
**Owner:** <assign teammate name here>
**Status:** Phase 1 — scaffolding only, controls not yet implemented

## What this domain protects against
<!-- Fill in: 2-3 sentences, plain language, what this domain catches -->

## Controls in this domain

| Control ID | File | Description |
|---|---|---|
| PL-001 | `pl_001_tool_whitelist.py` | Tool/Plugin Whitelist Enforcement |
| PL-002 | `pl_002_command_tracking.py` | Command & Argument Tracking |
| PL-003 | `pl_003_sensitive_tool_gate.py` | Sensitive Tool Access Gate |
| PL-004 | `pl_004_tool_anomaly.py` | Tool Execution Anomaly Detector |
| PL-005 | `pl_005_usage_correlation.py` | Cross-Tool Usage Correlation |
| PL-006 | `pl_006_rate_limiter.py` | Tool Call Rate Limiter |
| PL-007 | `pl_007_session_terminator.py` | Session Termination on Critical Abuse |

## How to run this domain's demo standalone

```bash
pytest domains/domain3_plugin_abuse/tests/test_domain3_plugin_abuse.py -v
```

## Demo Package Checklist (fill in as you go)
- [ ] `tests/payloads.csv` has at least 10-15 real attack examples
- [ ] `tests/test_domain3_plugin_abuse.py` passes
- [ ] Short demo output / recording showing a malicious prompt being caught
- [ ] This README's "What this domain protects against" section is filled in
