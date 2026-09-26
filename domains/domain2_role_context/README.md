# Domain 2: Role & Context Manipulation

**Layer:** `ingress`
**Owner:** <assign teammate name here>
**Status:** Phase 1 — scaffolding only, controls not yet implemented

## What this domain protects against
<!-- Fill in: 2-3 sentences, plain language, what this domain catches -->

## Controls in this domain

| Control ID | File | Description |
|---|---|---|
| RC-001 | `rc_001_role_lock.py` | System Role Lock / Anti Role-Switch Filter |
| RC-002 | `rc_002_impersonation_detector.py` | Impersonation & Identity-Claim Detector |
| RC-003 | `rc_003_context_drift.py` | Conversation Context Drift Monitor |
| RC-004 | `rc_004_session_pivot.py` | Session Pivoting / Topic Hijack Detector |
| RC-005 | `rc_005_nested_injection.py` | Nested / Multi-turn Injection Detector |
| RC-006 | `rc_006_role_assertion_log.py` | Role Assertion Logging |
| RC-007 | `rc_007_context_integrity.py` | Context Integrity Validator |

## How to run this domain's demo standalone

```bash
pytest domains/domain2_role_context/tests/test_domain2_role_context.py -v
```

## Demo Package Checklist (fill in as you go)
- [ ] `tests/payloads.csv` has at least 10-15 real attack examples
- [ ] `tests/test_domain2_role_context.py` passes
- [ ] Short demo output / recording showing a malicious prompt being caught
- [ ] This README's "What this domain protects against" section is filled in
