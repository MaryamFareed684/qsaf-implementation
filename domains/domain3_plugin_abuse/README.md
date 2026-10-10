# Domain 3: Plugin / Tool Abuse Monitoring

**Layer:** `execution`  
**Owner:** Pakeeza (Member 2, Domain 3 owner)  
**Status:** In Progress (Day 1: Allow-or-deny controls)

## Overview

**Threat protected against:** Plugin / Tool abuse — unauthorized tool invocation, execution of dangerous command arguments (e.g., shell injection, path traversal, bulk deletion), unauthorized access to sensitive tools, rapid tool-call flooding (denial of service), and multi-step data exfiltration via tool parameters.

**Attacker / failure source:** External prompt injection attacks instructing the agent to run unauthorized actions, malicious or poisoned tool outputs, or autonomous agent hallucination/drift deviating from user intent.

**Pipeline stage:** Execution — intercepts and monitors every tool invocation in `ctx.tool_calls` while the agent is executing, deciding whether to allow (`pass`), flag (`warn`), block (`block`), or require human intervention (`escalate`) before tool actions run or after results return.

## Controls in this domain

| Control ID | File | Description | Status |
|---|---|---|---|
| PL-001 | `pl_001_tool_whitelist.py` | Tool/Plugin Whitelist Enforcement & Schema Check | ✅ Implemented & tested |
| PL-002 | `pl_002_command_tracking.py` | Command & Argument Tracking (Secrets Redacted) | ✅ Implemented & tested |
| PL-003 | `pl_003_sensitive_tool_gate.py` | Sensitive Tool Access Gate (Role RBAC & Escalation) | ✅ Implemented & tested |
| PL-004 | `pl_004_tool_anomaly.py` | Tool Execution Anomaly Detector | ⏳ Stub (Day 2) |
| PL-005 | `pl_005_usage_correlation.py` | Cross-Tool Usage Correlation / Intent Matching | ⏳ Stub (Day 2) |
| PL-006 | `pl_006_rate_limiter.py` | Tool Call Rate Limiter | ⏳ Stub (Day 2) |
| PL-007 | `pl_007_session_terminator.py` | Session Termination on Critical Abuse | ⏳ Stub (Day 2) |

---

## Domain Metadata Contract

Per QSAF architectural rules, domain-specific parameters passed in `ctx.metadata` are prefixed with `domain3_`:

| Metadata Key | Type | Description | Used By |
|---|---|---|---|
| `domain3_user_role` | `str` | Security role of the invoking user (e.g., `"user"`, `"admin"`, `"analyst"`). Defaults to `"user"`. | PL-003 |
| `domain3_approved_actions` | `list[str]` | List of sensitive tool names that have received human confirmation/approval. | PL-003 |
| `domain3_tool_definitions` | `list[dict]` | Registered tool specifications (name, description, parameters) used for integrity hashing. | PL-008 (Day 3) |

---

## Control Details

### PL-001 — Tool Whitelist & Argument Check
- **Description:** Verifies requested tools in `ctx.tool_calls` against an allowlist in `policy.yaml` and enforces parameter schema structure and argument types.
- **Key risks addressed:** Unauthorized tool execution, arbitrary code or plugin invocation, and parameter spoofing.
- **What it checks:**
  - Checks if `tool_name` is present in `allowed_tools`.
  - In `strict_schema` mode, checks that all `required_args` exist and match configured Python types (`str`, `int`, `float`, `bool`, `list`, `dict`).
- **Verdict behavior:**
  - `pass` (risk `0.0`): All tools are whitelisted and argument schemas match.
  - `warn` (risk `0.3`-`0.4`): Malformed call or empty allowlist configuration.
  - `block` (risk `0.9`): Tool not on allowlist or required arguments/types missing or invalid.
- **Example scenarios:**
  - `calculator` with `{"expression": "2+2"}` $\rightarrow$ `pass`
  - `delete_file` $\rightarrow$ `block` (not on whitelist)
  - `calculator` with missing `expression` $\rightarrow$ `block`

### PL-002 — Command & Argument Tracking
- **Description:** Deep inspection of tool command strings and parameters for destructive patterns, shell chaining, and path traversal, while sanitizing and redacting credentials before logging.
- **Key risks addressed:** Remote command execution, destructive commands (`rm -rf`, `DROP TABLE`), path traversal (`../../etc/passwd`), credential leakage in audit logs.
- **What it checks:**
  - Evaluates invocations against regex lists: `dangerous_patterns` (destructive) and `suspicious_patterns` (chaining).
  - Sanitizes API keys, tokens, and passwords into `[REDACTED]` within `audit_records`.
- **Verdict behavior:**
  - `pass` (risk `0.0`): Safe command parameters; structured, redacted audit record placed in `evidence["audit_records"]`.
  - `warn` (risk `0.6`): Chained command operators detected (`&&`, `;`, `|`).
  - `block` (risk `1.0`): Destructive commands or path traversal attempts detected.
- **Example scenarios:**
  - `system_command` with `"ls -la"` $\rightarrow$ `pass`
  - `system_command` with `"rm -rf /"` $\rightarrow$ `block`
  - `read_file` with `"../../etc/passwd"` $\rightarrow$ `block`
  - `web_search` with `{"api_key": "sk-1234"}` $\rightarrow$ `pass` with redacted audit record `[REDACTED]`.

### PL-003 — Sensitive Tool Access Gate
- **Description:** Gatekeeper for high-privilege tools (e.g., file deletion, sending external email, code execution). Enforces role-based permissions and human-in-the-loop escalation.
- **Key risks addressed:** Privilege escalation, unauthorized high-impact operations, unreviewed actions taking effect autonomously.
- **What it checks:**
  - Reads `ctx.metadata.get("domain3_user_role", "user")`.
  - Checks whether the user's role is in the tool's `allowed_roles`.
  - If `requires_approval` is enabled, verifies that the tool name is listed in `ctx.metadata["domain3_approved_actions"]`.
- **Verdict behavior:**
  - `pass` (risk `0.0`): Tool is non-sensitive, or role is permitted and human approval was provided.
  - `block` (risk `0.95`): User role is not authorized for this sensitive tool.
  - `escalate` (risk `0.7`): Role is permitted, but required human approval is missing.
- **Example scenarios:**
  - `delete_file` invoked by role `"user"` $\rightarrow$ `block`
  - `send_email` invoked by role `"user"` without human approval $\rightarrow$ `escalate`
  - `send_email` with approval in `domain3_approved_actions` $\rightarrow$ `pass`

---

## How to test Domain 3

```bash
# Run Domain 3 tests standalone
pytest domains/domain3_plugin_abuse/tests/ -v

# Run the complete end-to-end integration test
pytest tests/integration/ -v
```

## Demo Package Checklist (fill in as you go)
- [x] Stage 1 overview filled in
- [x] Full `policy.yaml` skeleton established
- [x] PL-001 implemented and tested
- [x] PL-002 implemented and tested
- [x] PL-003 implemented and tested
- [x] `tests/test_domain3_plugin_abuse.py` passes (21/21 passed)
- [x] Integration tests pass (4/4 passed)
- [ ] Day 2 controls (PL-004 to PL-007)
- [ ] Day 3 controls (PL-008 to PL-010) & standalone demo

