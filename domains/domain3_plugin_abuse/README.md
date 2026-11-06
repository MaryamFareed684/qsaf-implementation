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
| PL-004 | `pl_004_tool_anomaly.py` | Tool Execution Anomaly Detector (Z-Score & Latency Caps) | ✅ Implemented & tested |
| PL-005 | `pl_005_usage_correlation.py` | Cross-Tool Usage Correlation / Intent Matching | ✅ Implemented & tested |
| PL-006 | `pl_006_rate_limiter.py` | Tool Call Rate Limiter (Sliding Window & Burst Cap) | ✅ Implemented & tested |
| PL-007 | `pl_007_session_terminator.py` | Session Termination on Critical Abuse (Strike System) | ✅ Implemented & tested |


---

## Domain Metadata Contract

Per QSAF architectural rules, domain-specific parameters passed in `ctx.metadata` are prefixed with `domain3_`:

| Metadata Key | Type | Description | Used By |
|---|---|---|---|
| `domain3_user_role` | `str` | Security role of the invoking user (e.g., `"user"`, `"admin"`, `"analyst"`). Defaults to `"user"`. | PL-003, PL-007 |
| `domain3_approved_actions` | `list[str]` | List of sensitive tool names that have received human confirmation/approval. | PL-003 |
| `domain3_strike` / `domain3_breach` | `bool` | Explicit signal indicating an external or cross-domain security breach strike. | PL-007 |
| `domain3_breach_reason` | `str` | Reason description accompanying an explicit breach strike. | PL-007 |
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

### PL-004 — Tool Execution Anomaly Detector
- **Description:** Monitors execution duration (`duration_ms`) of tool calls. Flags runs that take unusually long via statistical z-score analysis ($z > 3.0$) or expected baseline cutoffs, and immediately blocks runs exceeding the hard safety limit (10,000 ms).
- **Key risks addressed:** Hanging tool invocations, denial-of-service, runaway recursions, computational resource exhaustion.
- **Verdict behavior:**
  - `pass` (risk `0.0`): Execution duration within normal statistical range, or duration missing (cannot judge).
  - `warn` (risk `0.5`-`0.65`): Duration exceeds tool's expected maximum or statistical baseline outlier ($z > 3.0$).
  - `block` (risk `0.95`): Duration exceeds hard safety limit (10,000 ms).

### PL-005 — Cross-Tool Usage Correlation / Intent Matching
- **Description:** Verifies that tool calls in `ctx.tool_calls` match the intent of the user prompt and recent conversation history using keyword correlation mappings.
- **Key risks addressed:** Tool drift, indirect prompt injection tricking an agent into using unrequested tools, silent exfiltration.
- **Verdict behavior:**
  - `pass` (risk `0.0`): Tool call matches intent keywords in user prompt.
  - `warn` (risk `0.5`): Tool call does not match prompt intent for a normal tool.
  - `escalate` (risk `0.75`): Uncorrelated invocation of a sensitive tool (requires human confirmation).

### PL-006 — Tool Call Rate Limiter
- **Description:** Tracks total and per-tool invocations over a sliding window (60s) per session. Prevents rapid automated abuse, high-frequency flooding, and denial-of-service.
- **Key risks addressed:** Rate limit flooding, agent loop runaway, automated scraping and API quota exhaustion.
- **Verdict behavior:**
  - `pass` (risk `0.0`): Calls within safe threshold (< 80% capacity).
  - `warn` (risk `0.5`): Calls approaching window limit (80%-100% capacity).
  - `block` (risk `0.9`): Calls exceed window limit (> 20 calls/min or > 10 calls/tool).

### PL-007 — Session Termination on Critical Abuse
- **Description:** Maintains persistent strike tracking per user session. Accumulates strikes on security violations (disallowed tools, destructive commands, unapproved sensitive access) and issues warnings before hard session termination.
- **Key risks addressed:** Persistent brute-forcing, repeated attack payloads, multi-turn escalation attempts.
- **Verdict behavior:**
  - `pass` (risk `0.0`): Clean session (0-1 strikes).
  - `warn` (risk `0.7`): Approaching threshold (2 strikes).
  - `block` (risk `1.0`): Session terminated (3 strikes reached within 300s window; `evidence["terminate_session"] = True`).

---

## Evaluation Metrics & Standalone Demo

Run the standalone demo:
```bash
python domains/domain3_plugin_abuse/demo_domain3.py
```

> **Evaluation Methodology:** Metrics are evaluated across the 10 demonstration scenarios, covering benign executions (math calculation, file reading, web search, approved email), authorization gates, command injection, path traversal, prompt-tool drift, call flooding, and persistent strike accumulation.

### Verified Metrics Output:
- **Attack-Blocking Rate:** 100.0% (target: $\ge$ 90%)
- **False-Positive Rate:** 0.0% (target: $\le$ 5%)
- **Average Check Latency:** 5.09 ms (target: < 50 ms)
- **Active Controls:** 7 of 7 official QSAF execution controls active and tested

---

## How to Test Domain 3

```bash
# Run Domain 3 standalone test suite (49 tests)
pytest domains/domain3_plugin_abuse/tests/ -v

# Run the complete end-to-end integration test
pytest tests/integration/ -v
```

## Demo Package Checklist
- [x] Stage 1 overview filled in
- [x] Full `policy.yaml` skeleton established
- [x] PL-001 implemented and tested
- [x] PL-002 implemented and tested
- [x] PL-003 implemented and tested
- [x] PL-004 implemented and tested
- [x] PL-005 implemented and tested
- [x] PL-006 implemented and tested
- [x] PL-007 implemented and tested
- [x] `tests/test_domain3_plugin_abuse.py` passes (49/49 passed)
- [x] Integration tests pass (4/4 passed)
- [x] Standalone demo (`demo_domain3.py`) fully working with metrics output


