"""
PL-002: Command & Argument Tracking
Domain: Domain 3: Plugin / Tool Abuse Monitoring
Owner: Pakeeza (Member 2, Domain 3 owner)

Tracks tool execution at the command and argument level. Inspects commands
for destructive or suspicious execution patterns (e.g. shell chaining, path
traversal, bulk deletion) and redacts sensitive credentials before audit logging.
"""

import json
import re
from typing import Any
from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class CommandTrackingPL002(Control):
    control_id = "PL-002"
    domain = "Domain 3: Plugin / Tool Abuse Monitoring"
    layer = "execution"

    def _redact_value(self, val: Any, redact_patterns: list[str]) -> Any:
        if isinstance(val, dict):
            redacted_dict = {}
            for k, v in val.items():
                if any(re.search(s, str(k), re.IGNORECASE) for s in ["api[_-]?key", "password", "token", "secret", "passwd"]):
                    redacted_dict[k] = "[REDACTED]"
                else:
                    redacted_dict[k] = self._redact_value(v, redact_patterns)
            return redacted_dict
        if isinstance(val, list):
            return [self._redact_value(item, redact_patterns) for item in val]
        if not isinstance(val, str):
            return val

        redacted = val
        # Check standard key patterns like api_key=xyz, password: xyz
        for pattern in redact_patterns:
            try:
                # If regex has groups, redact the sensitive group
                def _replacer(m):
                    if m.lastindex and m.lastindex >= 2:
                        # replace the second group (value)
                        start, end = m.span(2)
                        full = m.group(0)
                        prefix = full[: start - m.start(0)]
                        suffix = full[end - m.start(0) :]
                        return f"{prefix}[REDACTED]{suffix}"
                    return "[REDACTED]"

                redacted = re.sub(pattern, _replacer, redacted)
            except Exception:
                continue

        # Common fallback for literal api_key / token strings
        redacted = re.sub(r"(?i)(api[_-]?key|password|token|secret|passwd)\s*[:=]\s*['\"]?([^\s'\",}]+)", r"\1=[REDACTED]", redacted)
        return redacted

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain3_plugin_abuse")
        config = policy.get("command_tracking", {})

        if not config.get("enabled", True):
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="Command tracking is disabled by policy.",
                evidence={},
            )

        tool_calls = ctx.tool_calls or []
        if not tool_calls:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="No tool calls requested in execution context.",
                evidence={},
            )

        dangerous_patterns = config.get("dangerous_patterns", [])
        suspicious_patterns = config.get("suspicious_patterns", [])
        redact_patterns = config.get("redact_patterns", [])
        max_chars = int(config.get("max_logged_argument_chars", 500))
        danger_risk = float(config.get("danger_risk_score", 1.0))
        suspicious_risk = float(config.get("suspicious_risk_score", 0.6))

        audit_records = []
        dangerous_match = None
        suspicious_match = None

        for idx, call in enumerate(tool_calls):
            if not isinstance(call, dict):
                continue
            tool_name = call.get("name", "unknown")
            args = call.get("arguments") or {}

            # Prepare string representation for inspection
            args_serialized = json.dumps(args) if isinstance(args, (dict, list)) else str(args)
            inspection_target = f"{tool_name} {args_serialized}"

            # Check 1: Dangerous patterns (block)
            for pat in dangerous_patterns:
                if re.search(pat, inspection_target, re.IGNORECASE):
                    dangerous_match = {"tool": tool_name, "pattern": pat, "call_index": idx}
                    break

            # Check 2: Suspicious patterns (warn)
            if not dangerous_match:
                for pat in suspicious_patterns:
                    if re.search(pat, inspection_target, re.IGNORECASE):
                        suspicious_match = {"tool": tool_name, "pattern": pat, "call_index": idx}
                        break

            # Redact secrets from arguments for clean audit record
            redacted_args = self._redact_value(args, redact_patterns)
            redacted_args_str = json.dumps(redacted_args) if isinstance(redacted_args, (dict, list)) else str(redacted_args)
            if len(redacted_args_str) > max_chars:
                redacted_args_str = redacted_args_str[:max_chars] + "...[TRUNCATED]"

            audit_records.append({
                "session_id": ctx.session_id,
                "user_id": ctx.user_id,
                "tool": tool_name,
                "arguments": redacted_args_str,
            })

            if dangerous_match:
                break

        if dangerous_match:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="block",
                risk_score=danger_risk,
                reason=(
                    f"Destructive/dangerous pattern detected in tool '{dangerous_match['tool']}': "
                    f"'{dangerous_match['pattern']}'."
                ),
                evidence={
                    "dangerous_match": dangerous_match,
                    "audit_records": audit_records,
                },
            )

        if suspicious_match:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="warn",
                risk_score=suspicious_risk,
                reason=(
                    f"Suspicious command execution pattern detected in tool '{suspicious_match['tool']}': "
                    f"'{suspicious_match['pattern']}'."
                ),
                evidence={
                    "suspicious_match": suspicious_match,
                    "audit_records": audit_records,
                },
            )

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason=f"All {len(audit_records)} command(s) verified safe and clean audit records created.",
            evidence={"audit_records": audit_records},
        )


if __name__ == "__main__":
    control = CommandTrackingPL002()

    # Test 1: Benign command -> PASS
    ctx1 = RequestContext(
        session_id="s1",
        user_id="alice",
        raw_prompt="List files in current directory",
        tool_calls=[{"name": "system_command", "arguments": {"cmd": "ls -la"}}],
    )
    v1 = control.evaluate(ctx1)
    print(f"Test 1 (Normal command): {v1.status.upper()} (risk: {v1.risk_score}) - {v1.reason}")

    # Test 2: Destructive pattern (rm -rf /) -> BLOCK
    ctx2 = RequestContext(
        session_id="s2",
        user_id="attacker",
        raw_prompt="Remove system root",
        tool_calls=[{"name": "system_command", "arguments": {"cmd": "rm -rf /"}}],
    )
    v2 = control.evaluate(ctx2)
    print(f"Test 2 (Destructive pattern): {v2.status.upper()} (risk: {v2.risk_score}) - {v2.reason}")

    # Test 3: Path traversal trick (../../etc/passwd) -> BLOCK
    ctx3 = RequestContext(
        session_id="s3",
        user_id="attacker",
        raw_prompt="Read system password file",
        tool_calls=[{"name": "read_file", "arguments": {"filepath": "../../etc/passwd"}}],
    )
    v3 = control.evaluate(ctx3)
    print(f"Test 3 (Path traversal): {v3.status.upper()} (risk: {v3.risk_score}) - {v3.reason}")

    # Test 4: Chained command (suspicious) -> WARN
    ctx4 = RequestContext(
        session_id="s4",
        user_id="bob",
        raw_prompt="Check disk and chain another command",
        tool_calls=[{"name": "system_command", "arguments": {"cmd": "df -h && free -m"}}],
    )
    v4 = control.evaluate(ctx4)
    print(f"Test 4 (Chained command): {v4.status.upper()} (risk: {v4.risk_score}) - {v4.reason}")

    # Test 5: Redaction in evidence
    ctx5 = RequestContext(
        session_id="s5",
        user_id="alice",
        raw_prompt="Authenticate service",
        tool_calls=[{"name": "web_search", "arguments": {"query": "weather", "api_key": "sk-secret12345"}}],
    )
    v5 = control.evaluate(ctx5)
    print(f"Test 5 (Redaction): {v5.status.upper()} - Audit Record: {v5.evidence['audit_records'][0]['arguments']}")

