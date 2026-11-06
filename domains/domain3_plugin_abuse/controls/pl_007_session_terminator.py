"""
PL-007: Session Termination on Critical Abuse
Domain: Domain 3: Plugin / Tool Abuse Monitoring
Owner: Pakeeza (Member 2, Domain 3 owner)

Tracks security strikes and persistent violations across a user session.
Issues warnings upon reaching warning thresholds and triggers immediate
session termination (status="block", risk_score=1.0, terminate_session=True)
when cumulative strikes exceed the critical limit within the configured window.
"""

import time
import re
from typing import Optional
from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class SessionTerminatorPL007(Control):
    control_id = "PL-007"
    domain = "Domain 3: Plugin / Tool Abuse Monitoring"
    layer = "execution"

    def __init__(self):
        super().__init__()
        # In-memory strike tracking: session_id -> list of strike timestamps
        self._strikes: dict[str, list[float]] = {}

    def reset_history(self):
        """Helper for test isolation."""
        self._strikes.clear()

    def _is_breach(self, ctx: RequestContext, policy: dict) -> tuple[bool, str]:
        """Detect whether the current request constitutes a security breach."""
        # 1. Explicit metadata strike signal
        if ctx.metadata.get("domain3_breach") or ctx.metadata.get("strike"):
            return True, ctx.metadata.get("breach_reason", "Explicit breach metadata flag")

        # 2. Check tool calls against dangerous patterns or unauthorized sensitive tools
        tool_whitelist_cfg = policy.get("tool_whitelist", {})
        allowed_tools = tool_whitelist_cfg.get("allowed_tools", [])
        command_cfg = policy.get("command_tracking", {})
        dangerous_patterns = command_cfg.get("dangerous_patterns", [])

        sensitive_cfg = policy.get("sensitive_tool_gate", {})
        sensitive_tools = sensitive_cfg.get("sensitive_tools", {})
        approved_actions = ctx.metadata.get("domain3_approved_actions", [])
        if isinstance(approved_actions, str):
            approved_actions = [approved_actions]

        for call in ctx.tool_calls or []:
            if not isinstance(call, dict):
                continue
            t_name = call.get("name", "")
            args = str(call.get("arguments", ""))

            # Disallowed tool violation
            if allowed_tools and t_name and t_name not in allowed_tools:
                return True, f"Attempted invocation of unauthorized tool: '{t_name}'"

            # Dangerous command pattern
            for pat in dangerous_patterns:
                if re.search(pat, f"{t_name} {args}", re.IGNORECASE):
                    return True, f"Dangerous command pattern in tool '{t_name}'"

            # Sensitive tool without approval
            if t_name in sensitive_tools:
                tool_rule = sensitive_tools[t_name]
                if tool_rule.get("requires_approval", False) and t_name not in approved_actions:
                    return True, f"Unapproved execution of sensitive tool '{t_name}'"

        return False, ""

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain3_plugin_abuse")
        config = policy.get("session_terminator", {})

        if not config.get("enabled", True):
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="Session terminator disabled by policy.",
                evidence={},
            )

        warn_strikes = int(config.get("warn_after_strikes", 2))
        terminate_strikes = int(config.get("terminate_after_strikes", 3))
        window_seconds = float(config.get("strike_window_seconds", 300))

        session_id = ctx.session_id or "anonymous_session"
        now = time.time()

        # Prune strikes outside the window
        cutoff = now - window_seconds
        active_strikes = [
            ts for ts in self._strikes.get(session_id, [])
            if ts >= cutoff
        ]

        # Check for breach in current request
        is_breach, reason = self._is_breach(ctx, policy)
        if is_breach:
            active_strikes.append(now)

        self._strikes[session_id] = active_strikes
        count = len(active_strikes)

        # Termination threshold reached (Block)
        if count >= terminate_strikes:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="block",
                risk_score=1.0,
                reason=(
                    f"Session '{session_id}' terminated: accumulated {count} security breach strike(s) "
                    f"within {window_seconds:.0f}s (threshold: {terminate_strikes}). Last breach: {reason}."
                ),
                evidence={
                    "session_id": session_id,
                    "strike_count": count,
                    "terminate_session": True,
                    "window_seconds": window_seconds,
                    "last_breach_reason": reason,
                },
            )

        # Warning threshold reached (Warn)
        if count >= warn_strikes:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="warn",
                risk_score=0.7,
                reason=(
                    f"Session '{session_id}' approaching termination: {count}/{terminate_strikes} "
                    f"security breach strike(s) recorded."
                ),
                evidence={
                    "session_id": session_id,
                    "strike_count": count,
                    "terminate_session": False,
                    "window_seconds": window_seconds,
                },
            )

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason=f"Session in good standing ({count}/{terminate_strikes} strikes).",
            evidence={
                "session_id": session_id,
                "strike_count": count,
                "terminate_session": False,
            },
        )


if __name__ == "__main__":
    control = SessionTerminatorPL007()

    # Breach 1: Strike 1 -> PASS (good standing, 1 strike)
    ctx1 = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="attack 1",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/etc/passwd"}}],
    )
    v1 = control.evaluate(ctx1)
    print(f"Breach 1: {v1.status.upper()} (risk: {v1.risk_score}) - {v1.reason}")

    # Breach 2: Strike 2 -> WARN (approaching limit)
    ctx2 = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="attack 2",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/var/log"}}],
    )
    v2 = control.evaluate(ctx2)
    print(f"Breach 2: {v2.status.upper()} (risk: {v2.risk_score}) - {v2.reason}")

    # Breach 3: Strike 3 -> BLOCK & TERMINATE
    ctx3 = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="attack 3",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/tmp/data"}}],
    )
    v3 = control.evaluate(ctx3)
    print(f"Breach 3: {v3.status.upper()} (risk: {v3.risk_score}) - Terminate={v3.evidence.get('terminate_session')} - {v3.reason}")

    # Separate session s2 -> unaffected (PASS)
    ctx4 = RequestContext(
        session_id="s2",
        user_id="u2",
        raw_prompt="normal query",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "1+1"}}],
    )
    v4 = control.evaluate(ctx4)
    print(f"Clean session s2: {v4.status.upper()} (risk: {v4.risk_score}) - {v4.reason}")

