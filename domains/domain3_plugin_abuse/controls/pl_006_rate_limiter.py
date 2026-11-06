"""
PL-006: Tool Call Rate Limiter
Domain: Domain 3: Plugin / Tool Abuse Monitoring
Owner: Pakeeza (Member 2, Domain 3 owner)

Enforces sliding-window rate limits across a session to prevent denial-of-service,
tool-call flooding, and automated resource exhaustion attacks. Limits are tracked
both in total calls per window and per specific tool.
"""

import time
from collections import Counter
from typing import Optional
from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class RateLimiterPL006(Control):
    control_id = "PL-006"
    domain = "Domain 3: Plugin / Tool Abuse Monitoring"
    layer = "execution"

    def __init__(self):
        super().__init__()
        # In-memory sliding window: session_id -> list of (timestamp, tool_name)
        self._history: dict[str, list[tuple[float, str]]] = {}

    def reset_history(self):
        """Helper for test isolation."""
        self._history.clear()

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain3_plugin_abuse")
        config = policy.get("rate_limiter", {})

        if not config.get("enabled", True):
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="Rate limiter disabled by policy.",
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

        window_seconds = float(config.get("window_seconds", 60))
        max_calls_total = int(config.get("max_calls_per_window", 20))
        max_calls_tool = int(config.get("max_calls_per_tool", 10))
        warn_ratio = float(config.get("warn_ratio", 0.8))

        session_id = ctx.session_id or "anonymous_session"
        now = time.time()

        # 1. Prune historical entries outside the sliding window
        cutoff = now - window_seconds
        current_history = [
            (ts, name) for (ts, name) in self._history.get(session_id, [])
            if ts >= cutoff
        ]

        # 2. Add all tool calls from the current request
        for call in tool_calls:
            if isinstance(call, dict):
                t_name = call.get("name", "unknown")
                ts = call.get("timestamp")
                try:
                    ts = float(ts) if ts is not None else now
                except (ValueError, TypeError):
                    ts = now
                current_history.append((ts, t_name))

        # Save updated history for this session
        self._history[session_id] = current_history

        total_calls = len(current_history)
        tool_counts = Counter(name for _, name in current_history)

        # 3. Check hard limits (Block)
        if total_calls > max_calls_total:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="block",
                risk_score=0.9,
                reason=(
                    f"Session rate limit exceeded: {total_calls} tool calls in {window_seconds:.0f}s "
                    f"window (maximum allowed: {max_calls_total})."
                ),
                evidence={
                    "session_id": session_id,
                    "total_calls_in_window": total_calls,
                    "max_calls_per_window": max_calls_total,
                    "window_seconds": window_seconds,
                    "tool_distribution": dict(tool_counts),
                },
            )

        for tool_name, count in tool_counts.items():
            if count > max_calls_tool:
                return Verdict(
                    control_id=self.control_id,
                    domain=self.domain,
                    status="block",
                    risk_score=0.9,
                    reason=(
                        f"Per-tool rate limit exceeded for tool '{tool_name}': {count} calls in "
                        f"{window_seconds:.0f}s window (maximum allowed: {max_calls_tool})."
                    ),
                    evidence={
                        "session_id": session_id,
                        "tool": tool_name,
                        "tool_calls_in_window": count,
                        "max_calls_per_tool": max_calls_tool,
                        "window_seconds": window_seconds,
                    },
                )

        # 4. Check warning thresholds (Warn)
        warn_total_threshold = max_calls_total * warn_ratio
        if total_calls >= warn_total_threshold:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="warn",
                risk_score=0.5,
                reason=(
                    f"Tool call volume approaching rate limit: {total_calls}/{max_calls_total} "
                    f"calls used ({int(total_calls / max_calls_total * 100)}%) in {window_seconds:.0f}s window."
                ),
                evidence={
                    "session_id": session_id,
                    "total_calls": total_calls,
                    "limit": max_calls_total,
                },
            )

        warn_tool_threshold = max_calls_tool * warn_ratio
        for tool_name, count in tool_counts.items():
            if count >= warn_tool_threshold:
                return Verdict(
                    control_id=self.control_id,
                    domain=self.domain,
                    status="warn",
                    risk_score=0.5,
                    reason=(
                        f"Tool '{tool_name}' volume approaching per-tool rate limit: "
                        f"{count}/{max_calls_tool} calls used in {window_seconds:.0f}s window."
                    ),
                    evidence={
                        "session_id": session_id,
                        "tool": tool_name,
                        "count": count,
                        "limit": max_calls_tool,
                    },
                )

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason=f"Rate limit check passed ({total_calls}/{max_calls_total} calls in window).",
            evidence={
                "session_id": session_id,
                "calls_in_window": total_calls,
                "window_seconds": window_seconds,
            },
        )


if __name__ == "__main__":
    control = RateLimiterPL006()

    # Test 1: Single normal call -> PASS
    ctx1 = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="calc",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "2+2"}}],
    )
    v1 = control.evaluate(ctx1)
    print(f"Test 1 (Normal call): {v1.status.upper()} (risk: {v1.risk_score}) - {v1.reason}")

    # Test 2: Burst of 30 calls in one request -> BLOCK (Reviewer's specific test!)
    ctx2 = RequestContext(
        session_id="s2",
        user_id="u2",
        raw_prompt="run burst",
        tool_calls=[{"name": "calculator", "arguments": {"expression": f"{i}+{i}"}} for i in range(30)],
    )
    v2 = control.evaluate(ctx2)
    print(f"Test 2 (30 calls burst): {v2.status.upper()} (risk: {v2.risk_score}) - {v2.reason}")

    # Test 3: Different session is unaffected -> PASS
    ctx3 = RequestContext(
        session_id="s3",
        user_id="u3",
        raw_prompt="calc",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "10*10"}}],
    )
    v3 = control.evaluate(ctx3)
    print(f"Test 3 (Separate session): {v3.status.upper()} (risk: {v3.risk_score}) - {v3.reason}")

