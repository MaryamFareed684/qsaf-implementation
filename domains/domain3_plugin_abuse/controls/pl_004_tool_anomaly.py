"""
PL-004: Tool Execution Anomaly Detector
Domain: Domain 3: Plugin / Tool Abuse Monitoring
Owner: Pakeeza (Member 2, Domain 3 owner)

Monitors the execution duration (duration_ms) of tool calls. Flags tool runs
that take unusually long based on historical z-score anomaly analysis or
configured maximum expected latency, and blocks execution if hard safety
limits are exceeded.
"""

import math
from typing import Optional
from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class ToolAnomalyPL004(Control):
    control_id = "PL-004"
    domain = "Domain 3: Plugin / Tool Abuse Monitoring"
    layer = "execution"

    def __init__(self):
        super().__init__()
        # In-memory history per tool: tool_name -> list of durations (ms)
        self._history: dict[str, list[float]] = {}

    def reset_history(self):
        """Helper for test isolation."""
        self._history.clear()

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain3_plugin_abuse")
        config = policy.get("tool_anomaly", {})

        if not config.get("enabled", True):
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="Tool execution anomaly detection disabled by policy.",
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

        max_expected_map = config.get("max_expected_ms", {})
        z_threshold = float(config.get("z_score_threshold", 3.0))
        min_samples = int(config.get("min_samples", 10))
        hard_limit_ms = float(config.get("hard_limit_ms", 10000))
        hard_limit_risk = float(config.get("hard_limit_risk_score", 0.95))
        z_score_risk = float(config.get("z_score_risk_score", 0.65))
        expected_max_risk = float(config.get("expected_max_risk_score", 0.5))

        checked_calls = []
        for idx, call in enumerate(tool_calls):
            if not isinstance(call, dict):
                continue

            tool_name = call.get("name", "unknown")
            duration_ms = call.get("duration_ms")

            # If duration is missing, we cannot judge timing anomaly (safe pass per QSAF design)
            if duration_ms is None:
                checked_calls.append({"tool": tool_name, "status": "no_duration"})
                continue

            try:
                duration = float(duration_ms)
            except (ValueError, TypeError):
                continue

            checked_calls.append({"tool": tool_name, "duration_ms": duration})

            # Check 1: Hard safety limit (Block)
            if duration > hard_limit_ms:
                return Verdict(
                    control_id=self.control_id,
                    domain=self.domain,
                    status="block",
                    risk_score=hard_limit_risk,
                    reason=(
                        f"Tool '{tool_name}' execution time ({duration:.1f} ms) exceeded "
                        f"hard safety limit ({hard_limit_ms:.1f} ms)."
                    ),
                    evidence={
                        "tool": tool_name,
                        "duration_ms": duration,
                        "hard_limit_ms": hard_limit_ms,
                        "call_index": idx,
                    },
                )

            # Check 2: Statistical Z-Score Anomaly (Warn)
            history = self._history.setdefault(tool_name, [])
            if len(history) >= min_samples:
                mean = sum(history) / len(history)
                variance = sum((x - mean) ** 2 for x in history) / len(history)
                std_dev = math.sqrt(variance)

                if std_dev > 0.001:
                    z_score = (duration - mean) / std_dev
                    if z_score > z_threshold:
                        history.append(duration)
                        return Verdict(
                            control_id=self.control_id,
                            domain=self.domain,
                            status="warn",
                            risk_score=z_score_risk,
                            reason=(
                                f"Execution time anomaly detected for tool '{tool_name}': "
                                f"duration {duration:.1f} ms is {z_score:.2f} standard deviations "
                                f"above baseline (mean: {mean:.1f} ms, threshold: {z_threshold})."
                            ),
                            evidence={
                                "tool": tool_name,
                                "duration_ms": duration,
                                "mean_ms": round(mean, 2),
                                "std_dev_ms": round(std_dev, 2),
                                "z_score": round(z_score, 2),
                                "sample_count": len(history),
                            },
                        )

            # Check 3: Configured Expected Maximum Duration (Warn)
            expected_max = max_expected_map.get(tool_name)
            if expected_max is not None and duration > float(expected_max):
                history.append(duration)
                return Verdict(
                    control_id=self.control_id,
                    domain=self.domain,
                    status="warn",
                    risk_score=expected_max_risk,
                    reason=(
                        f"Tool '{tool_name}' execution time ({duration:.1f} ms) exceeded "
                        f"expected baseline maximum ({float(expected_max):.1f} ms)."
                    ),
                    evidence={
                        "tool": tool_name,
                        "duration_ms": duration,
                        "max_expected_ms": expected_max,
                    },
                )

            # Record baseline sample
            history.append(duration)

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason=f"All {len(checked_calls)} tool call duration(s) within normal limits.",
            evidence={"inspected_durations": checked_calls},
        )


if __name__ == "__main__":
    control = ToolAnomalyPL004()

    # Test 1: Normal duration within expected limit -> PASS
    ctx1 = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="Calculate 2+2",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "2+2"}, "duration_ms": 120}],
    )
    v1 = control.evaluate(ctx1)
    print(f"Test 1 (Normal duration): {v1.status.upper()} (risk: {v1.risk_score}) - {v1.reason}")

    # Test 2: Missing duration -> PASS (cannot judge)
    ctx2 = RequestContext(
        session_id="s2",
        user_id="u2",
        raw_prompt="Search query",
        tool_calls=[{"name": "web_search", "arguments": {"query": "weather"}}],
    )
    v2 = control.evaluate(ctx2)
    print(f"Test 2 (Missing duration): {v2.status.upper()} (risk: {v2.risk_score}) - {v2.reason}")

    # Test 3: Exceeding hard limit -> BLOCK
    ctx3 = RequestContext(
        session_id="s3",
        user_id="u3",
        raw_prompt="Calculate something huge",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "2**1000"}, "duration_ms": 15000}],
    )
    v3 = control.evaluate(ctx3)
    print(f"Test 3 (Exceeds hard limit): {v3.status.upper()} (risk: {v3.risk_score}) - {v3.reason}")

    # Test 4: Z-Score anomaly (10 normal samples followed by an outlier) -> WARN
    control.reset_history()
    for _ in range(10):
        control.evaluate(
            RequestContext(
                session_id="s4",
                user_id="u4",
                raw_prompt="test",
                tool_calls=[{"name": "read_file", "arguments": {"filepath": "doc.txt"}, "duration_ms": 100}],
            )
        )
    ctx_outlier = RequestContext(
        session_id="s4",
        user_id="u4",
        raw_prompt="test",
        tool_calls=[{"name": "read_file", "arguments": {"filepath": "doc.txt"}, "duration_ms": 2500}],
    )
    v4 = control.evaluate(ctx_outlier)
    print(f"Test 4 (Statistical anomaly): {v4.status.upper()} (risk: {v4.risk_score}) - {v4.reason}")

