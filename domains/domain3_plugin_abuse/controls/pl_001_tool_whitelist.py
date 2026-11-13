"""
PL-001: Tool Whitelist & Argument Check
Domain: Domain 3: Plugin / Tool Abuse Monitoring
Owner: Pakeeza (Member 2, Domain 3 owner)

Verifies every tool requested in ctx.tool_calls against a strict whitelist of
approved tools and validates required argument schemas and types.
"""

from typing import Any
from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class ToolWhitelistPL001(Control):
    control_id = "PL-001"
    domain = "Domain 3: Plugin / Tool Abuse Monitoring"
    layer = "execution"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain3_plugin_abuse")
        config = policy.get("tool_whitelist", {})

        if not config.get("enabled", True):
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="Tool whitelist check is disabled by policy.",
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

        allowed_tools = config.get("allowed_tools", [])
        if not allowed_tools:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="warn",
                risk_score=0.3,
                reason="Allowed tools whitelist is empty in policy configuration (setup warning).",
                evidence={"tool_calls_count": len(tool_calls)},
            )

        tool_schemas = config.get("tool_schemas", {})
        strict_schema = config.get("strict_schema", True)
        violation_risk = float(config.get("violation_risk_score", 0.9))

        type_map = {
            "str": str,
            "int": int,
            "float": (int, float),
            "bool": bool,
            "list": list,
            "dict": dict,
        }

        checked_tools = []
        for idx, call in enumerate(tool_calls):
            if not isinstance(call, dict):
                return Verdict(
                    control_id=self.control_id,
                    domain=self.domain,
                    status="warn",
                    risk_score=0.4,
                    reason=f"Tool call at index {idx} is malformed (not a dictionary).",
                    evidence={"call_index": idx, "raw_call": str(call)},
                )

            tool_name = call.get("name")
            if not tool_name or not isinstance(tool_name, str) or not tool_name.strip():
                return Verdict(
                    control_id=self.control_id,
                    domain=self.domain,
                    status="warn",
                    risk_score=0.4,
                    reason=f"Tool call at index {idx} has missing or invalid tool name.",
                    evidence={"call_index": idx, "call": str(call)},
                )

            tool_name = tool_name.strip()
            checked_tools.append(tool_name)

            # Check 1: Tool Whitelist check
            if tool_name not in allowed_tools:
                return Verdict(
                    control_id=self.control_id,
                    domain=self.domain,
                    status="block",
                    risk_score=violation_risk,
                    reason=f"Tool '{tool_name}' is not in the approved whitelist.",
                    evidence={
                        "blocked_tool": tool_name,
                        "allowed_tools": allowed_tools,
                        "call_index": idx,
                    },
                )

            # Check 2: Argument Schema & Type Validation
            args = call.get("arguments")
            if args is None:
                args = {}

            if not isinstance(args, dict):
                if strict_schema:
                    return Verdict(
                        control_id=self.control_id,
                        domain=self.domain,
                        status="block",
                        risk_score=violation_risk,
                        reason=f"Arguments for tool '{tool_name}' must be a dictionary/object.",
                        evidence={"tool": tool_name, "arguments": str(args)},
                    )
                args = {}

            schema = tool_schemas.get(tool_name, {})
            required_args = schema.get("required_args", [])
            arg_types = schema.get("arg_types", {})

            # Required arguments check
            missing_args = [arg for arg in required_args if arg not in args or args[arg] is None]
            if missing_args and strict_schema:
                return Verdict(
                    control_id=self.control_id,
                    domain=self.domain,
                    status="block",
                    risk_score=violation_risk,
                    reason=f"Tool '{tool_name}' missing required argument(s): {', '.join(missing_args)}.",
                    evidence={"tool": tool_name, "missing_args": missing_args},
                )

            # Argument types check
            if strict_schema and arg_types:
                for arg_key, expected_type_str in arg_types.items():
                    if arg_key in args and args[arg_key] is not None:
                        expected_type = type_map.get(expected_type_str)
                        val = args[arg_key]
                        if expected_type is int and isinstance(val, bool):
                            matches = False
                        elif expected_type:
                            matches = isinstance(val, expected_type)
                        else:
                            matches = True

                        if not matches:
                            return Verdict(
                                control_id=self.control_id,
                                domain=self.domain,
                                status="block",
                                risk_score=violation_risk,
                                reason=(
                                    f"Tool '{tool_name}' argument '{arg_key}' expected type "
                                    f"'{expected_type_str}', got '{type(val).__name__}'."
                                ),
                                evidence={
                                    "tool": tool_name,
                                    "arg": arg_key,
                                    "expected_type": expected_type_str,
                                    "actual_type": type(val).__name__,
                                },
                            )

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason=f"All {len(checked_tools)} tool call(s) passed whitelist and schema validation.",
            evidence={"approved_tools": checked_tools},
        )


if __name__ == "__main__":
    control = ToolWhitelistPL001()

    # Self-test 1: Allowed tool with valid args -> pass
    ctx_pass = RequestContext(
        session_id="s1",
        user_id="user1",
        raw_prompt="Calculate 2 + 2",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "2+2"}}],
    )
    v1 = control.evaluate(ctx_pass)
    print(f"Test 1 (Safe tool): {v1.status.upper()} (risk: {v1.risk_score}) - {v1.reason}")

    # Self-test 2: Disallowed tool -> block
    ctx_block = RequestContext(
        session_id="s2",
        user_id="user2",
        raw_prompt="Delete sensitive log file",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/etc/passwd"}}],
    )
    v2 = control.evaluate(ctx_block)
    print(f"Test 2 (Disallowed tool): {v2.status.upper()} (risk: {v2.risk_score}) - {v2.reason}")

    # Self-test 3: Allowed tool with missing required arg -> block
    ctx_missing_arg = RequestContext(
        session_id="s3",
        user_id="user3",
        raw_prompt="Calculate something",
        tool_calls=[{"name": "calculator", "arguments": {}}],
    )
    v3 = control.evaluate(ctx_missing_arg)
    print(f"Test 3 (Missing arg): {v3.status.upper()} (risk: {v3.risk_score}) - {v3.reason}")

    # Self-test 4: Allowed tool with web search -> pass
    ctx_search = RequestContext(
        session_id="s4",
        user_id="user4",
        raw_prompt="Search latest AI security papers",
        tool_calls=[{"name": "web_search", "arguments": {"query": "QSAF AI security"}}],
    )
    v4 = control.evaluate(ctx_search)
    print(f"Test 4 (Web search): {v4.status.upper()} (risk: {v4.risk_score}) - {v4.reason}")

