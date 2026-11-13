"""
PL-003: Sensitive Tool Access Gate
Domain: Domain 3: Plugin / Tool Abuse Monitoring
Owner: Pakeeza (Member 2, Domain 3 owner)

Enforces role-based access control and human approval escalation for sensitive,
high-privilege, or dangerous agent tools.
"""

from typing import Any
from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class SensitiveToolGatePL003(Control):
    control_id = "PL-003"
    domain = "Domain 3: Plugin / Tool Abuse Monitoring"
    layer = "execution"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain3_plugin_abuse")
        config = policy.get("sensitive_tool_gate", {})

        if not config.get("enabled", True):
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="Sensitive tool access gate is disabled by policy.",
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

        sensitive_tools = config.get("sensitive_tools", {})
        default_role = config.get("default_role", "user")
        block_risk = float(config.get("block_risk_score", 0.95))
        escalate_risk = float(config.get("escalate_risk_score", 0.7))

        user_role = ctx.metadata.get("domain3_user_role")
        role_assumed = False
        if not user_role:
            user_role = default_role
            role_assumed = True

        approved_actions = ctx.metadata.get("domain3_approved_actions") or []
        if isinstance(approved_actions, str):
            approved_actions = [approved_actions]

        for idx, call in enumerate(tool_calls):
            if not isinstance(call, dict):
                continue
            tool_name = call.get("name")
            if not tool_name or not isinstance(tool_name, str):
                continue
            tool_name = tool_name.strip()

            if tool_name in sensitive_tools:
                tool_cfg = sensitive_tools[tool_name]
                allowed_roles = tool_cfg.get("allowed_roles", ["admin"])
                requires_approval = tool_cfg.get("requires_approval", False)

                # 1. Check Role Permission
                if user_role not in allowed_roles:
                    return Verdict(
                        control_id=self.control_id,
                        domain=self.domain,
                        status="block",
                        risk_score=block_risk,
                        reason=(
                            f"User role '{user_role}' is not authorized to execute sensitive "
                            f"tool '{tool_name}'. Allowed roles: {allowed_roles}."
                        ),
                        evidence={
                            "tool": tool_name,
                            "user_role": user_role,
                            "allowed_roles": allowed_roles,
                            "role_assumed": role_assumed,
                            "call_index": idx,
                        },
                    )

                # 2. Check Human Approval Requirement
                if requires_approval and tool_name not in approved_actions:
                    return Verdict(
                        control_id=self.control_id,
                        domain=self.domain,
                        status="escalate",
                        risk_score=escalate_risk,
                        reason=(
                            f"Sensitive tool '{tool_name}' requires human approval before "
                            f"execution. No approval found in domain3_approved_actions."
                        ),
                        evidence={
                            "tool": tool_name,
                            "user_role": user_role,
                            "requires_approval": True,
                            "approved_actions": approved_actions,
                            "call_index": idx,
                        },
                    )

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason="All tool calls passed sensitive gate authorization and approval checks.",
            evidence={
                "user_role": user_role,
                "role_assumed": role_assumed,
                "checked_tools": [c.get("name") for c in tool_calls if isinstance(c, dict)],
            },
        )


if __name__ == "__main__":
    control = SensitiveToolGatePL003()

    # Test 1: delete_file by normal user -> BLOCK
    ctx1 = RequestContext(
        session_id="s1",
        user_id="user1",
        raw_prompt="Delete log file",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/var/log/sys.log"}}],
        metadata={"domain3_user_role": "user"},
    )
    v1 = control.evaluate(ctx1)
    print(f"Test 1 (delete_file by user): {v1.status.upper()} (risk: {v1.risk_score}) - {v1.reason}")

    # Test 2: send_email by user without approval -> ESCALATE
    ctx2 = RequestContext(
        session_id="s2",
        user_id="user2",
        raw_prompt="Send an email to client",
        tool_calls=[{"name": "send_email", "arguments": {"to": "client@example.com", "subject": "Hi", "body": "Test"}}],
        metadata={"domain3_user_role": "user"},
    )
    v2 = control.evaluate(ctx2)
    print(f"Test 2 (send_email without approval): {v2.status.upper()} (risk: {v2.risk_score}) - {v2.reason}")

    # Test 3: send_email by user with human approval -> PASS
    ctx3 = RequestContext(
        session_id="s3",
        user_id="user3",
        raw_prompt="Send an email to client",
        tool_calls=[{"name": "send_email", "arguments": {"to": "client@example.com", "subject": "Hi", "body": "Test"}}],
        metadata={
            "domain3_user_role": "user",
            "domain3_approved_actions": ["send_email"],
        },
    )
    v3 = control.evaluate(ctx3)
    print(f"Test 3 (send_email with approval): {v3.status.upper()} (risk: {v3.risk_score}) - {v3.reason}")

    # Test 4: non-sensitive tool (calculator) -> PASS
    ctx4 = RequestContext(
        session_id="s4",
        user_id="user4",
        raw_prompt="Calculate 5 * 5",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "5 * 5"}}],
    )
    v4 = control.evaluate(ctx4)
    print(f"Test 4 (non-sensitive tool): {v4.status.upper()} (risk: {v4.risk_score}) - {v4.reason}")

