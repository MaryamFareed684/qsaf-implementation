"""
PL-005: Cross-Tool Usage Correlation / Intent Matching
Domain: Domain 3: Plugin / Tool Abuse Monitoring
Owner: Pakeeza (Member 2, Domain 3 owner)

Verifies that tool invocations in ctx.tool_calls correlate with the user's prompt
and recent conversation history. Discrepancies on sensitive tools trigger human
escalation, while mismatches on normal tools produce a security warning.
"""

import re
from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class UsageCorrelationPL005(Control):
    control_id = "PL-005"
    domain = "Domain 3: Plugin / Tool Abuse Monitoring"
    layer = "execution"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain3_plugin_abuse")
        config = policy.get("usage_correlation", {})

        if not config.get("enabled", True):
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="Usage correlation check disabled by policy.",
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

        tool_intents = config.get("tool_intents", {})
        n_history = int(config.get("history_messages_to_check", 3))
        sensitive_status = config.get("sensitive_mismatch_status", "escalate")

        # Sensitive tools list from sensitive_tool_gate policy or default high-impact tools
        sensitive_cfg = policy.get("sensitive_tool_gate", {}).get("sensitive_tools", {})
        sensitive_tool_names = set(sensitive_cfg.keys()) | {"send_email", "delete_file", "execute_code", "database_query"}

        # Combine raw prompt and recent conversation history
        text_corpus = (ctx.raw_prompt or "").lower()
        if ctx.conversation_history:
            recent_msgs = ctx.conversation_history[-n_history:]
            for msg in recent_msgs:
                content = msg.get("content", "")
                if isinstance(content, str):
                    text_corpus += " " + content.lower()

        matched_tools = []
        for idx, call in enumerate(tool_calls):
            if not isinstance(call, dict):
                continue
            tool_name = call.get("name")
            if not tool_name or not isinstance(tool_name, str):
                continue
            tool_name = tool_name.strip()

            keywords = tool_intents.get(tool_name, [])
            if not keywords:
                # No intent keywords configured for this tool
                matched_tools.append({"tool": tool_name, "matched_keyword": None, "note": "no_keywords_configured"})
                continue

            # Check if any keyword matches as a word or substring in the text corpus
            matched_kw = None
            for kw in keywords:
                pattern = r"\b" + re.escape(kw.lower()) + r"\b"
                if re.search(pattern, text_corpus) or kw.lower() in text_corpus:
                    matched_kw = kw
                    break

            if matched_kw:
                matched_tools.append({"tool": tool_name, "matched_keyword": matched_kw})
            else:
                # Intent mismatch detected!
                is_sensitive = tool_name in sensitive_tool_names
                if is_sensitive:
                    return Verdict(
                        control_id=self.control_id,
                        domain=self.domain,
                        status=sensitive_status,
                        risk_score=0.75,
                        reason=(
                            f"Sensitive tool '{tool_name}' does not correlate with user prompt "
                            f"intent (no matching keywords: {keywords[:4]}). Human escalation required."
                        ),
                        evidence={
                            "tool": tool_name,
                            "expected_keywords": keywords,
                            "user_prompt": ctx.raw_prompt,
                            "is_sensitive": True,
                            "call_index": idx,
                        },
                    )
                else:
                    return Verdict(
                        control_id=self.control_id,
                        domain=self.domain,
                        status="warn",
                        risk_score=0.5,
                        reason=(
                            f"Tool '{tool_name}' does not match user prompt intent "
                            f"(no matching keywords: {keywords[:4]})."
                        ),
                        evidence={
                            "tool": tool_name,
                            "expected_keywords": keywords,
                            "user_prompt": ctx.raw_prompt,
                            "is_sensitive": False,
                            "call_index": idx,
                        },
                    )

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason=f"All {len(matched_tools)} tool call(s) correlate with user prompt intent.",
            evidence={"matched_tools": matched_tools},
        )


if __name__ == "__main__":
    control = UsageCorrelationPL005()

    # Test 1: Math question with calculator -> PASS
    ctx1 = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="What is 12 times 5?",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "12 * 5"}}],
    )
    v1 = control.evaluate(ctx1)
    print(f"Test 1 (Correlated tool): {v1.status.upper()} (risk: {v1.risk_score}) - {v1.reason}")

    # Test 2: Unrelated summary request with sensitive send_email -> ESCALATE
    ctx2 = RequestContext(
        session_id="s2",
        user_id="u2",
        raw_prompt="Summarize this document for me",
        tool_calls=[{"name": "send_email", "arguments": {"to": "a@b.com", "subject": "Summary", "body": "..."}}],
    )
    v2 = control.evaluate(ctx2)
    print(f"Test 2 (Uncorrelated sensitive tool): {v2.status.upper()} (risk: {v2.risk_score}) - {v2.reason}")

    # Test 3: Unrelated query with normal tool -> WARN
    ctx3 = RequestContext(
        session_id="s3",
        user_id="u3",
        raw_prompt="Tell me a joke",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "1+1"}}],
    )
    v3 = control.evaluate(ctx3)
    print(f"Test 3 (Uncorrelated normal tool): {v3.status.upper()} (risk: {v3.risk_score}) - {v3.reason}")

    # Test 4: No tool calls -> PASS
    ctx4 = RequestContext(
        session_id="s4",
        user_id="u4",
        raw_prompt="Hello assistant",
        tool_calls=[],
    )
    v4 = control.evaluate(ctx4)
    print(f"Test 4 (No tool calls): {v4.status.upper()} (risk: {v4.risk_score}) - {v4.reason}")

