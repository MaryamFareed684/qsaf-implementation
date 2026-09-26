"""
demo/demo_agent.py

The final demo entry point: a tiny toy "agent" wrapped by the full QSAF
pipeline. This is what you run live in front of your panel.

Run:
    python demo/demo_agent.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import Orchestrator
from core.models import RequestContext

from domains.domain1_prompt_injection.controls import ALL_CONTROLS as D1
from domains.domain2_role_context.controls import ALL_CONTROLS as D2
from domains.domain3_plugin_abuse.controls import ALL_CONTROLS as D3
from domains.domain4_output_risk.controls import ALL_CONTROLS as D4


def build_qsaf_orchestrator() -> Orchestrator:
    orch = Orchestrator()
    for control in D1 + D2 + D3 + D4:
        orch.register(control)
    return orch


def fake_llm_response(prompt: str) -> str:
    """Stand-in for a real LLM call — replace with an actual API call later."""
    return f"[demo agent response to]: {prompt[:80]}"


def run_demo():
    orchestrator = build_qsaf_orchestrator()
    print("=" * 60)
    print(" QSAF DEMO AGENT — Phase 1 (Domains 1-4)")
    print(" Type a message. Type 'quit' to exit.")
    print("=" * 60)

    session_id = "demo-session-1"

    while True:
        user_input = input("\nUser > ")
        if user_input.strip().lower() == "quit":
            break

        ctx = RequestContext(
            session_id=session_id, user_id="demo-user", raw_prompt=user_input
        )

        ingress_result = orchestrator.run_layer("ingress", ctx)
        print(f"\n[Ingress check] status={ingress_result.final_status} "
              f"risk={ingress_result.overall_risk_score}")

        if ingress_result.final_status == "block":
            print(f"  -> BLOCKED by {ingress_result.blocked_by}. Request rejected.")
            continue

        # In a real agent, tool calls would happen here and populate ctx.tool_calls
        execution_result = orchestrator.run_layer("execution", ctx)
        print(f"[Execution check] status={execution_result.final_status} "
              f"risk={execution_result.overall_risk_score}")

        if execution_result.final_status == "block":
            print(f"  -> BLOCKED by {execution_result.blocked_by}. Tool use rejected.")
            continue

        ctx.agent_output = fake_llm_response(user_input)

        egress_result = orchestrator.run_layer("egress", ctx)
        print(f"[Egress check] status={egress_result.final_status} "
              f"risk={egress_result.overall_risk_score}")

        if egress_result.final_status == "block":
            print(f"  -> Response BLOCKED by {egress_result.blocked_by}.")
            continue

        print(f"\nAgent > {ctx.agent_output}")


if __name__ == "__main__":
    run_demo()
