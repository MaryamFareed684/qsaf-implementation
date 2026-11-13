"""
core/orchestrator.py

The central "traffic controller." It does NOT know anything about any
specific domain's internal logic - it only knows the Control interface.
This is what makes domains "plug in" without special-case code.

Usage:
    from core.orchestrator import Orchestrator
    orch = Orchestrator()
    orch.register(SomeControlInstance())
    result = orch.run_layer("ingress", ctx)
"""

from core.control_base import Control
from core.models import RequestContext, Verdict, PipelineResult
from core.risk_engine import aggregate
from core.logger import log_verdict, log_pipeline_result


class Orchestrator:
    def __init__(self):
        self._controls: list[Control] = []

    def register(self, control: Control):
        """Every domain calls this once per control, at startup, to plug in."""
        self._controls.append(control)

    def controls_for_layer(self, layer: str) -> list[Control]:
        return [c for c in self._controls if c.layer == layer]

    def run_layer(self, layer: str, ctx: RequestContext) -> PipelineResult:
        """
        Runs every registered control belonging to `layer`, in registration
        order, against the given context. Logs every verdict, then returns
        one aggregated PipelineResult for that layer.

        Contract for controls that need earlier verdicts (RC-006, SA-003, SA-007):
        before each control runs, ctx.metadata["prior_verdicts"] is set to a fresh
        list holding the verdicts of the controls that already ran in THIS layer.

        Short-circuit: once a control returns "block", the remaining controls of the
        layer are skipped (saves time/cost), EXCEPT controls that declare
        always_run = True (monitoring controls that must still see the request).
        """
        verdicts: list[Verdict] = []
        blocked = False
        for control in self.controls_for_layer(layer):
            if blocked and not getattr(control, "always_run", False):
                continue
            ctx.metadata["prior_verdicts"] = list(verdicts)
            verdict = control.safe_evaluate(ctx)
            log_verdict(ctx.session_id, verdict)
            verdicts.append(verdict)
            if verdict.status == "block":
                blocked = True

        result = aggregate(ctx.session_id, verdicts)
        log_pipeline_result(result)
        return result

    def run_full_pipeline(self, ctx: RequestContext) -> dict[str, PipelineResult]:
        """
        Runs ingress -> (agent would execute here) -> execution -> egress.
        Returns a dict of layer_name -> PipelineResult so callers (like the
        demo agent) can decide what to do at each stage.

        NOTE: this does not call the actual LLM/agent itself - that's the
        demo app's job. This just shows the intended layer ordering.
        """
        results = {}

        results["ingress"] = self.run_layer("ingress", ctx)
        if results["ingress"].final_status == "block":
            return results

        # ctx.tool_calls / ctx.agent_output would be filled in by the demo
        # agent between these two calls in a real run.

        results["execution"] = self.run_layer("execution", ctx)
        if results["execution"].final_status == "block":
            return results

        results["egress"] = self.run_layer("egress", ctx)
        return results