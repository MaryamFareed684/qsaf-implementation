"""
core/control_base.py

THE SHARED CONTRACT — Part 2: The Control Interface

Every single control, in every domain (all 63+ across all 10 QSAF domains),
MUST be implemented as a class that inherits from `Control` below.

Rules (see CONTRIBUTING.md for the full list):
1. `evaluate()` must NEVER raise an unhandled exception. If something goes
   wrong internally, catch it and return a Verdict with status="warn" and
   explain the failure in `reason`. A crashing control must never take
   down the whole pipeline (fail-safe, not fail-open).
2. `evaluate()` must always return a `Verdict`, nothing else.
3. Do not hardcode thresholds/config inside the control file — load them
   from that domain's config/policy.yaml via `core/policy_loader.py`.
"""

from abc import ABC, abstractmethod
from core.models import RequestContext, Verdict

VALID_LAYERS = ("ingress", "execution", "egress", "continuous", "infra")


class Control(ABC):
    """
    Base class for every QSAF control.

    Class attributes to set on every subclass:
        control_id : str   e.g. "PI-001"
        domain     : str   e.g. "Domain 1: Prompt Injection Protection"
        layer      : str   one of VALID_LAYERS
    """

    control_id: str = "UNSET"
    domain: str = "UNSET"
    layer: str = "ingress"

    def __init__(self):
        if self.layer not in VALID_LAYERS:
            raise ValueError(
                f"{self.control_id}: invalid layer '{self.layer}'. "
                f"Must be one of {VALID_LAYERS}."
            )

    @abstractmethod
    def evaluate(self, ctx: RequestContext) -> Verdict:
        """
        Inspect the given RequestContext and return a Verdict.
        Must be side-effect-free with respect to `ctx` (don't mutate it) —
        if you need to pass data forward, put it in ctx.metadata explicitly
        and document the key you're using in your domain's README.
        """
        raise NotImplementedError

    def safe_evaluate(self, ctx: RequestContext) -> Verdict:
        """
        Wrapper used by the orchestrator. Do not override this — override
        `evaluate()` instead. This guarantees the fail-safe rule even if a
        contributor forgets to handle their own exceptions.
        """
        try:
            return self.evaluate(ctx)
        except Exception as exc:  # noqa: BLE001 - intentionally broad, this is our safety net
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="warn",
                risk_score=0.5,
                reason=f"Control raised an internal error: {exc}",
                evidence={"exception_type": type(exc).__name__},
            )
