"""
core/models.py

THE SHARED CONTRACT — Part 1: Data Objects

Every domain, every control, in every phase MUST use these exact classes
as input and output. Do not create your own request/response shapes.

If you need extra data specific to your domain, put it in the `metadata`
dict on RequestContext, or `evidence` dict on Verdict — do NOT add new
top-level fields without discussing with the team lead first, since that
changes the contract for everyone.
"""

from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class RequestContext:
    """
    Represents one request flowing through the QSAF pipeline.
    Built once per user request, and passed (and progressively filled in)
    through every layer: ingress -> execution -> egress.
    """

    session_id: str
    user_id: str
    raw_prompt: str

    # Filled in as the request moves through the pipeline
    conversation_history: list[dict] = field(default_factory=list)
    retrieved_docs: list[dict] = field(default_factory=list)   # used by Domain 7 (Phase 2)
    tool_calls: list[dict] = field(default_factory=list)       # used by Domain 3
    agent_output: Optional[str] = None                          # filled after the LLM responds

    # Free-form bucket for anything domain-specific that doesn't
    # belong in the shared shape above. Namespace your keys by domain,
    # e.g. metadata["domain2_role_hint"] = "..."
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Verdict:
    """
    The ONLY thing a control is allowed to return.
    Every control, in every domain, must produce exactly this shape.
    """

    control_id: str          # e.g. "PI-001"
    domain: str               # e.g. "Domain 1: Prompt Injection Protection"
    status: str                # one of: "pass" | "warn" | "block" | "escalate"
    risk_score: float          # 0.0 (safe) -> 1.0 (dangerous)
    reason: str                 # short, human-readable explanation (shown on dashboard)
    evidence: dict[str, Any] = field(default_factory=dict)  # matched pattern, score, etc.

    VALID_STATUSES = ("pass", "warn", "block", "escalate")

    def __post_init__(self):
        if self.status not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid Verdict.status '{self.status}'. "
                f"Must be one of {self.VALID_STATUSES}."
            )
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError(
                f"Verdict.risk_score must be between 0.0 and 1.0, got {self.risk_score}."
            )


@dataclass
class PipelineResult:
    """
    The final, aggregated result after ALL controls in a layer (or the
    whole pipeline) have run. This is what the orchestrator + risk engine
    produce, and what the dashboard displays.
    """

    session_id: str
    final_status: str             # "pass" | "warn" | "block" | "escalate"
    overall_risk_score: float
    verdicts: list[Verdict] = field(default_factory=list)
    blocked_by: Optional[str] = None   # control_id that caused a block, if any
