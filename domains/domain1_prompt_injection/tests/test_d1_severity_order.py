"""Regression tests: Domain 1 must rank statuses exactly like core/risk_engine.py (block is the worst)."""
import pytest

from core.models import RequestContext, Verdict
from core.risk_engine import _SEVERITY_ORDER
from domains.domain1_prompt_injection.controls.pi_004_risk_scoring import RiskScoringPI004
from domains.domain1_prompt_injection.controls.pi_005_multi_phase_validator import MultiPhaseValidatorPI005

DOMAIN = "Domain 1: Prompt Injection Protection"


def _v(control_id, status, risk):
    return Verdict(control_id=control_id, domain=DOMAIN, status=status, risk_score=risk, reason="test", evidence={})


def _ctx(verdicts):
    ctx = RequestContext(session_id="t", user_id="t", raw_prompt="x")
    ctx.metadata["prior_verdicts"] = verdicts
    return ctx


@pytest.mark.parametrize("control_class", [RiskScoringPI004, MultiPhaseValidatorPI005])
def test_severity_order_matches_the_core_risk_engine(control_class):
    assert control_class.STATUS_SEVERITY == _SEVERITY_ORDER


def test_pi004_block_beats_escalate():
    ctx = _ctx([_v("PI-X", "escalate", 0.6), _v("PI-Y", "block", 0.9)])
    assert RiskScoringPI004().evaluate(ctx).status == "block"


def test_pi005_block_beats_escalate():
    ctx = _ctx([_v("PI-X", "escalate", 0.6), _v("PI-Y", "block", 0.9)])
    verdict = MultiPhaseValidatorPI005().evaluate(ctx)
    assert verdict.status == "block"
    assert verdict.evidence["triggering_control"] == "PI-Y"