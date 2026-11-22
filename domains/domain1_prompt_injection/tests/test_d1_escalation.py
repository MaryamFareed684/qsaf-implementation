"""Regression tests for Domain 1 escalation. Found by measurement: the PI-002 judge refuses or answers without
usable JSON on some prompts, and PI-006 (human review) could never fire because no control returned escalate and
nobody gave PI-006 the final verdict through the shared orchestrator."""
import json

import pytest

import core.orchestrator as orch_mod
from core.models import RequestContext, Verdict
from core.orchestrator import Orchestrator
from core.policy_loader import load_domain_policy
from domains.domain1_prompt_injection.controls import ALL_CONTROLS
from domains.domain1_prompt_injection.controls import pi_004_risk_scoring as m4
from domains.domain1_prompt_injection.controls import pi_006_escalation_router as m6
from domains.domain1_prompt_injection.controls.pi_004_risk_scoring import RiskScoringPI004
from domains.domain1_prompt_injection.controls.pi_006_escalation_router import EscalationRouterPI006

DOMAIN = "Domain 1: Prompt Injection Protection"


def _v(control_id, status, risk, **evidence):
    return Verdict(control_id=control_id, domain=DOMAIN, status=status, risk_score=risk,
                   reason="test", evidence=evidence)


def _ctx(verdicts):
    ctx = RequestContext(session_id="t", user_id="t", raw_prompt="x")
    ctx.metadata["prior_verdicts"] = verdicts
    return ctx


def _judge_failed(kind):
    return _v("PI-002", "warn", 0.5, analyzer_failure=kind)


@pytest.mark.parametrize("kind", ["refused", "not_json", "invalid_score"])
def test_pi004_escalates_when_the_judge_could_not_decide(kind):
    verdict = RiskScoringPI004().evaluate(_ctx([_v("PI-001", "pass", 0.0), _judge_failed(kind)]))
    assert verdict.status == "escalate"
    assert verdict.evidence["escalation_reason"]["control_id"] == "PI-002"
    assert verdict.evidence["escalation_reason"]["analyzer_failure"] == kind
    json.dumps(verdict.evidence)


def test_a_network_or_key_error_does_not_escalate():
    verdict = RiskScoringPI004().evaluate(_ctx([_judge_failed("error")]))
    assert verdict.status == "warn"


def test_a_confident_block_beats_the_escalation():
    verdict = RiskScoringPI004().evaluate(_ctx([_judge_failed("refused"), _v("PI-001", "block", 0.9)]))
    assert verdict.status == "block"


def test_clean_verdicts_do_not_escalate():
    verdict = RiskScoringPI004().evaluate(_ctx([_v("PI-001", "pass", 0.0), _v("PI-003", "pass", 0.0)]))
    assert verdict.status == "pass"


def test_the_policy_can_switch_escalation_off(monkeypatch):
    monkeypatch.setattr(m4, "load_domain_policy", lambda name: {"risk_scoring": {"escalate_on_analyzer_failure": []}})
    verdict = RiskScoringPI004().evaluate(_ctx([_judge_failed("refused")]))
    assert verdict.status == "warn"


def test_policy_lists_the_failure_kinds_that_escalate():
    kinds = load_domain_policy("domain1_prompt_injection")["risk_scoring"]["escalate_on_analyzer_failure"]
    assert isinstance(kinds, list) and kinds and all(isinstance(k, str) for k in kinds)


def test_pi006_finds_the_aggregator_verdict_in_prior_verdicts(tmp_path, monkeypatch):
    log = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(m6, "ALERT_LOG_PATH", str(log))
    verdict = EscalationRouterPI006().evaluate(_ctx([_v("PI-004", "escalate", 0.5)]))
    assert verdict.status == "escalate"
    assert len(log.read_text(encoding="utf-8").strip().splitlines()) == 1


def test_pi006_stays_quiet_without_an_escalation(tmp_path, monkeypatch):
    log = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(m6, "ALERT_LOG_PATH", str(log))
    verdict = EscalationRouterPI006().evaluate(_ctx([_v("PI-004", "warn", 0.5)]))
    assert verdict.status == "pass"
    assert not log.exists()


def test_a_refusing_judge_escalates_through_the_real_orchestrator(tmp_path, monkeypatch):
    log = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(m6, "ALERT_LOG_PATH", str(log))
    monkeypatch.setattr(orch_mod, "log_verdict", lambda *a, **k: None)
    monkeypatch.setattr(orch_mod, "log_pipeline_result", lambda *a, **k: None)
    judge = [c for c in ALL_CONTROLS if c.control_id == "PI-002"][0]
    monkeypatch.setattr(judge, "evaluate", lambda ctx: _judge_failed("refused"))
    orch = Orchestrator()
    for control in ALL_CONTROLS:
        orch.register(control)
    ctx = RequestContext(session_id="esc", user_id="t", raw_prompt="explain me Agentic AI")
    result = orch.run_layer("ingress", ctx)
    assert result.final_status == "escalate"
    assert "PI-006" in [v.control_id for v in result.verdicts]
    assert len(log.read_text(encoding="utf-8").strip().splitlines()) == 1