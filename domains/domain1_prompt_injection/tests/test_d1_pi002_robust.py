"""Regression tests for PI-002 robustness. A fake client replaces Groq, so no key or network is needed.
Found by measurement: the judge sometimes refuses ("I can't help with that") or answers without JSON, and
a risk_score outside 0..1 would make Verdict() raise inside evaluate()."""
import json

import pytest

from core.models import RequestContext
from core.policy_loader import load_domain_policy
from domains.domain1_prompt_injection.controls import pi_002_dynamic_analysis as m2

FENCE = chr(96) * 3
REFUSAL = "I\u2019m sorry, but I can\u2019t help with that."


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content):
        self.choices = [_Choice(content)]


class FakeClient:
    """Returns the scripted answers one by one (the last one repeats). An Exception instance is raised."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0
        self.chat = self
        self.completions = self

    def create(self, **kwargs):
        self.calls += 1
        answer = self.answers[min(self.calls, len(self.answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        return _Resp(answer)


def _j(score, explanation="ok"):
    return json.dumps({"risk_score": score, "is_suspicious": score > 0.5, "explanation": explanation})


def _run(answers):
    control = m2.DynamicAnalysisPI002()
    fake = FakeClient(answers)
    control._client = fake
    ctx = RequestContext(session_id="t", user_id="t", raw_prompt="some prompt")
    return control.evaluate(ctx), fake


@pytest.mark.parametrize("score, expected", [(0.1, "pass"), (0.6, "warn"), (0.95, "block")])
def test_valid_answers_map_to_pass_warn_block(score, expected):
    verdict, fake = _run([_j(score)])
    assert verdict.status == expected
    assert fake.calls == 1


def test_success_keeps_raw_output_and_counts_attempts():
    verdict, _ = _run([_j(0.95, "attack")])
    assert verdict.evidence["raw_llm_output"]["risk_score"] == 0.95
    assert verdict.evidence["attempts"] == 1


def test_two_refusals_give_a_visible_warn_of_kind_refused():
    verdict, fake = _run([REFUSAL, REFUSAL])
    assert verdict.status == "warn"
    assert verdict.reason.startswith("Analyzer unavailable")
    assert verdict.evidence["analyzer_failure"] == "refused"
    assert fake.calls == 2


def test_refusal_then_valid_answer_uses_the_second_answer():
    verdict, fake = _run([REFUSAL, _j(0.95)])
    assert verdict.status == "block"
    assert verdict.evidence["attempts"] == 2
    assert fake.calls == 2


def test_plain_text_without_json_is_kind_not_json():
    verdict, _ = _run(["hmm, hard to say", "hmm, hard to say"])
    assert verdict.status == "warn"
    assert verdict.evidence["analyzer_failure"] == "not_json"


def test_json_inside_a_code_fence_is_accepted():
    answer = FENCE + "json\n" + _j(0.95) + "\n" + FENCE
    verdict, fake = _run([answer])
    assert verdict.status == "block"
    assert fake.calls == 1


@pytest.mark.parametrize("bad", [
    _j(1.5),
    _j(-0.2),
    '{"risk_score": NaN, "explanation": "x"}',
    '{"risk_score": "high", "explanation": "x"}',
    '{"is_suspicious": true}',
    '{"risk_score": true}',
])
def test_unusable_scores_give_a_warn_and_never_raise(bad):
    verdict, fake = _run([bad, bad])
    assert verdict.status == "warn"
    assert verdict.evidence["analyzer_failure"] == "invalid_score"
    assert 0.0 <= verdict.risk_score <= 1.0
    assert fake.calls == 2


def test_api_error_warns_without_retry():
    verdict, fake = _run([RuntimeError("network down")])
    assert verdict.status == "warn"
    assert verdict.evidence["analyzer_failure"] == "error"
    assert fake.calls == 1


@pytest.mark.parametrize("attempts", [1, 3])
def test_number_of_attempts_comes_from_the_policy(monkeypatch, attempts):
    monkeypatch.setattr(m2, "load_domain_policy",
                        lambda name: {"dynamic_analysis": {"threshold": 0.5, "max_attempts": attempts}})
    verdict, fake = _run([REFUSAL])
    assert fake.calls == attempts


def test_failure_evidence_is_json_serializable():
    verdict, _ = _run([REFUSAL, REFUSAL])
    json.dumps(verdict.evidence)


def test_policy_defines_max_attempts():
    cfg = load_domain_policy("domain1_prompt_injection")["dynamic_analysis"]
    assert isinstance(cfg["max_attempts"], int) and cfg["max_attempts"] >= 1