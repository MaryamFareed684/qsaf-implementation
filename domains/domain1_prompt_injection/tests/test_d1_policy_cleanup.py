"""Regression tests for the Domain 1 policy cleanup: every setting in policy.yaml must be read by the code,
and PI-002's block line must come from the policy instead of being written inside the control."""
import json

import pytest

from core.models import RequestContext
from core.policy_loader import load_domain_policy
from domains.domain1_prompt_injection.controls import pi_002_dynamic_analysis as m2

ALLOWED = {
    "blacklist": {"phrases"},
    "dynamic_analysis": {"threshold", "block_threshold", "max_attempts"},
    "embedding_similarity": {"threshold", "block_threshold"},
    "risk_scoring": {"escalate_on_analyzer_failure"},
    "multi_phase_validator": {"stop_on_status"},
    "token_anomaly": {"max_length", "entropy_threshold", "min_repeat_count"},
}


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
    def __init__(self, answer):
        self.answer = answer
        self.chat = self
        self.completions = self

    def create(self, **kwargs):
        return _Resp(self.answer)


def _judge(score):
    control = m2.DynamicAnalysisPI002()
    control._client = FakeClient(json.dumps({"risk_score": score, "explanation": "x"}))
    return control.evaluate(RequestContext(session_id="t", user_id="t", raw_prompt="some prompt"))


def test_policy_contains_only_settings_that_the_code_reads():
    policy = load_domain_policy("domain1_prompt_injection")
    assert set(policy) == set(ALLOWED)
    for section, keys in ALLOWED.items():
        assert set(policy[section]) == keys, section


def test_policy_defines_the_pi002_block_line_above_the_warn_line():
    cfg = load_domain_policy("domain1_prompt_injection")["dynamic_analysis"]
    assert 0 < cfg["threshold"] < cfg["block_threshold"] <= 1


def test_pi002_block_line_comes_from_the_policy(monkeypatch):
    monkeypatch.setattr(m2, "load_domain_policy",
                        lambda name: {"dynamic_analysis": {"threshold": 0.5, "block_threshold": 0.9, "max_attempts": 1}})
    assert _judge(0.85).status == "warn"
    assert _judge(0.95).status == "block"