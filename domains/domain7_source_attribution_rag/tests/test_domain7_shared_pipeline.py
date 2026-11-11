"""Domain 7 inside the shared Orchestrator after the core changes
(prior_verdicts filled by the orchestrator, always_run, and the 'RAG not used' flag)."""

import uuid

import pytest

from core.models import RequestContext
from core.orchestrator import Orchestrator
from domains.domain7_source_attribution_rag.controls import ALL_CONTROLS
from domains.domain7_source_attribution_rag.controls.sa_007_auto_disable import is_rag_disabled, reset_all
from domains.domain7_source_attribution_rag.demo_data import KNOWLEDGE_BASE

GOOD = "You can request a refund within 14 days of delivery [kb-001]."
BAD = "Our headquarters are located in Berlin [kb-001]. We ship by drone on Sundays [kb-002]."


@pytest.fixture(autouse=True)
def _clean_sa007_state():
    reset_all()
    yield
    reset_all()


def _orchestrator():
    orch = Orchestrator()
    for control in ALL_CONTROLS:
        orch.register(control)
    return orch


def _ctx(answer, session_id=None, flag=None):
    ctx = RequestContext(
        session_id=session_id or uuid.uuid4().hex, user_id="t",
        raw_prompt="How many days do I have to ask for a refund?",
        retrieved_docs=[dict(KNOWLEDGE_BASE[0]), dict(KNOWLEDGE_BASE[1])], agent_output=answer)
    if flag is not None:
        ctx.metadata["domain7_rag_used"] = flag
    return ctx


def test_only_sa007_is_an_always_run_control():
    assert [c.control_id for c in ALL_CONTROLS if c.always_run] == ["SA-007"]


def test_orchestrator_fills_prior_verdicts_so_a_good_answer_passes_cleanly():
    result = _orchestrator().run_layer("egress", _ctx(GOOD))
    assert result.final_status == "pass"
    assert [v.control_id for v in result.verdicts] == [f"SA-00{i}" for i in range(1, 8)]


def test_blocked_requests_still_reach_sa007_and_disable_rag_after_three():
    orch, session = _orchestrator(), uuid.uuid4().hex
    for _ in range(3):
        result = orch.run_layer("egress", _ctx(BAD, session))
    assert [v.control_id for v in result.verdicts] == ["SA-001", "SA-002", "SA-007"]   # SA-003..006 skipped
    assert result.verdicts[-1].status == "block" and result.verdicts[-1].evidence["rag_disabled"] is True
    assert is_rag_disabled(session)


def test_plain_chat_is_skipped_when_the_rag_flag_is_false():
    ctx = RequestContext(uuid.uuid4().hex, "t", "Hello, how are you?",
                         agent_output="I am fine, thank you for asking.")
    ctx.metadata["domain7_rag_used"] = False
    result = _orchestrator().run_layer("egress", ctx)
    assert result.final_status == "pass" and len(result.verdicts) == 7
    assert all(v.evidence.get("rag_used") is False for v in result.verdicts)


def test_without_the_flag_behaviour_is_unchanged():
    ctx = RequestContext(uuid.uuid4().hex, "t", "q", agent_output="Refunds take 14 days.")
    result = _orchestrator().run_layer("egress", ctx)
    sa002 = next(v for v in result.verdicts if v.control_id == "SA-002")
    assert sa002.status == "warn"          # answer without retrieved documents, as before