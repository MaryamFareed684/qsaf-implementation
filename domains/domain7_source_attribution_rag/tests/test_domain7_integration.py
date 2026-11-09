"""
Domain 7 with the shared Orchestrator and logger (Stage 7 and Stage 8).

Nothing in core/ or in the shared integration test is modified.
"""

import json

import pytest

from core import logger as qlogger
from core.models import RequestContext
from core.orchestrator import Orchestrator
from domains.domain7_source_attribution_rag.controls import ALL_CONTROLS
from domains.domain7_source_attribution_rag.controls.sa_007_auto_disable import reset_all
from domains.domain7_source_attribution_rag.demo_data import KNOWLEDGE_BASE


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


def _good_ctx(session_id="it-d7"):
    return RequestContext(
        session_id=session_id,
        user_id="tester",
        raw_prompt="How many days do I have to ask for a refund?",
        retrieved_docs=[dict(KNOWLEDGE_BASE[0]), dict(KNOWLEDGE_BASE[1])],
        agent_output="You can request a refund within 14 days of delivery [kb-001].",
    )


def test_domain7_registers_and_runs_through_orchestrator():
    orch = _orchestrator()
    assert len(orch.controls_for_layer("egress")) == 7
    result = orch.run_layer("egress", _good_ctx())
    assert result.final_status in ("pass", "warn")       # no block for a good answer
    assert len(result.verdicts) == 7                       # nothing short-circuited
    assert not any(v.reason.startswith("Control raised an internal error")
                   for v in result.verdicts)


def test_good_answer_passes_cleanly_through_orchestrator():
    result = _orchestrator().run_layer("egress", _good_ctx("it-d7-clean"))
    assert result.final_status == "pass"


def test_every_verdict_reaches_the_audit_log(tmp_path, monkeypatch):
    log_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(qlogger, "LOG_FILE", str(log_file))

    _orchestrator().run_layer("egress", _good_ctx("it-d7-log"))

    records = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    verdict_records = [r for r in records if r["type"] == "verdict"]
    assert {r["control_id"] for r in verdict_records} == {f"SA-00{i}" for i in range(1, 8)}
    assert all(r["session_id"] == "it-d7-log" for r in verdict_records)
    assert any(r["type"] == "pipeline_result" for r in records)

    sa001 = next(r for r in verdict_records if r["control_id"] == "SA-001")
    assert [d["doc_id"] for d in sa001["evidence"]["tracked_sources"]] == ["kb-001", "kb-002"]