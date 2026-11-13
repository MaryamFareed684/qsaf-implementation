"""Tests for the Domain 7 demo runner (local pipeline with prior_verdicts and logging)."""

import json

import pytest

from core import logger as qlogger
from domains.domain7_source_attribution_rag.controls.sa_007_auto_disable import (
    is_rag_disabled, reset_all)
from domains.domain7_source_attribution_rag.demo_domain7 import SCENARIOS, build_ctx, run_pipeline


@pytest.fixture(autouse=True)
def _clean_sa007_state():
    reset_all()
    yield
    reset_all()


GOOD, FABRICATED = SCENARIOS[0], SCENARIOS[2]


def test_runner_passes_a_good_answer_cleanly():
    final, stages = run_pipeline(build_ctx("run-good", GOOD), log=False)
    assert len(stages) == 7
    assert final.status == "pass", [(v.control_id, v.status) for v in stages]


def test_runner_blocks_fabricated_answer_and_names_the_control():
    final, stages = run_pipeline(build_ctx("run-bad", FABRICATED), log=False)
    assert final.status == "block"
    assert final.evidence["blocked_by"] == "SA-002"
    assert "SA-003" in final.evidence["controls_flagged"]


def test_runner_logs_every_verdict(tmp_path, monkeypatch):
    log_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(qlogger, "LOG_FILE", str(log_file))
    run_pipeline(build_ctx("run-log", GOOD))
    records = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert sum(r["type"] == "verdict" for r in records) == 7
    assert sum(r["type"] == "pipeline_result" for r in records) == 1


def test_runner_disables_rag_after_repeated_anomalies_end_to_end():
    for _ in range(3):
        final, stages = run_pipeline(build_ctx("run-attacker", FABRICATED), log=False)
    assert is_rag_disabled("run-attacker")
    assert stages[-1].control_id == "SA-007" and stages[-1].status == "block"
    final, stages = run_pipeline(build_ctx("run-attacker", GOOD), log=False)
    assert final.evidence["blocked_by"] == "SA-007"          # latched even for a good answer