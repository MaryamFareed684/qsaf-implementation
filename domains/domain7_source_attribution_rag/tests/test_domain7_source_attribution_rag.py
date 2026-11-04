"""
Tests for Domain 7: Source Attribution & RAG Monitoring.

Per-answer controls (SA-001..SA-006) are run in registry order on each payload
row, with earlier verdicts supplied through ctx.metadata["prior_verdicts"] (the
RC-006 convention). SA-007 is session-level and tested separately.

Row labels: benign / malicious / known_gap / false_positive.
known_gap and false_positive rows are marked xfail so limitations are
documented and tested.
"""

import csv
import json
from pathlib import Path

import pytest

from core.models import RequestContext, Verdict
from domains.domain7_source_attribution_rag.controls import ALL_CONTROLS
from domains.domain7_source_attribution_rag.controls.sa_007_auto_disable import reset_all
from domains.domain7_source_attribution_rag.demo_data import KNOWLEDGE_BASE

HERE = Path(__file__).parent
KB = {d["doc_id"]: d for d in KNOWLEDGE_BASE}
CHECKS = ALL_CONTROLS[:6]                       # SA-001..SA-006
BY_ID = {c.control_id: c for c in ALL_CONTROLS}
VALID_STATUS = {"pass", "warn", "block", "escalate"}
DOMAIN = "Domain 7: Source Attribution & RAG Monitoring"


def _rows():
    with open(HERE / "payloads.csv", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _params(with_xfail):
    out = []
    for i, r in enumerate(_rows()):
        marks = []
        if with_xfail and r["expected"] in ("known_gap", "false_positive"):
            marks = [pytest.mark.xfail(reason=r["notes"], strict=False)]
        out.append(pytest.param(r, marks=marks,
                                id=f"{i:02d}-{r['expected']}-{r['expected_control'] or 'none'}"))
    return out


def _ctx(row):
    docs = [dict(KB[i]) for i in row["doc_ids"].split("|")]
    return RequestContext(session_id="test", user_id="tester", raw_prompt=row["prompt"],
                          retrieved_docs=docs, agent_output=row["answer"])


def run_checks(ctx):
    verdicts = []
    for control in CHECKS:
        ctx.metadata["prior_verdicts"] = list(verdicts)
        verdicts.append(control.safe_evaluate(ctx))
    return {v.control_id: v for v in verdicts}


def _v(control_id, status, risk, evidence=None):
    return Verdict(control_id=control_id, domain=DOMAIN, status=status,
                   risk_score=risk, reason="hand-made", evidence=evidence or {})


@pytest.fixture(autouse=True)
def _clean_sa007_state():
    reset_all()
    yield
    reset_all()


# ---------- registry ----------

def test_registry_has_seven_unique_egress_controls():
    assert [c.control_id for c in ALL_CONTROLS] == [f"SA-00{i}" for i in range(1, 8)]
    assert all(c.layer == "egress" for c in ALL_CONTROLS)
    assert all(c.domain == DOMAIN for c in ALL_CONTROLS)


# ---------- payload-driven ----------

@pytest.mark.parametrize("row", _params(with_xfail=True))
def test_payload_verdicts(row):
    verdicts = run_checks(_ctx(row))
    if row["expected"] in ("benign", "false_positive"):
        statuses = {cid: v.status for cid, v in verdicts.items()}
        assert all(s == "pass" for s in statuses.values()), statuses
    else:
        flagged = verdicts[row["expected_control"]]
        assert flagged.status != "pass", (
            f"{row['expected_control']} did not flag: {flagged.reason}")


@pytest.mark.parametrize("row", _params(with_xfail=False))
def test_verdict_shape_and_no_internal_crash(row):
    for cid, v in run_checks(_ctx(row)).items():
        assert v.status in VALID_STATUS, cid
        assert 0.0 <= v.risk_score <= 1.0, cid
        assert v.reason.strip(), cid
        assert not v.reason.startswith("Control raised an internal error"), (cid, v.reason)
        json.dumps(v.evidence)  # must be JSON-serializable


# ---------- unit tests with hand-made inputs ----------

def test_sa001_flags_doc_without_source():
    ctx = RequestContext("t", "u", "q", retrieved_docs=[dict(KB["kb-001"]), {"text": "x"}])
    v = BY_ID["SA-001"].safe_evaluate(ctx)
    assert v.status == "warn" and v.evidence["incomplete_docs"][0]["position"] == 1


def test_sa003_without_sa002_verdict_warns_not_crashes():
    ctx = RequestContext("t", "u", "q", retrieved_docs=[dict(KB["kb-001"])],
                         agent_output="Refunds take 14 days.")
    v = BY_ID["SA-003"].safe_evaluate(ctx)
    assert v.status == "warn" and "SA-002" in v.reason


def test_sa003_uses_handmade_sa002_evidence():
    docs = [dict(KB["kb-001"])]
    clean = RequestContext("t", "u", "q", retrieved_docs=docs,
                           agent_output="Refunds take 14 days.")
    clean.metadata["prior_verdicts"] = [_v("SA-002", "pass", 0.0, {"unsupported_ratio": 0.0})]
    assert BY_ID["SA-003"].safe_evaluate(clean).status == "pass"

    bad = RequestContext("t", "u", "q", retrieved_docs=docs,
                         agent_output="Our office is in Berlin.")
    bad.metadata["prior_verdicts"] = [_v("SA-002", "block", 0.9, {"unsupported_ratio": 1.0})]
    assert BY_ID["SA-003"].safe_evaluate(bad).status == "block"


def test_sa005_fake_citation_blocks_and_missing_citation_warns():
    docs = [dict(KB["kb-001"])]
    fake = RequestContext("t", "u", "q", retrieved_docs=docs, agent_output="Yes [kb-999].")
    assert BY_ID["SA-005"].safe_evaluate(fake).status == "block"
    none = RequestContext("t", "u", "q", retrieved_docs=docs, agent_output="Yes.")
    assert BY_ID["SA-005"].safe_evaluate(none).status == "warn"


def test_sa006_block_is_capped_to_warn_when_nothing_is_cited():
    docs = [dict(KB["kb-001"]), dict(KB["kb-006"])]
    uncited = RequestContext("t", "u", "q", retrieved_docs=docs, agent_output="Refunds take 14 days.")
    assert BY_ID["SA-006"].safe_evaluate(uncited).status == "warn"
    cited = RequestContext("t", "u", "q", retrieved_docs=docs, agent_output="Refunds take 90 days [kb-006].")
    v = BY_ID["SA-006"].safe_evaluate(cited)
    assert v.status == "block" and "trust_footer" in v.evidence


def _sa007(session, verdicts):
    ctx = RequestContext(session, "u", "q")
    ctx.metadata["prior_verdicts"] = verdicts
    return BY_ID["SA-007"].safe_evaluate(ctx)


def test_sa007_disables_after_repeated_anomalies_and_stays_latched():
    bad = [_v("SA-005", "block", 0.8)]
    clean = [_v("SA-005", "pass", 0.0)]
    assert _sa007("s1", bad).status == "warn"
    assert _sa007("s1", bad).status == "warn"
    third = _sa007("s1", bad)
    assert third.status == "block" and third.evidence["rag_disabled"] is True
    assert _sa007("s1", clean).status == "block"      # latched


def test_sa007_sessions_are_isolated_and_reset_works():
    from domains.domain7_source_attribution_rag.controls.sa_007_auto_disable import (
        is_rag_disabled, reset_session)
    bad = [_v("SA-005", "block", 0.8)]
    for _ in range(3):
        _sa007("s1", bad)
    assert is_rag_disabled("s1") and not is_rag_disabled("s2")
    assert _sa007("s2", [_v("SA-005", "pass", 0.0)]).status == "pass"
    reset_session("s1")
    assert _sa007("s1", [_v("SA-005", "pass", 0.0)]).status == "pass"


def test_sa007_without_domain7_verdicts_warns():
    assert _sa007("s9", []).status == "warn"

def test_sa003_ignores_citation_ids_as_numbers():
    ctx = RequestContext("t", "u", "q", retrieved_docs=[dict(KB["kb-003"])],
                         agent_output="The warranty does not cover water damage [kb-003].")
    ctx.metadata["prior_verdicts"] = [_v("SA-002", "pass", 0.0, {"unsupported_ratio": 0.0})]
    v = BY_ID["SA-003"].safe_evaluate(ctx)
    assert v.evidence["ungrounded_numbers"] == []
    assert v.status == "pass"