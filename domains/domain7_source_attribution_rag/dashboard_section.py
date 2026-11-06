"""
domains/domain7_source_attribution_rag/dashboard_section.py

Domain 7's tab for the shared dashboard (dashboard/streamlit_app.py).
Everything Domain 7 needs lives in this domain's folder; the shared file only
imports render_domain7_tab() and calls it inside its tab.
"""

import html

import streamlit as st

from core.models import RequestContext
from domains.domain7_source_attribution_rag.controls.sa_007_auto_disable import (
    is_rag_disabled,
    reset_session,
)
from domains.domain7_source_attribution_rag.demo_domain7 import (
    KB,
    SCENARIOS,
    SHORT_NAMES,
    build_ctx,
    run_pipeline,
)

SESSION_ID = "dashboard-domain7"
CUSTOM = "Custom RAG answer"
BY_NAME = {s["name"]: s for s in SCENARIOS}

STATUS_COLORS = {
    "pass": "#2ecc71",
    "warn": "#f39c12",
    "block": "#e74c3c",
    "escalate": "#9b59b6",
}

CONTROL_SUMMARY = {
    "SA-001": "Every retrieved document has a doc_id and a source; the source list goes to the audit log.",
    "SA-002": "Each answer sentence is compared with the retrieved sentences (embeddings, measured threshold 0.55).",
    "SA-003": "Hallucination score: unsupported sentences from SA-002 plus numbers/names found in no document.",
    "SA-004": "Are the retrieved documents relevant to the question at all? (bad retrieval, measured threshold 0.40)",
    "SA-005": "The answer must cite documents that were really retrieved. Fake citation = block, no citation = warn.",
    "SA-006": "Trust level of the sources the answer relies on. Untrusted source cited = block.",
    "SA-007": "Session level: repeated anomalous requests disable the RAG pipeline until an operator resets it.",
}

KNOWN_LIMITATIONS = [
    "SA-002 measures topical similarity, not agreement: a negation error ('covers' instead of "
    "'does not cover') is not caught (tested as a known gap).",
    "SA-003's number check pools numbers across all retrieved documents, so a wrong number that "
    "appears in any of them is not caught. Numbers written as words are not compared.",
    "The thresholds (0.55 and 0.40) were measured on a small set of short documents and are provisional "
    "until the labelled evaluation.",
    "An honest 'I could not find that in the documents' answer is flagged by SA-002 (tested false positive).",
    "A faithful answer from a trusted but wrong document is not detectable by any Domain 7 control.",
    "SA-007 keeps its state in memory only (lost on restart), per process, and is not thread-safe.",
    "The shared orchestrator does not pass earlier verdicts to later controls, so Domain 7 uses its own "
    "runner (run_pipeline) for SA-003 and SA-007.",
]


def _card(label, status, reason, risk):
    color = STATUS_COLORS.get(status, "#95a5a6")
    st.markdown(
        f"<div style='padding:12px;border-radius:8px;background-color:{color}22;"
        f"border-left:5px solid {color};margin-bottom:8px;'>"
        f"<b style='color:{color};'>{html.escape(label)} - {status.upper()}</b>"
        f"<br><span style='font-size:0.9em;'>{html.escape(reason)}</span>"
        f"<br><span style='font-size:0.8em;color:#888;'>risk_score: {risk:.2f}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )


def _render_trace(final_verdict, stages):
    st.subheader("Pipeline Trace")
    for v in stages:
        _card(f"{v.control_id} {SHORT_NAMES[v.control_id]}", v.status, v.reason, v.risk_score)

    st.subheader("Final Verdict")
    color = STATUS_COLORS.get(final_verdict.status, "#95a5a6")
    blocked_by = final_verdict.evidence.get("blocked_by")
    suffix = f" - first blocking control: {blocked_by}" if blocked_by else ""
    st.markdown(
        f"<div style='padding:20px;border-radius:10px;background-color:{color};"
        f"color:white;text-align:center;font-size:1.3em;font-weight:bold;'>"
        f"{html.escape(final_verdict.status.upper())} - risk score {final_verdict.risk_score:.2f}"
        f"{html.escape(suffix)}</div>",
        unsafe_allow_html=True,
    )
    with st.expander("Raw evidence (what each control recorded in the audit log)"):
        st.json({v.control_id: v.evidence for v in stages})


def _session_bar():
    disabled = is_rag_disabled(SESSION_ID)
    left, right = st.columns([3, 1])
    with left:
        if disabled:
            st.error("RAG pipeline is DISABLED for this dashboard session (SA-007).")
        else:
            st.success("RAG pipeline is active for this dashboard session.")
    with right:
        if st.button("Reset session", key="domain7_reset"):
            reset_session(SESSION_ID)
            st.rerun()
    return disabled


def render_domain7_tab():
    st.header("Domain 7: Source Attribution & RAG Monitoring")
    st.caption(
        "Pick a prepared RAG scenario or write your own answer, then watch it pass through the 7 controls. "
        "The answer is scripted: there is no LLM in this demo. Citations look like [kb-001]."
    )

    disabled = _session_bar()

    choice = st.selectbox("Scenario", list(BY_NAME.keys()) + [CUSTOM], key="domain7_scenario")

    ctx = None
    if choice == CUSTOM:
        question = st.text_input("Question", key="domain7_question")
        doc_ids = st.multiselect(
            "Retrieved documents",
            options=list(KB.keys()),
            default=["kb-001"],
            format_func=lambda i: f"{i} - {KB[i]['source']}",
            key="domain7_docs",
        )
        answer = st.text_area("Answer written by the 'LLM'", height=100, key="domain7_answer")
        if question.strip() and answer.strip() and doc_ids:
            ctx = RequestContext(
                session_id=SESSION_ID,
                user_id="dashboard-user",
                raw_prompt=question.strip(),
                retrieved_docs=[dict(KB[i]) for i in doc_ids],
                agent_output=answer.strip(),
            )
    else:
        scenario = BY_NAME[choice]
        ctx = build_ctx(SESSION_ID, scenario)
        st.markdown("**Question**")
        st.text(ctx.raw_prompt)
        st.markdown("**Retrieved documents**")
        for d in ctx.retrieved_docs:
            st.caption(f"{d['doc_id']} - {d['source']}")
        st.markdown("**Answer**")
        st.text(ctx.agent_output)  # st.text keeps brackets exactly as written

    if st.button("Run Pipeline", type="primary", key="domain7_run"):
        if disabled:
            st.warning("RAG is disabled for this session. Press 'Reset session' first.")
        elif ctx is None:
            st.warning("Please fill in the question, at least one document and the answer first.")
        else:
            with st.spinner("Running the answer through Domain 7..."):
                final_verdict, stages = run_pipeline(ctx)
            _render_trace(final_verdict, stages)
            if is_rag_disabled(SESSION_ID):
                st.error("SA-007 has now disabled the RAG pipeline for this session.")

    with st.expander("What each control checks"):
        for control_id, summary in CONTROL_SUMMARY.items():
            st.markdown(f"**{control_id}** - {summary}")
    with st.expander("Known limitations (each one is a documented, tested case)"):
        for limitation in KNOWN_LIMITATIONS:
            st.markdown(f"- {limitation}")