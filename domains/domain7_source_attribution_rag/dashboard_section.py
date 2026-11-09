"""
domains/domain7_source_attribution_rag/dashboard_section.py

Domain 7's tab for the shared dashboard (dashboard/streamlit_app.py).
Everything Domain 7 needs lives in this domain's folder; the shared file only
imports render_domain7_tab() and calls it inside its tab.
"""

import hashlib
import html
import os

import streamlit as st

from core.models import RequestContext
from domains.domain7_source_attribution_rag import live_rag
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
    "SA-002": "Each answer sentence is compared with the retrieved sentences (embeddings with a calibrated threshold; citation markers removed; refusals skipped).",
    "SA-003": "Hallucination score: unsupported sentences from SA-002 plus numbers/names found in no cited document and contradictions with the source wording.",
    "SA-004": "Are the retrieved documents relevant to the question at all? (bad retrieval; question-to-passage model with a calibrated threshold)",
    "SA-005": "The answer must cite documents that were really retrieved. Fake citation = block, no citation = warn.",
    "SA-006": "Trust level of the sources the answer relies on. Untrusted source cited = block.",
    "SA-007": "Session level: repeated blocked requests disable the RAG pipeline until an operator resets it.",
}

KNOWN_LIMITATIONS = [
    "SA-002 compares meaning, not facts: a wrong number or a negation can still look supported, "
    "so SA-003 adds a number/name check and a contradiction heuristic.",
    "The contradiction heuristic (negation and antonym pairs) is deliberately weak: on its own it only "
    "records evidence, because as a warning it raised false alarms on correct paraphrases. Negation "
    "errors are therefore mostly not flagged (0 of 3 in the fresh test set).",
    "SA-003's number check uses the cited document, so a wrong number that also appears elsewhere in "
    "the same document is not caught. Numbers written as words are not compared.",
    "SA-004 is the weakest control: its model and threshold were calibrated on one small collection, "
    "and it raised 3 false alarms on 25 acceptable answers in the fresh test set.",
    "The refusal exemption is a phrase list: unusual wording is not recognised as a refusal, and a "
    "refusal followed by 'but ...' is checked as a normal claim.",
    "A faithful answer from a trusted but wrong document cannot be detected by any Domain 7 control.",
    "SA-007 keeps its state in memory only (lost on restart), per process, and counts only blocked requests.",
    "The shared orchestrator does not pass earlier verdicts to later controls, so Domain 7 uses its own "
    "runner (run_pipeline) for SA-003 and SA-007.",
    "All evaluation answers were written by hand, not produced by a real LLM.",
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


def _render_scripted_tab():
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


# ---------------- live demo: upload a document, ask a question, Groq answers ----------------

LIVE_SESSION_ID = "dashboard-domain7-live"
TRUST_CHOICES = {
    "Trusted source (for example an official policy)": "upload_trusted",
    "Unverified source": "upload_neutral",
    "Untrusted source (for example an anonymous forum post)": "upload_untrusted",
}


def _live_status():
    if os.environ.get("GROQ_API_KEY"):
        st.success("GROQ_API_KEY is set in this terminal (the key itself is never shown).")
    else:
        st.error("GROQ_API_KEY is not set in the terminal that started Streamlit, so Groq cannot be called.")
    st.text_input("Groq model", value=live_rag.default_model(), key="d7live_model")
    if st.button("List available Groq models", key="d7live_models"):
        try:
            st.write(live_rag.list_models())
        except live_rag.LiveRagError as exc:
            st.error(str(exc))


def _live_session_bar():
    disabled = is_rag_disabled(LIVE_SESSION_ID)
    left, right = st.columns([3, 1])
    with left:
        if disabled:
            st.error("RAG pipeline is DISABLED for this live session (SA-007).")
        else:
            st.success("RAG pipeline is active for this live session.")
    with right:
        if st.button("Reset session", key="d7live_reset"):
            reset_session(LIVE_SESSION_ID)
            st.rerun()
    return disabled


def _run_live(uploaded, source_label, question, top_k, tamper_mode):
    data = uploaded.getvalue()
    key = hashlib.sha1(data).hexdigest() + source_label
    index = st.session_state.get("d7live_index")
    if not index or index["key"] != key:
        with st.spinner("Reading the document and embedding its passages..."):
            text = live_rag.extract_text(uploaded.name, data)
            chunks, truncated = live_rag.limit_chunks(live_rag.chunk_text(text))
            index = {"key": key, "chunks": chunks, "emb": live_rag.embed_chunks(chunks), "truncated": truncated}
        st.session_state["d7live_index"] = index
    if index["truncated"]:
        st.warning(f"The document is long: only the first {live_rag.MAX_CHUNKS} passages are used.")

    docs = live_rag.retrieve(question, index["chunks"], index["emb"], source_label, k=top_k)
    with st.spinner("Asking Groq..."):
        raw = live_rag.ask_groq(live_rag.build_messages(question, docs),
                                model=st.session_state.get("d7live_model") or live_rag.default_model())
    answer = live_rag.tamper_answer(raw, tamper_mode)

    st.markdown("**Answer written by Groq**")
    st.text(raw)
    if answer != raw:
        st.markdown("**Answer after tampering (this is what the controls check)**")
        st.text(answer)
    with st.expander(f"Retrieved passages ({len(docs)})"):
        for d in docs:
            st.markdown(f"**{d['doc_id']}** (similarity {d['score']})")
            st.text(d["text"])

    ctx = RequestContext(session_id=LIVE_SESSION_ID, user_id="dashboard-user", raw_prompt=question,
                         retrieved_docs=docs, agent_output=answer)
    final_verdict, stages = run_pipeline(ctx)
    _render_trace(final_verdict, stages)
    footer = next((v.evidence.get("trust_footer") for v in stages if v.control_id == "SA-006"), None)
    if footer:
        st.caption(footer)
    if is_rag_disabled(LIVE_SESSION_ID):
        st.error("SA-007 has now disabled the RAG pipeline for this live session.")


def _render_live_tab():
    st.header("Live demo: your document, a real LLM, Domain 7 checking the answer")
    st.caption(
        "Upload a PDF or text file and ask a question about it. The best-matching passages are retrieved, "
        "Groq writes an answer that must cite them (for example [up-2]), and the seven Domain 7 controls "
        "check that answer. 'Tamper with the answer' simulates a corrupted or manipulated LLM."
    )
    _live_status()
    disabled = _live_session_bar()

    uploaded = st.file_uploader("Document (PDF or TXT)", type=["pdf", "txt"], key="d7live_file")
    trust_label = st.radio("How much do you trust this document?", list(TRUST_CHOICES.keys()), key="d7live_trust")
    question = st.text_input("Your question about the document", key="d7live_question")
    top_k = st.slider("Passages to retrieve", 1, 5, 3, key="d7live_k")
    tamper_label = st.selectbox("Tamper with the answer (simulate an attack)",
                                list(live_rag.TAMPER_LABELS.keys()), key="d7live_tamper")

    if st.button("Ask and check", type="primary", key="d7live_run"):
        if disabled:
            st.warning("RAG is disabled for this live session. Press 'Reset session' first.")
        elif uploaded is None:
            st.warning("Please upload a document first.")
        elif not question.strip():
            st.warning("Please type a question.")
        else:
            try:
                _run_live(uploaded, TRUST_CHOICES[trust_label], question.strip(), int(top_k),
                          live_rag.TAMPER_LABELS[tamper_label])
            except live_rag.LiveRagError as exc:
                st.error(str(exc))


def render_domain7_tab():
    scripted, live = st.tabs(["Scripted scenarios", "Live demo: upload a document + Groq"])
    with scripted:
        _render_scripted_tab()
    with live:
        _render_live_tab()
