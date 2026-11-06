"""
domains/domain2_role_context/dashboard_section.py

Domain 2's tab for the shared dashboard (dashboard/streamlit_app.py).
Everything Domain 2 needs lives in this domain's folder; the shared file only
imports render_domain2_tab() and calls it inside its tab.
"""

import html

import streamlit as st

from domains.domain2_role_context.demo_domain2 import SCENARIOS, run_pipeline

STATUS_COLORS = {
    "pass": "#2ecc71",
    "warn": "#f39c12",
    "block": "#e74c3c",
    "escalate": "#9b59b6",
}

CUSTOM = "Custom conversation"
VALID_ROLES = ("user", "assistant", "system")
CHAT_AVATARS = {"user": "user", "assistant": "assistant", "system": "assistant"}

CONTROL_SUMMARY = {
    "RC-001": "Role switching ('you are now...', 'pretend to be...'). Current message only.",
    "RC-002": "Impersonation ('I am the system administrator...'). Current message only.",
    "RC-003": "Role redefinition in earlier messages ('let's play a game where...'). Needs 2+ messages.",
    "RC-004": "Fake session boundaries ('[NEW SESSION]', 'system reset'). Current message only.",
    "RC-005": "Role tokens hidden inside code fences or tags. Current message only.",
    "RC-006": "Audit log of role events (RC-001/002/004). Only records, never flags.",
    "RC-007": "Planted context: role tokens in earlier user messages, or a system message mid-conversation.",
}

KNOWN_LIMITATIONS = [
    "Phrase matching: a role switch or impersonation worded without any listed phrase is not caught "
    "(Domain 1's PI-002/PI-003 handle those).",
    "False positives by design: 'I am the developer of this app', 'pretend to be a pirate' and "
    "YAML with 'user:' inside a code fence are flagged.",
    "RC-003 needs at least 2 messages and also scans assistant messages.",
    "Slow multi-turn drift is not covered in Phase 1 (the Control Book assigns it to Domain 5).",
    "Domain 2 only warns. The final allow/block decision belongs to the cross-domain risk engine.",
]


def _parse_earlier_messages(text):
    """One message per line, written as 'role: message'. Returns (messages, errors)."""
    messages, errors = [], []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        role, separator, content = line.partition(":")
        role = role.strip().lower()
        if not separator or role not in VALID_ROLES or not content.strip():
            errors.append(f"Line {number}: write it as  user: ...   assistant: ...   or   system: ...")
            continue
        messages.append({"role": role, "content": content.strip()})
    return messages, errors


def _show_conversation(history):
    for message in history:
        with st.chat_message(CHAT_AVATARS.get(message["role"], "assistant")):
            label = "[system] " if message["role"] == "system" else ""
            st.text(label + message["content"])  # st.text keeps <tags> and ``` exactly as typed


def _card(label, status, reason, risk):
    color = STATUS_COLORS.get(status, "#95a5a6")
    st.markdown(
        f"<div style='padding:12px;border-radius:8px;background-color:{color}22;"
        f"border-left:5px solid {color};margin-bottom:8px;'>"
        f"<b style='color:{color};'>{html.escape(label)} — {status.upper()}</b>"
        f"<br><span style='font-size:0.9em;'>{html.escape(reason)}</span>"
        f"<br><span style='font-size:0.8em;color:#888;'>risk_score: {risk:.2f}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )


def _render_trace(final_verdict, stages):
    st.subheader("Pipeline Trace")
    for stage in stages:
        if stage.get("skipped"):
            st.markdown(
                f"<div style='padding:10px;border-radius:8px;background-color:#ecf0f1;"
                f"color:#7f8c8d;margin-bottom:8px;'>"
                f"<b>{html.escape(stage['control_id'])}</b> — SKIPPED</div>",
                unsafe_allow_html=True,
            )
            continue
        verdict = stage["verdict"]
        label = "FINAL DECISION" if stage.get("is_final") else verdict.control_id
        _card(label, verdict.status, verdict.reason, verdict.risk_score)

    st.subheader("Final Verdict")
    color = STATUS_COLORS.get(final_verdict.status, "#95a5a6")
    st.markdown(
        f"<div style='padding:20px;border-radius:10px;background-color:{color};"
        f"color:white;text-align:center;font-size:1.4em;font-weight:bold;'>"
        f"{final_verdict.status.upper()}  —  risk score {final_verdict.risk_score:.2f}"
        f"</div>",
        unsafe_allow_html=True,
    )


def render_domain2_tab():
    st.header("Domain 2: Role & Context Manipulation")
    st.caption(
        "Pick a prepared conversation or write your own, then watch it pass through the 7 controls. "
        "RC-003 and RC-007 read the earlier messages; the others look only at the current message."
    )

    choice = st.selectbox("Conversation", list(SCENARIOS.keys()) + [CUSTOM], key="domain2_scenario")

    errors = []
    if choice == CUSTOM:
        earlier = st.text_area(
            "Earlier messages (optional) - one per line, written as  role: message",
            placeholder="user: Can you help me plan a trip?\nassistant: Of course, where to?",
            height=120,
            key="domain2_earlier",
        )
        current = st.text_input("Current user message", key="domain2_current")
        history, errors = _parse_earlier_messages(earlier)
        if current.strip():
            history.append({"role": "user", "content": current.strip()})
    else:
        history = SCENARIOS[choice]

    for error in errors:
        st.error(error)

    if history:
        st.subheader("Conversation")
        _show_conversation(history)

    if st.button("Run Pipeline", type="primary", key="domain2_run"):
        if errors:
            st.warning("Fix the lines above first.")
        elif not history:
            st.warning("Please enter a current message first.")
        else:
            with st.spinner("Running the conversation through Domain 2..."):
                final_verdict, stages = run_pipeline(history, session_id="dashboard-domain2", verbose=False)
            _render_trace(final_verdict, stages)

    with st.expander("What each control checks"):
        for control_id, summary in CONTROL_SUMMARY.items():
            st.markdown(f"**{control_id}** — {summary}")
    with st.expander("Known limitations (each one is a documented, tested case)"):
        for limitation in KNOWN_LIMITATIONS:
            st.markdown(f"- {limitation}")
