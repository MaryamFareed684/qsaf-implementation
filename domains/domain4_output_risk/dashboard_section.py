"""
domains/domain4_output_risk/dashboard_section.py

The Domain 4 tab for the shared dashboard. One public function:
    render_domain4_tab()

All Streamlit code for Domain 4 lives here, so nobody edits the shared
dashboard/streamlit_app.py except the two lines the team agreed on.

Domain 4 checks the AGENT'S REPLY, so this tab has two text boxes:
the user prompt and the agent reply.

All widget keys start with "d4_" so they never clash with other domains' tabs.
"""

import streamlit as st

from domains.domain4_output_risk.demo_domain4 import EXAMPLES, run_domain4

_ICONS = {"pass": "✅", "warn": "⚠️", "block": "⛔", "escalate": "🚨"}


def _load_example(name: str) -> None:
    """Button callback: fill both text boxes and clear any old result."""
    prompt, reply = EXAMPLES[name]
    st.session_state["d4_prompt"] = prompt
    st.session_state["d4_reply"] = reply
    st.session_state.pop("d4_result", None)


def render_domain4_tab() -> None:
    st.header("Domain 4: Output Risk & Response Control")
    st.write(
        "Paste what the user asked and what the agent replied. "
        "Domain 4 checks the reply before it reaches the user."
    )

    # Default values must be set before the widgets are created.
    st.session_state.setdefault("d4_prompt", "")
    st.session_state.setdefault("d4_reply", "")

    st.text_area("User prompt", key="d4_prompt", height=80)
    st.text_area("Agent reply (this is what gets checked)", key="d4_reply", height=140)

    st.caption("Load an example:")
    columns = st.columns(len(EXAMPLES))
    for column, name in zip(columns, EXAMPLES):
        column.button(name, key=f"d4_example_{name}", on_click=_load_example, args=(name,))

    if st.button("Run Pipeline", key="d4_run", type="primary"):
        reply = st.session_state["d4_reply"]
        if not reply.strip():
            st.warning("Type or load an agent reply first.")
            st.session_state.pop("d4_result", None)
        else:
            st.session_state["d4_result"] = run_domain4(st.session_state["d4_prompt"], reply)

    result = st.session_state.get("d4_result")
    if not result:
        return

    verdicts, worst = result
    st.subheader("Result")
    left, right = st.columns(2)
    left.metric("Domain 4 overall status", worst.status.upper())
    right.metric("Highest risk score", f"{worst.risk_score:.2f}")
    st.caption(
        "Overall = the most serious control result shown here. "
        "The shared risk engine makes the real final decision."
    )

    for verdict in verdicts:
        icon = _ICONS.get(verdict.status, "")
        title = f"{icon} {verdict.control_id}: {verdict.status.upper()} (risk {verdict.risk_score:.2f})"
        with st.expander(title, expanded=verdict.status != "pass"):
            st.write(verdict.reason)
            if verdict.evidence:
                st.json(verdict.evidence)

    st.caption("Controls that are not implemented yet may show placeholder results.")
