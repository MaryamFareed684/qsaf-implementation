"""
dashboard/streamlit_app.py

ONE shared dashboard for ALL domains — do not build separate dashboards
per domain. Run with:
    streamlit run dashboard/streamlit_app.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd

from core.logger import read_recent_logs

st.set_page_config(page_title="QSAF Live Dashboard", layout="wide")

st.title("QSAF Security Pipeline — Live Dashboard")
st.caption("Phase 1: Domains 1 (Prompt Injection), 2 (Role/Context), "
           "3 (Plugin Abuse), 4 (Output Risk)")

logs = read_recent_logs(200)

if not logs:
    st.info("No activity yet. Run `python demo/demo_agent.py` in another "
            "terminal and send some messages, then refresh this page.")
else:
    verdict_logs = [l for l in logs if l.get("type") == "verdict"]
    pipeline_logs = [l for l in logs if l.get("type") == "pipeline_result"]

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Verdicts Logged", len(verdict_logs))
    blocked = sum(1 for l in verdict_logs if l.get("status") == "block")
    col2.metric("Blocked", blocked)
    col3.metric("Pipeline Runs", len(pipeline_logs))

    st.subheader("Recent Control Verdicts")
    if verdict_logs:
        df = pd.DataFrame(verdict_logs)
        st.dataframe(
            df[["logged_at", "domain", "control_id", "status", "risk_score", "reason"]]
            .sort_values("logged_at", ascending=False),
            use_container_width=True,
        )

    st.subheader("Recent Pipeline Results")
    if pipeline_logs:
        df2 = pd.DataFrame(pipeline_logs)
        st.dataframe(
            df2[["logged_at", "session_id", "final_status", "overall_risk_score", "blocked_by"]]
            .sort_values("logged_at", ascending=False),
            use_container_width=True,
        )

st.button("Refresh")
