import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domains.domain1_prompt_injection.dashboard_section import render_domain1_tab
from domains.domain2_role_context.dashboard_section import render_domain2_tab
from domains.domain7_source_attribution_rag.dashboard_section import render_domain7_tab

st.set_page_config(page_title="QSAF Dashboard", layout="centered")
st.title("QSAF — Live Control Dashboard")

tab1, tab2, tab3, tab4, tab7 = st.tabs([
    "Domain 1: Prompt Injection",
    "Domain 2: Role/Context",
    "Domain 3: Plugin Abuse",
    "Domain 4: Output Risk",
    "Domain 7: Source Attribution",
])

with tab1:
    render_domain1_tab()

with tab2:
    render_domain2_tab()

with tab3:
    st.info("Domain 3 dashboard — not yet implemented.")

with tab4:
    st.info("Domain 4 dashboard — not yet implemented.")

with tab7:
    render_domain7_tab()
