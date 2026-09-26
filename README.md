# QSAF Implementation — Phase 1

A working implementation of the QSAF (Quantum-Safe/Qorvex AI Security
Framework) — a modular security pipeline that protects LLM agents across
multiple domains: prompt injection, role manipulation, tool/plugin abuse,
output risk, and (in later phases) behavioral monitoring, payload
integrity, RAG source verification, data governance, cross-environment
defense, and cognitive-degradation resilience.

## Project Status: Phase 1 (Domains 1-4)

| Domain | Layer | Status |
|---|---|---|
| Domain 1: Prompt Injection Protection | ingress | Scaffolded (dummy controls) |
| Domain 2: Role & Context Manipulation | ingress | Scaffolded (dummy controls) |
| Domain 3: Plugin/Tool Abuse Monitoring | execution | Scaffolded (dummy controls) |
| Domain 4: Output Risk & Response Control | egress | Scaffolded (dummy controls) |

## Quick Start

```bash
git clone <this-repo-url>
cd qsaf-implementation
pip install -r requirements.txt

# Run the integration test — confirms the pipeline works end-to-end
pytest tests/integration/ -v

# Run the interactive demo agent
python demo/demo_agent.py

# Run the live dashboard (separate terminal)
streamlit run dashboard/streamlit_app.py
```

## How the System Works (high level)

```
User Input
    |
[Domain 1: Prompt Injection]  [Domain 2: Role/Context]   <- INGRESS layer
    |
Agent Core (LLM + tools)
    |
[Domain 3: Plugin/Tool Abuse]                              <- EXECUTION layer
    |
[Domain 4: Output Risk]                                     <- EGRESS layer
    |
Final Response to User
```

Every check produces a `Verdict`. All verdicts for a layer are combined by
`core/risk_engine.py` into one `PipelineResult`. Everything is logged to
`logs/audit/qsaf_audit_log.jsonl` and visualized on the dashboard.

## Repository Structure

```
qsaf-implementation/
├── core/                 # SHARED contract — models, Control base class,
│                           orchestrator, risk engine, logger. Owned by lead.
├── domains/              # One folder per domain, all with identical shape:
│   ├── domain1_prompt_injection/
│   ├── domain2_role_context/
│   ├── domain3_plugin_abuse/
│   └── domain4_output_risk/
│       ├── controls/       # one file per control (PI-001, PI-002, ...)
│       ├── config/          # policy.yaml — thresholds, never hardcoded
│       ├── tests/            # payloads.csv + test_<domain>.py
│       └── README.md
├── dashboard/            # ONE shared Streamlit dashboard for all domains
├── tests/integration/    # end-to-end test across ALL domains together
├── demo/                 # the final panel demo agent + script
├── docs/                 # architecture docs, reports, diagrams
└── config/               # global_policy.yaml
```

## Before You Write Any Domain Code

**Read `CONTRIBUTING.md` first.** It defines the shared contract every
control must follow — this is what makes independent work from 3 team
members integrate cleanly at the end instead of breaking.

## Roadmap

- **Phase 1** (current): Domains 1-4 — full input -> execution -> output
  pipeline
- **Phase 2**: Domains 5-7 — behavioral anomaly detection, payload
  signing, RAG source attribution
- **Phase 3**: Domains 8-10 — data governance, cross-environment defense,
  cognitive/behavioral resilience
- **Final**: Integrate all 10 domains + full dashboard + panel demo
