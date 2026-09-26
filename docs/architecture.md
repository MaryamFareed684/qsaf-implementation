# QSAF System Architecture — Phase 1

## 1. Problem Statement

AI agents can be attacked at multiple independent stages of their
operation: the input they receive (prompt injection, role manipulation),
their tool/plugin use, and the output they produce. No existing framework
implements defenses across these stages as one integrated, working
system. This project implements QSAF — a 9(+1)-domain, 63+-control
security framework — as a real, runnable pipeline, starting with Phase 1
(Domains 1-4).

## 2. High-Level Architecture

```
                     User Input
                         |
        +----------------+----------------+
        |         INGRESS LAYER            |
        |  Domain 1: Prompt Injection      |
        |  Domain 2: Role/Context          |
        +----------------+----------------+
                         |  (pass / warn -> continue, block -> reject)
                         v
                  Agent Core (LLM + tools)
                         |
        +----------------+----------------+
        |        EXECUTION LAYER           |
        |  Domain 3: Plugin/Tool Abuse     |
        +----------------+----------------+
                         v
        +----------------+----------------+
        |         EGRESS LAYER             |
        |  Domain 4: Output Risk           |
        +----------------+----------------+
                         v
                  Final Response to User

  Cross-cutting (used by every layer):
    - core/risk_engine.py   -> combines verdicts into one decision
    - core/logger.py        -> unified audit log
    - dashboard/            -> live visualization
```

## 3. Component Responsibilities

| Component | Responsibility |
|---|---|
| `core/models.py` | Defines the shared data contract (RequestContext, Verdict) |
| `core/control_base.py` | Abstract interface every control implements |
| `core/orchestrator.py` | Runs controls per layer, in order, layer-agnostic to domain internals |
| `core/risk_engine.py` | Aggregates many Verdicts into one final PipelineResult |
| `core/logger.py` | Unified audit trail (JSONL), used by every domain |
| `core/policy_loader.py` | Loads per-domain thresholds from YAML, no hardcoding |
| `domains/*/controls/` | Domain-specific detection logic (the actual "smarts") |
| `dashboard/` | Live view of verdicts, risk scores, blocked requests |
| `demo/` | The end-to-end demo agent used for the panel presentation |

## 4. Why This Design Prevents Integration Problems

Every control, regardless of which domain or which team member built it,
has the exact same "plug shape": it receives a `RequestContext` and
returns a `Verdict`. The `Orchestrator` never contains domain-specific
logic — it only knows how to call `evaluate()` and collect results. This
means:

- New controls can be added to an existing domain without touching the
  orchestrator or any other domain's code.
- New domains (Phase 2, Phase 3) plug in the same way, at whichever
  layer they belong to (`continuous`, `infra`, etc.)
- Three team members can build 4 domains fully independently, because
  they are all building against the same fixed interface.

## 5. Roadmap

| Phase | Domains | Adds |
|---|---|---|
| 1 (current) | 1, 2, 3, 4 | Full input -> execution -> output pipeline |
| 2 | 5, 6, 7 | Continuous behavioral monitoring, payload signing, RAG trust checks |
| 3 | 8, 9, 10 | Data governance, cross-environment defense, cognitive resilience |

## 6. Final Product

A working demo AI agent wrapped by the QSAF pipeline. Malicious inputs
are detected and blocked in real time, with a live dashboard showing
which domain/control caught each threat, plus a full audit log.
