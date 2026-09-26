# Contributing to QSAF Implementation

Read this ENTIRELY before writing any domain code. This document is the
shared contract that lets 3 people build 4+ domains independently and
still have everything integrate correctly at the end.

---

## 1. The Shared Contract (non-negotiable)

### 1.1 Every control receives a `RequestContext` and returns a `Verdict`

Both are defined in `core/models.py`. Do not invent your own input/output
shapes. If your domain needs extra data that doesn't fit the standard
fields, put it in `RequestContext.metadata` (a free-form dict) — and
document the key you're using in your domain's README.

```python
from core.models import RequestContext, Verdict
```

### 1.2 Every control inherits from `Control` in `core/control_base.py`

```python
from core.control_base import Control
from core.models import RequestContext, Verdict

class MyControl(Control):
    control_id = "PI-003"
    domain = "Domain 1: Prompt Injection Protection"
    layer = "ingress"   # one of: ingress | execution | egress | continuous | infra

    def evaluate(self, ctx: RequestContext) -> Verdict:
        # your real logic goes here
        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",       # pass | warn | block | escalate
            risk_score=0.0,        # 0.0 to 1.0
            reason="...",
            evidence={},
        )
```

### 1.3 Rules you must follow

1. **Never crash the pipeline.** If your control hits an unexpected error,
   the base class's `safe_evaluate()` wrapper will catch it automatically
   and downgrade it to a `warn` — but write your own try/except for
   expected failure cases too (e.g. a missing config key), so your
   `reason` field is actually useful for debugging.
2. **Never hardcode thresholds.** Put them in your domain's
   `config/policy.yaml` and read them via
   `core.policy_loader.load_domain_policy("domain1_prompt_injection")`.
3. **No cross-domain imports.** `domains/domain3_plugin_abuse/` must never
   import anything from `domains/domain1_prompt_injection/`. If two
   domains genuinely need to share logic, that logic belongs in `core/`
   — raise it with the team lead first.
4. **Use the shared logger.** Don't write your own log files — the
   orchestrator already calls `core/logger.py` for every verdict
   automatically. You don't need to log manually inside `evaluate()`.
5. **One control = one file.** Filename pattern:
   `<id_lowercase>_<short_name>.py`, e.g. `pi_003_embedding_similarity.py`.
6. **Every control needs at least one test row** in your domain's
   `tests/payloads.csv`, ideally several (benign + malicious examples).
7. **Don't touch `core/` without review.** If you think the contract
   itself needs to change (new field, new status value, etc.), open a PR
   against `core/` specifically and tag the team lead — don't just change
   it while working on your domain PR.

---

## 2. Git Workflow

- `main` = always working, always demoable. Nobody pushes directly to it.
- Create your own branch: `git checkout -b domain2-dev`
- Commit small, working increments — don't wait until your whole domain
  is finished to open a PR. Open a PR after your FIRST control works.
- Push and open a Pull Request into `main`.
- The integration test (`tests/integration/test_end_to_end.py`) runs
  automatically on every PR via GitHub Actions. It must pass before merge.
- The team lead reviews every PR against this checklist:
  - [ ] Does it inherit `Control` correctly?
  - [ ] Does `evaluate()` return a proper `Verdict`?
  - [ ] Are thresholds in `policy.yaml`, not hardcoded?
  - [ ] Does the integration test still pass?
  - [ ] Is there at least one test payload for the new control?

---

## 3. Domain Folder Shape (identical for every domain)

```
domains/<your_domain>/
├── controls/
│   ├── __init__.py          # registers ALL_CONTROLS list — update when
│   │                          you add/finish a control
│   ├── <id>_<name>.py        # one file per control
│   └── ...
├── config/
│   └── policy.yaml           # thresholds for every control in this domain
├── tests/
│   ├── payloads.csv           # prompt, expected (benign/malicious), notes
│   └── test_<domain>.py       # auto-runs payloads.csv against ALL_CONTROLS
└── README.md                  # what this domain protects against, control
                                  table, how to demo it standalone
```

---

## 4. Replacing a Dummy Control With Real Logic

1. Open your control's file (already exists as a dummy stub).
2. Do NOT rename the class, change `control_id`, `domain`, or `layer`.
3. Replace the body of `evaluate()` with your real detection logic.
4. Load any thresholds from `policy.yaml` instead of hardcoding.
5. Add real attack examples to `payloads.csv`.
6. Run `pytest domains/<your_domain>/tests/ -v` and confirm it passes.
7. Run `pytest tests/integration/ -v` and confirm the WHOLE pipeline
   still passes.
8. Open/update your PR.

---

## 5. Questions About the Contract Itself

If you think the shared contract (`core/models.py` or
`core/control_base.py`) is missing something you need — don't work around
it silently. Raise it in the team chat or weekly sync. Changing the
contract affects everyone, so it needs a quick group discussion, not a
solo decision.
