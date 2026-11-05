r"""
Measured evaluation of Domain 7 on the labelled set in eval_set.py.

Run from the repo root:
    py domains\domain7_source_attribution_rag\evaluate_domain7.py

Classification covers SA-001..SA-006 (per answer). SA-007 is session-level and
covered by the functional tests. Two decision rules are reported:
  warn_or_block: flagged when the final status is warn or block
  block_only:    flagged only when the final status is block
Latency is measured per control after a warm-up run (model loading excluded).
"""

import csv
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.models import RequestContext
from domains.domain7_source_attribution_rag.controls import ALL_CONTROLS
from domains.domain7_source_attribution_rag.eval_set import EVAL_KB, EXAMPLES, KIND_ORDER

CHECKS = ALL_CONTROLS[:6]
SEVERITY = {"pass": 0, "warn": 1, "escalate": 2, "block": 3}


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "n/a"


def pctl(values, q):
    s = sorted(values)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def run_one(example, session_id):
    ctx = RequestContext(
        session_id=session_id, user_id="eval", raw_prompt=example["question"],
        retrieved_docs=[dict(EVAL_KB[i]) for i in example["doc_ids"]],
        agent_output=example["answer"],
    )
    verdicts, timings, prior = {}, {}, []
    for control in CHECKS:
        ctx.metadata["prior_verdicts"] = list(prior)
        t0 = time.perf_counter()
        v = control.safe_evaluate(ctx)
        timings[control.control_id] = (time.perf_counter() - t0) * 1000
        prior.append(v)
        verdicts[control.control_id] = v
    return verdicts, timings


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out


def main():
    run_one(EXAMPLES[0], "eval-warmup")          # load the model before timing
    results = []
    for i, ex in enumerate(EXAMPLES):
        verdicts, timings = run_one(ex, f"eval-{i}")
        worst = max(verdicts.values(), key=lambda v: SEVERITY[v.status]).status
        results.append({
            **ex, "verdicts": verdicts, "timings": timings, "final": worst,
            "any": worst != "pass", "blk": worst == "block",
            "flagged": [c for c, v in verdicts.items() if v.status != "pass"],
        })

    ok = [r for r in results if r["label"] == "ok"]
    bad = [r for r in results if r["label"] == "bad"]
    lines = ["# Domain 7 evaluation", "",
             f"Examples: {len(results)} ({len(ok)} acceptable, {len(bad)} faulty). "
             "Controls SA-001 to SA-006; SA-007 is session-level and covered by functional tests.", ""]

    lines += ["## Overall", ""]
    rows = []
    for name, key in (("warn or block", "any"), ("block only", "blk")):
        tp = sum(r[key] for r in bad)
        fn = len(bad) - tp
        fp = sum(r[key] for r in ok)
        tn = len(ok) - fp
        rows.append([name, tp, fp, tn, fn, pct(tp + tn, len(results)),
                     pct(tp, tp + fp), pct(tp, len(bad)), pct(fp, len(ok))])
    lines += table(["decision rule", "TP", "FP", "TN", "FN", "accuracy", "precision", "recall", "false-positive rate"], rows)

    lines += ["", "## By example kind", ""]
    rows = []
    for kind in KIND_ORDER:
        group = [r for r in results if r["kind"] == kind]
        hit = ""
        if group[0]["label"] == "bad":
            hit = f"{sum(r['expected_control'] in r['flagged'] for r in group)}/{len(group)}"
        rows.append([kind, group[0]["label"], len(group),
                     f"{sum(r['any'] for r in group)}/{len(group)}",
                     f"{sum(r['blk'] for r in group)}/{len(group)}", hit])
    lines += table(["kind", "label", "n", "flagged (warn or block)", "flagged (block)", "expected control flagged"], rows)

    lines += ["", "## By control (latency in milliseconds after warm-up)", ""]
    rows = []
    for c in CHECKS:
        cid = c.control_id
        own = [r for r in bad if r["expected_control"] == cid]
        ms = [r["timings"][cid] for r in results]
        rows.append([cid, f"{sum(cid in r['flagged'] for r in ok)}/{len(ok)}",
                     f"{sum(cid in r['flagged'] for r in own)}/{len(own)}" if own else "-",
                     f"{statistics.mean(ms):.1f}", f"{statistics.median(ms):.1f}", f"{pctl(ms, 0.95):.1f}"])
    totals = [sum(r["timings"].values()) for r in results]
    rows.append(["pipeline", "-", "-", f"{statistics.mean(totals):.1f}",
                 f"{statistics.median(totals):.1f}", f"{pctl(totals, 0.95):.1f}"])
    lines += table(["control", "false alarms on acceptable answers", "caught its own failure kind",
                    "mean ms", "median ms", "p95 ms"], rows)

    lines += ["", "## Missed faulty answers (false negatives, warn or block rule)", ""]
    misses = [r for r in bad if not r["any"]]
    lines += [f"- {r['id']} [{r['kind']}] {r['question']} -> {r['answer']}" for r in misses] or ["- none"]
    lines += ["", "## Acceptable answers that were flagged (false positives)", ""]
    fps = [r for r in ok if r["any"]]
    for r in fps:
        reasons = "; ".join(f"{c}: {r['verdicts'][c].reason}" for c in r["flagged"])
        lines.append(f"- {r['id']} [{r['kind']}] {r['question']} -> {reasons}")
    lines += [] if fps else ["- none"]

    report = "\n".join(lines) + "\n"
    print(report)
    (HERE / "evaluation_report.md").write_text(report, encoding="utf-8")
    with open(HERE / "evaluation_details.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "kind", "label", "expected_control", "final", "flagged_controls", "question", "answer"])
        for r in results:
            w.writerow([r["id"], r["kind"], r["label"], r["expected_control"], r["final"],
                        "|".join(r["flagged"]), r["question"], r["answer"]])
    print("Wrote evaluation_report.md and evaluation_details.csv")


if __name__ == "__main__":
    main()