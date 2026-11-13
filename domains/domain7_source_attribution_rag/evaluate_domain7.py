r"""
Measured evaluation of Domain 7 on a labelled set.

  py domains\domain7_source_attribution_rag\evaluate_domain7.py                  (dev set)
  py domains\domain7_source_attribution_rag\evaluate_domain7.py --set test       (fresh test set)
  add --repeats 3 (default) to measure latency over several passes

Classification covers SA-001..SA-006 (per answer). SA-007 is session-level and covered by
the functional tests. Two decision rules are reported:
  warn_or_block: flagged when the final status is warn or block
  block_only:    flagged only when the final status is block
Latency is measured per control after a warm-up run (model loading excluded) and reported
over all passes.
"""

import argparse
import csv
import importlib
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

CHECKS = ALL_CONTROLS[:6]
SEVERITY = {"pass": 0, "warn": 1, "escalate": 2, "block": 3}
SETS = {
    "dev": ("domains.domain7_source_attribution_rag.eval_set", "evaluation_report.md",
            "evaluation_details.csv", "DEV set (thresholds were calibrated on it)"),
    "test": ("domains.domain7_source_attribution_rag.eval_set_test", "evaluation_report_test.md",
             "evaluation_details_test.csv", "FRESH TEST set (never used for tuning)"),
}


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "n/a"


def pctl(values, q):
    s = sorted(values)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def run_one(example, session_id, kb):
    ctx = RequestContext(
        session_id=session_id, user_id="eval", raw_prompt=example["question"],
        retrieved_docs=[dict(kb[i]) for i in example["doc_ids"]],
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--set", choices=list(SETS), default="dev")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    module_name, report_name, details_name, label = SETS[args.set]
    mod = importlib.import_module(module_name)
    kb, examples, kind_order = mod.EVAL_KB, mod.EXAMPLES, mod.KIND_ORDER

    run_one(examples[0], "eval-warmup", kb)            # load the models before timing
    timings = {c.control_id: [] for c in CHECKS}
    totals, results = [], []
    for rep in range(max(1, args.repeats)):
        results = []
        for i, ex in enumerate(examples):
            verdicts, tm = run_one(ex, f"eval-{rep}-{i}", kb)
            for cid, ms in tm.items():
                timings[cid].append(ms)
            totals.append(sum(tm.values()))
            worst = max(verdicts.values(), key=lambda v: SEVERITY[v.status]).status
            results.append({
                **ex, "verdicts": verdicts, "final": worst,
                "any": worst != "pass", "blk": worst == "block",
                "flagged": [c for c, v in verdicts.items() if v.status != "pass"],
            })

    ok = [r for r in results if r["label"] == "ok"]
    bad = [r for r in results if r["label"] == "bad"]
    lines = ["# Domain 7 evaluation", "", f"Set: {label}", "",
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
    for kind in kind_order:
        group = [r for r in results if r["kind"] == kind]
        hit = ""
        if group[0]["label"] == "bad":
            hit = f"{sum(r['expected_control'] in r['flagged'] for r in group)}/{len(group)}"
        rows.append([kind, group[0]["label"], len(group),
                     f"{sum(r['any'] for r in group)}/{len(group)}",
                     f"{sum(r['blk'] for r in group)}/{len(group)}", hit])
    lines += table(["kind", "label", "n", "flagged (warn or block)", "flagged (block)", "expected control flagged"], rows)

    lines += ["", f"## By control (latency in milliseconds, {max(1, args.repeats)} passes after warm-up)", ""]
    rows = []
    for c in CHECKS:
        cid = c.control_id
        own = [r for r in bad if r["expected_control"] == cid]
        ms = timings[cid]
        rows.append([cid, f"{sum(cid in r['flagged'] for r in ok)}/{len(ok)}",
                     f"{sum(cid in r['flagged'] for r in own)}/{len(own)}" if own else "-",
                     f"{statistics.mean(ms):.1f}", f"{statistics.median(ms):.1f}", f"{pctl(ms, 0.95):.1f}"])
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
    (HERE / report_name).write_text(report, encoding="utf-8")
    with open(HERE / details_name, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "kind", "label", "expected_control", "final", "flagged_controls", "question", "answer"])
        for r in results:
            w.writerow([r["id"], r["kind"], r["label"], r["expected_control"], r["final"],
                        "|".join(r["flagged"]), r["question"], r["answer"]])
    print(f"Wrote {report_name} and {details_name}")


if __name__ == "__main__":
    main()