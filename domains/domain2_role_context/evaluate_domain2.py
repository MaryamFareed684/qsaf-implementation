"""Measures Domain 2's controls on the DEV set. Read-only: changes no policy and writes no log (RC-006 is left out)."""
from core.models import RequestContext
from domains.domain2_role_context.controls import ALL_CONTROLS
from domains.domain2_role_context.eval_set_d2 import DEV_SET

CONTROL_IDS = ["RC-001", "RC-002", "RC-003", "RC-004", "RC-005", "RC-007"]


def run():
    controls = {c.control_id: c for c in ALL_CONTROLS if c.control_id in CONTROL_IDS}
    rows = []
    for label, kind, prompt, previous in DEV_SET:
        history = [{"role": role, "content": content} for role, content in previous]
        ctx = RequestContext(session_id="eval", user_id="eval", raw_prompt=prompt, conversation_history=history)
        verdicts = {}
        for cid in CONTROL_IDS:
            try:
                verdicts[cid] = controls[cid].evaluate(ctx).status
            except Exception as exc:
                verdicts[cid] = "CRASH(" + type(exc).__name__ + ")"
        rows.append((label, kind, prompt, verdicts))
    return rows


def rate(rows, flagged):
    atk = [r for r in rows if r[0] == "attack"]
    ben = [r for r in rows if r[0] == "benign"]
    return (sum(1 for r in atk if flagged(r)), len(atk), sum(1 for r in ben if flagged(r)), len(ben))


def main():
    rows = run()
    print("Per control (flagged = status is not pass), policy settings as they are now:")
    for cid in CONTROL_IDS:
        tp, na, fp, nb = rate(rows, lambda r, c=cid: r[3][c] != "pass")
        print("  %s  attacks flagged %2d/%d   benign flagged %2d/%d" % (cid, tp, na, fp, nb))
    tp, na, fp, nb = rate(rows, lambda r: any(s != "pass" for s in r[3].values()))
    print("  ANY     attacks flagged %2d/%d   benign flagged %2d/%d" % (tp, na, fp, nb))
    crashes = sum(1 for r in rows for s in r[3].values() if s.startswith("CRASH"))
    print("  crashes:", crashes)
    print("\nWrong answers of ANY (attack not flagged, or benign flagged):")
    for label, kind, prompt, v in rows:
        flagged = any(s != "pass" for s in v.values())
        if (label == "attack" and not flagged) or (label == "benign" and flagged):
            who = ",".join(c + ":" + s for c, s in v.items() if s != "pass") or "none"
            print("  %-6s %-15s %-24s %s" % (label, kind, who, prompt.replace("\n", " ")[:52]))
    print("\nBy kind (flagged / total):")
    kinds = {}
    for label, kind, prompt, v in rows:
        entry = kinds.setdefault((label, kind), [0, 0])
        entry[1] += 1
        if any(s != "pass" for s in v.values()):
            entry[0] += 1
    for (label, kind), (n, total) in sorted(kinds.items()):
        print("  %-6s %-15s %d/%d" % (label, kind, n, total))


if __name__ == "__main__":
    main()