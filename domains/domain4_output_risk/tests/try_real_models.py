"""
Run this ONCE on your own machine to try the REAL optional models of Domain 4.
(The unit tests use fakes, so they cannot tell you how the real models behave.)

    python domains/domain4_output_risk/tests/try_real_models.py

Each part is independent. If a package or model is missing, that part prints a clear message and
the script moves on. The first run of each part downloads a model, so it needs internet.
Nothing in policy.yaml is changed: the optional layers are switched on in memory only.
"""

import copy
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.models import RequestContext  # noqa: E402
from core.policy_loader import load_domain_policy  # noqa: E402
from domains.domain4_output_risk.controls import or_004_sensitivity_scoring as m004  # noqa: E402
from domains.domain4_output_risk.controls import or_006_prompt_response_correlation as m006  # noqa: E402
from domains.domain4_output_risk.controls import or_007_tone_deviation as m007  # noqa: E402


def make_ctx(reply, prompt="test", history=None):
    return RequestContext(session_id="try", user_id="u", raw_prompt=prompt, agent_output=reply, conversation_history=history or [])


def show(title, verdict):
    print(f"  {title:<34} -> {verdict.status.upper():<5} risk={verdict.risk_score:.2f} | {verdict.reason}")


def with_policy(module, key, **changes):
    cfg = copy.deepcopy(load_domain_policy("domain4_output_risk"))
    section = cfg[key]
    for dotted, value in changes.items():
        target = section
        *parents, last = dotted.split(".")
        for name in parents:
            target = target[name]
        target[last] = value
    return patch.object(module, "load_domain_policy", return_value=cfg)


# ------------------------------------------------------------------ OR-004 NER (Presidio)
print("\n[OR-004] NER with Microsoft Presidio")
print("  needs: python -m pip install presidio-analyzer   and   python -m spacy download en_core_web_lg")
try:
    reply = "Please contact Alice Johnson in Lahore about the invoice."
    with with_policy(m004, "or_004_sensitivity", **{"ner.enabled": True}):
        v = m004.SensitivityScoringOR004().safe_evaluate(make_ctx(reply))
    ner = v.evidence.get("ner", {})
    if ner.get("fallback"):
        print(f"  NER NOT AVAILABLE ({ner.get('error')}). Regex-only result is used. Install the packages above to enable it.")
    else:
        show("names and places", v)
        print("  findings:", [(f["category"], f["count"], f["masked_samples"]) for f in v.evidence["findings"]])
except Exception as exc:  # noqa: BLE001
    print("  could not run:", type(exc).__name__, exc)

# ------------------------------------------------------------------ OR-006 embeddings
print("\n[OR-006] meaning similarity with sentence-transformers")
try:
    prompt = "How do I fix a flat tyre on my bicycle?"
    paraphrase = "Remove the wheel, pull out the inner tube and patch the puncture, then pump it back up."
    unrelated = "The stock market closed higher today, led by technology shares and strong bank earnings."
    for method in ("keyword", "embedding", "hybrid"):
        with with_policy(m006, "or_006_prompt_response", method=method):
            control = m006.PromptResponseCorrelationOR006()
            show(f"{method}: paraphrase (on-topic)", control.safe_evaluate(make_ctx(paraphrase, prompt)))
            show(f"{method}: unrelated reply", control.safe_evaluate(make_ctx(unrelated, prompt)))
    print("  Expected: keyword wrongly WARNs on the paraphrase; embedding and hybrid PASS it and still WARN on the unrelated reply.")
except Exception as exc:  # noqa: BLE001
    print("  could not run:", type(exc).__name__, exc)

# ------------------------------------------------------------------ OR-007 emotion
print("\n[OR-007] emotion classifier (transformers)")
try:
    sneer = "I am done with your nonsense. Ask someone else."
    calm = "Here is how loops work in Python."
    with with_policy(m007, "or_007_tone_deviation", **{"emotion.enabled": True}):
        control = m007.ToneDeviationOR007()
        for name, text in (("calm reply", calm), ("sneering reply (no bad words)", sneer)):
            v = control.safe_evaluate(make_ctx(text))
            show(name, v)
            emo = v.evidence.get("emotion", {})
            if emo.get("fallback"):
                print(f"    EMOTION MODEL NOT AVAILABLE ({emo.get('error')}); word lists only.")
            elif emo.get("scores"):
                print("    top emotion:", emo.get("top"), "| scores:", emo["scores"])
except Exception as exc:  # noqa: BLE001
    print("  could not run:", type(exc).__name__, exc)

print("\nDone. If a part says NOT AVAILABLE, the control still works (it falls back safely).")
