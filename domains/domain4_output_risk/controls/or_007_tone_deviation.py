"""
domains/domain4_output_risk/controls/or_007_tone_deviation.py

QSAF-OR-007: Tone and sentiment deviation tracking (real-time, egress).

What it does, in plain words:
  1. WORD LISTS (always on). Scores the reply's sentiment from -1 (negative) to +1 (positive) with
     small word lists, and compares it with the agent's EARLIER replies in
     ctx.conversation_history. Also flags hostile, threatening, manipulative or dismissive
     wording and SHOUTING (many capitals or exclamation marks).
  2. EMOTION CLASSIFIER (optional, off by default). A small trained model (via the transformers
     library) gives the probability of emotions such as anger or disgust in the whole reply, so
     it can catch aggression that uses no listed word ("I am done with your nonsense."). It also
     compares the current emotion with the agent's earlier replies to spot a sudden shift.
  3. All signals are combined into one risk score: pass / warn / block.

If the emotion model cannot load (no package, no internet) the control does NOT crash: it keeps
the word-list result and records the fallback in the evidence.

Limits: English only. It never stores the reply text in the evidence, only numbers and ids.
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_007_tone_deviation"

_WORD = re.compile(r"[A-Za-z']+")
_CLASSIFIERS: dict = {}


def _sentiment(text: str, positive: set, negative: set, min_words: int):
    """Return sentiment in [-1, 1], or None if the text has too few sentiment words."""
    words = [w.lower() for w in _WORD.findall(text)]
    pos = sum(1 for w in words if w in positive)
    neg = sum(1 for w in words if w in negative)
    if pos + neg < min_words:
        return None
    return (pos - neg) / (pos + neg)


def _message_text(item) -> str:
    if isinstance(item, dict):
        for key in ("content", "text", "message"):
            if isinstance(item.get(key), str):
                return item[key]
    return ""


def _build_default_classifier(model_name: str):
    """
    Create the real emotion classifier (a transformers text-classification pipeline).
    Needs the transformers package (installed with sentence-transformers) and, the first time, internet.
    """
    classifier = _CLASSIFIERS.get(model_name)
    if classifier is None:
        from transformers import pipeline  # imported here so loading stays optional
        classifier = pipeline("text-classification", model=model_name, top_k=None)
        _CLASSIFIERS[model_name] = classifier

    def classify(texts: list) -> list:
        raw = classifier(texts, truncation=True)
        results = []
        for item in raw:                      # one list of {"label","score"} per text
            rows = item if isinstance(item, list) else [item]
            results.append({str(r["label"]).lower(): float(r["score"]) for r in rows})
        return results

    return classify


class ToneDeviationOR007(Control):
    control_id = "OR-007"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def __init__(self, emotion_classifier=None):
        """emotion_classifier: optional callable(list of texts) -> list of {emotion: probability}. Tests pass a fake."""
        super().__init__()
        self._injected_classifier = emotion_classifier
        self._classifier_cache: dict = {}

    def evaluate(self, ctx: RequestContext) -> Verdict:
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict("warn", 0.5, f"OR-007 policy section '{POLICY_KEY}' is missing from policy.yaml; reply was not checked.", {})
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-007 is disabled in policy.yaml.", {})

        try:
            min_history = int(cfg["min_history_replies"])
            min_sent_words = int(cfg["min_sentiment_words"])
            dev_threshold = float(cfg["deviation_threshold"])
            dev_weight = float(cfg["deviation_weight"])
            dev_max = float(cfg["deviation_max_weight"])
            warn_threshold = float(cfg["warn_threshold"])
            block_threshold = float(cfg["block_threshold"])
            roles = {str(r).lower() for r in cfg.get("assistant_roles", [])}
            positive = {str(w).lower() for w in cfg.get("positive_words", [])}
            negative = {str(w).lower() for w in cfg.get("negative_words", [])}
            shout = cfg["shouting"]
            shout_min_words = int(shout["min_words"])
            shout_caps = float(shout["caps_ratio"])
            shout_excl = int(shout["exclamation_count"])
            shout_weight = float(shout["weight"])
            signals = cfg.get("signals", [])
        except (KeyError, TypeError, ValueError) as exc:
            return self._verdict("warn", 0.5, f"OR-007 policy values are invalid ({type(exc).__name__}); reply was not checked.", {})

        reply = ctx.agent_output
        if reply is None or not str(reply).strip():
            return self._verdict("pass", 0.0, "No agent output to inspect.", {})
        reply = str(reply)

        weights, found, flag_ids, invalid = [], [], [], []

        # --- wording signals
        for sig in signals:
            try:
                if re.search(sig["pattern"], reply):
                    flag_ids.append(str(sig.get("id", "?")))
                    weights.append(float(sig.get("weight", 0.0)))
                    found.append(str(sig.get("category", "signal")))
            except (re.error, KeyError, TypeError, ValueError):
                invalid.append(str(sig.get("id", "?")) if isinstance(sig, dict) else "?")

        # --- shouting
        words = reply.split()
        letters_words = [w for w in words if sum(c.isalpha() for c in w) >= 2]
        caps_words = [w for w in letters_words if w.isupper()]
        caps_ratio = len(caps_words) / len(letters_words) if letters_words else 0.0
        exclamations = reply.count("!")
        shouting = (len(words) >= shout_min_words and caps_ratio >= shout_caps) or exclamations >= shout_excl
        if shouting:
            weights.append(shout_weight)
            found.append("shouting")

        # --- the agent's earlier replies
        history_texts = []
        for item in ctx.conversation_history:
            if isinstance(item, dict) and str(item.get("role", "")).lower() in roles:
                text = _message_text(item)
                if text.strip():
                    history_texts.append(text)

        # --- sentiment deviation (word lists)
        current = _sentiment(reply, positive, negative, min_sent_words)
        history_scores = [s for s in (_sentiment(t, positive, negative, min_sent_words) for t in history_texts) if s is not None]
        baseline = deviation = None
        if current is not None and len(history_scores) >= min_history:
            baseline = sum(history_scores) / len(history_scores)
            deviation = abs(current - baseline)
            if deviation >= dev_threshold:
                weights.append(min(dev_weight * deviation / dev_threshold, dev_max))
                found.append("sentiment shift")

        # --- optional emotion classifier
        emotion_info = None
        emotion_cfg = cfg.get("emotion", {}) or {}
        if emotion_cfg.get("enabled", False):
            emotion_info = {"used": False, "fallback": False}
            try:
                min_probability = float(emotion_cfg["min_probability"])
                risky = {str(k).lower(): float(v) for k, v in emotion_cfg["risky_emotions"].items()}
                shift_threshold = float(emotion_cfg["shift_threshold"])
                shift_weight = float(emotion_cfg["shift_weight"])
                max_history = int(emotion_cfg["max_history_replies"])
                classify = self._get_classifier(str(emotion_cfg["model_name"]))
                recent = history_texts[-max_history:] if max_history > 0 else []
                outputs = classify([reply] + recent)
                if len(outputs) != 1 + len(recent):
                    raise ValueError("emotion classifier returned the wrong number of results")
                current_emotions, history_emotions = outputs[0], outputs[1:]
                for label, weight in risky.items():
                    probability = float(current_emotions.get(label, 0.0))
                    if probability >= min_probability:
                        weights.append(min(weight * probability, 0.95))
                        flag_ids.append(f"EM-{label}")
                        found.append(f"{label} emotion")
                if len(history_emotions) >= min_history:
                    now = sum(float(current_emotions.get(l, 0.0)) for l in risky)
                    before = sum(sum(float(h.get(l, 0.0)) for l in risky) for h in history_emotions) / len(history_emotions)
                    emotion_info["current_risky"] = round(now, 3)
                    emotion_info["baseline_risky"] = round(before, 3)
                    if now - before >= shift_threshold:
                        weights.append(shift_weight)
                        found.append("emotion shift")
                emotion_info["top"] = max(current_emotions, key=current_emotions.get) if current_emotions else None
                emotion_info["scores"] = {k: round(float(v), 3) for k, v in current_emotions.items()}
                emotion_info["used"] = True
            except Exception as exc:  # noqa: BLE001  package/model missing or bad settings: keep the word-list result
                emotion_info["fallback"] = True
                emotion_info["error"] = type(exc).__name__

        remaining = 1.0
        for w in weights:
            remaining *= 1.0 - w
        score = round(1.0 - remaining, 3)

        if score >= block_threshold:
            status = "block"
        elif score >= warn_threshold:
            status = "warn"
        else:
            status = "pass"

        evidence = {
            "flag_ids": flag_ids,
            "shouting": shouting,
            "caps_ratio": round(caps_ratio, 3),
            "exclamations": exclamations,
            "current_sentiment": None if current is None else round(current, 3),
            "baseline_sentiment": None if baseline is None else round(baseline, 3),
            "deviation": None if deviation is None else round(deviation, 3),
            "history_replies_used": len(history_scores),
        }
        if emotion_info is not None:
            evidence["emotion"] = emotion_info
        if invalid:
            evidence["invalid_rules"] = invalid

        if status == "pass":
            reason = f"Tone is normal for this conversation (risk {score:.2f})." if not found else \
                f"Minor tone signals ({', '.join(found)}) below the warning level (risk {score:.2f})."
        else:
            reason = f"Unusual tone detected: {', '.join(found)} (risk {score:.2f})."
        if emotion_info and emotion_info["fallback"]:
            reason += " (Emotion model unavailable, word lists only.)"
        return self._verdict(status, score, reason, evidence)

    def _get_classifier(self, model_name: str):
        if self._injected_classifier is not None:
            return self._injected_classifier
        if model_name not in self._classifier_cache:
            self._classifier_cache[model_name] = _build_default_classifier(model_name)
        return self._classifier_cache[model_name]

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
