"""
domains/domain4_output_risk/controls/or_004_sensitivity_scoring.py

QSAF-OR-004: Sensitivity scoring of LLM responses (real-time, egress).

What it does, in plain words:
  1. REGEX + CHECKSUMS (always on). Finds structured secrets and personal data: emails, phone
     numbers, card numbers (verified with the Luhn formula so random digits are ignored),
     national ID numbers, bank accounts, API keys, "password: ..." lines, private-key blocks.
  2. NER (optional, off by default). Named Entity Recognition finds things regex cannot:
     PERSON names and LOCATIONS written as ordinary words. Uses Microsoft Presidio if installed.
     A name on its own is low risk; names next to an email or ID push the score up.
  3. Every category gets a score (more items = higher, never above the cap), and the categories
     are combined into ONE sensitivity score from 0 to 1.
  4. pass / warn / block using thresholds from policy.yaml.

If the NER package or its language model is missing, the control does NOT crash: it keeps the
regex result and records the fallback in the evidence.

Privacy: the audit log shows MASKED samples only (j***@example.com, ************1111, A***).
The full detected value is never stored.
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_004_sensitivity"


def luhn_ok(number: str) -> bool:
    """Card-number checksum. Random digit strings usually fail it."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask_value(style: str, value: str) -> str:
    """Hide most of a detected value so logs stay safe."""
    if style == "email":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    if style == "tail4":
        keep = "".join(c for c in value if c.isalnum())[-4:]
        return "*" * 8 + keep
    if style == "initial":
        return value[:1] + "***"
    # head3 (keys, passwords, private keys): show only the first 3 characters
    return value[:3] + "***"


_ANALYZERS: dict = {}


def _build_default_analyzer(language: str):
    """
    Create the real NER analyzer (Microsoft Presidio, which uses spaCy). Optional packages:
        python -m pip install presidio-analyzer
        python -m spacy download en_core_web_lg      (or another spaCy English model)
    Raises if they are missing; the caller turns that into a safe fallback.
    """
    engine = _ANALYZERS.get(language)
    if engine is None:
        from presidio_analyzer import AnalyzerEngine  # imported here so the package stays optional
        engine = AnalyzerEngine()
        _ANALYZERS[language] = engine

    def analyze(text: str, entities: list) -> list:
        results = engine.analyze(text=text, entities=entities, language=language)
        return [{"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": r.score} for r in results]

    return analyze


class SensitivityScoringOR004(Control):
    control_id = "OR-004"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def __init__(self, ner_analyzer=None):
        """
        ner_analyzer: optional callable(text, entity_names) -> list of
        {"entity_type", "start", "end", "score"}. Tests pass a fake one, so no Presidio is needed.
        """
        super().__init__()
        self._injected_analyzer = ner_analyzer
        self._analyzer_cache: dict = {}

    def evaluate(self, ctx: RequestContext) -> Verdict:
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict("warn", 0.5, f"OR-004 policy section '{POLICY_KEY}' is missing from policy.yaml; reply was not checked.", {})
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-004 is disabled in policy.yaml.", {})

        try:
            warn_threshold = float(cfg["warn_threshold"])
            block_threshold = float(cfg["block_threshold"])
            category_cap = float(cfg["category_cap"])
            max_samples = int(cfg["max_samples"])
            rules = cfg.get("rules", [])
        except (KeyError, TypeError, ValueError) as exc:
            return self._verdict("warn", 0.5, f"OR-004 policy values are invalid ({type(exc).__name__}); reply was not checked.", {})

        reply = ctx.agent_output
        if reply is None or not str(reply).strip():
            return self._verdict("pass", 0.0, "No agent output to inspect.", {})
        reply = str(reply)

        used_spans = []
        categories = {}   # category -> {"label", "weight", "count", "samples"}
        invalid = []

        # --- 1) regex + checksums (earlier rules win; later rules ignore text already matched)
        for rule in rules:
            try:
                pattern = re.compile(rule["pattern"])
                weight = float(rule["weight"])
                category = str(rule["category"])
            except (re.error, KeyError, TypeError, ValueError):
                invalid.append(str(rule.get("id", "?")) if isinstance(rule, dict) else "?")
                continue
            for match in pattern.finditer(reply):
                start, end = match.span()
                if any(start < e and end > s for s, e in used_spans):
                    continue
                if rule.get("validator") == "luhn" and not luhn_ok(match.group(0)):
                    continue
                used_spans.append((start, end))
                self._add(categories, category, str(rule.get("label", category)), weight,
                          str(rule.get("mask", "head3")), match.group(0), max_samples)

        # --- 2) optional NER
        ner_info = None
        ner_cfg = cfg.get("ner", {}) or {}
        if ner_cfg.get("enabled", False):
            ner_info = {"used": False, "fallback": False}
            try:
                entities = ner_cfg["entities"]
                min_confidence = float(ner_cfg["min_confidence"])
                language = str(ner_cfg.get("language", "en"))
                analyzer = self._get_analyzer(language)
                for item in analyzer(reply, list(entities.keys())):
                    spec = entities.get(item["entity_type"])
                    start, end = int(item["start"]), int(item["end"])
                    if not spec or float(item["score"]) < min_confidence:
                        continue
                    if any(start < e and end > s for s, e in used_spans):
                        continue   # regex already explained this text
                    used_spans.append((start, end))
                    self._add(categories, str(spec["category"]), str(spec.get("label", spec["category"])),
                              float(spec["weight"]), str(spec.get("mask", "initial")), reply[start:end], max_samples)
                ner_info["used"] = True
            except Exception as exc:  # noqa: BLE001  package/model missing or bad settings: keep the regex result
                ner_info["fallback"] = True
                ner_info["error"] = type(exc).__name__

        # --- score: per category 1-(1-w)^count (capped), then combine categories
        remaining = 1.0
        findings = []
        for category, entry in categories.items():
            cat_score = min(1.0 - (1.0 - entry["weight"]) ** entry["count"], category_cap)
            remaining *= 1.0 - cat_score
            findings.append({"category": category, "count": entry["count"], "category_score": round(cat_score, 3), "masked_samples": entry["samples"]})
        score = round(1.0 - remaining, 3)

        if score >= block_threshold:
            status = "block"
        elif score >= warn_threshold:
            status = "warn"
        else:
            status = "pass"

        evidence = {"sensitivity_score": score, "findings": findings, "thresholds": {"warn": warn_threshold, "block": block_threshold}}
        if ner_info is not None:
            evidence["ner"] = ner_info
        if invalid:
            evidence["invalid_rules"] = invalid

        if not categories:
            reason = "No sensitive data found in the agent reply (sensitivity 0.00)."
        else:
            parts = [f"{e['count']} {e['label']}{'s' if e['count'] > 1 else ''}" for e in categories.values()]
            joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
            reason = f"Contains {joined} (sensitivity {score:.2f})."
        if ner_info and ner_info["fallback"]:
            reason += " (NER unavailable, regex checks only.)"
        return self._verdict(status, score, reason, evidence)

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _add(categories: dict, category: str, label: str, weight: float, mask_style: str, raw_value: str, max_samples: int) -> None:
        entry = categories.setdefault(category, {"label": label, "weight": 0.0, "count": 0, "samples": []})
        entry["weight"] = max(entry["weight"], weight)
        entry["count"] += 1
        if len(entry["samples"]) < max_samples:
            entry["samples"].append(mask_value(mask_style, raw_value))

    def _get_analyzer(self, language: str):
        if self._injected_analyzer is not None:
            return self._injected_analyzer
        if language not in self._analyzer_cache:
            self._analyzer_cache[language] = _build_default_analyzer(language)
        return self._analyzer_cache[language]

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
