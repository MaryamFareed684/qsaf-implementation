"""
Shared helpers for the Domain 7 controls (kept inside this domain: domains may not
import each other).
"""

import re

from core.policy_loader import load_domain_policy

DOMAIN_FOLDER = "domain7_source_attribution_rag"
DEFAULT_CITATION_PATTERN = r"\[([A-Za-z0-9_.-]+)\]"

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
_NEGATIONS = {"not", "no", "never", "cannot", "without", "none", "nobody", "neither", "nor"}
_STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "to", "of", "in", "on", "at", "for",
    "and", "or", "can", "may", "will", "you", "your", "i", "it", "its", "this", "that", "with", "by",
    "as", "from", "do", "does", "up", "per", "any", "each", "if", "when", "than", "they", "their",
    "there", "so", "but", "who", "what", "which", "has", "have", "had", "we", "our", "us", "also",
}


def load_policy() -> dict:
    return load_domain_policy(DOMAIN_FOLDER)


def citation_pattern(policy: dict) -> str:
    return (policy.get("attribution") or {}).get("citation_pattern", DEFAULT_CITATION_PATTERN)


def split_sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_SPLIT.split(text) if s.strip()]


def strip_citations(text: str, pattern: str) -> str:
    """Remove citation markers such as [kb-001] so they are not treated as content."""
    cleaned = re.sub(pattern, " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return re.sub(r"\s+([.!?,;:])", r"\1", cleaned).strip()


def is_refusal_sentence(sentence: str, refusal_policy) -> bool:
    """True only for short, digit-free sentences that decline to answer and contain
    no 'but/however' style continuation (so a refusal cannot hide a claim)."""
    if not refusal_policy or not refusal_policy.get("enabled", True):
        return False
    s = sentence.lower()
    if len(s.split()) > int(refusal_policy["max_words"]) or re.search(r"\d", s):
        return False
    if any(re.search(rf"\b{re.escape(w)}\b", s) for w in refusal_policy["blockers"]):
        return False
    return any(p in s for p in refusal_policy["phrases"])


def _stem(word: str) -> str:
    if len(word) > 5 and word.endswith("ing"):
        return word[:-3]
    if len(word) > 4 and word.endswith("ed"):
        return word[:-2]
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def content_stems(text: str) -> set[str]:
    return {_stem(w) for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in _STOPWORDS}


def lexical_coverage(sentence: str, doc_text: str) -> float:
    """Share of the sentence's content words (crudely stemmed) that appear in the document."""
    words = content_stems(sentence)
    if not words:
        return 0.0
    return len(words & content_stems(doc_text)) / len(words)


def _tokens(sentence: str) -> list[str]:
    sentence = re.sub(r"^\s*(yes|no)\b[,.]?\s*", "", sentence, flags=re.IGNORECASE)
    return re.findall(r"[a-z']+", sentence.lower())


def _negated(tokens: list[str]) -> bool:
    return any(t in _NEGATIONS or t.endswith("n't") for t in tokens)


def polarity_conflict(answer_sentence: str, doc_sentence: str, antonym_pairs) -> str | None:
    """Heuristic contradiction check between an answer sentence and the document
    sentence it matches best: a negation mismatch or an antonym pair on one side only."""
    if not doc_sentence:
        return None
    a, d = _tokens(answer_sentence), _tokens(doc_sentence)
    if _negated(a) != _negated(d):
        return "negation"
    sa, sd = set(a), set(d)
    for x, y in antonym_pairs or []:
        if (x in sa and x not in sd and y in sd) or (y in sa and y not in sd and x in sd):
            return f"{x}/{y}"
    return None