"""Shared helpers for Domain 2 controls (this domain's own code; no import from another domain)."""
import re
import unicodedata

from core.models import RequestContext

# Same cleaning idea as Domain 1's PI-008. The contract forbids importing another domain, so this is a
# separate copy; tests/integration/test_domain_sanitizer_agreement.py fails if the two ever disagree.
ANSI_PATTERN = re.compile(r"\x1B\[[0-9;?]*[A-Za-z]")
WORD_SEPARATING_CONTROLS = {"\t", "\n", "\r", "\x0b", "\x0c"}


def clean_text(text: str) -> str:
    """Remove what hides a phrase from exact matching: ANSI escapes, invisible and control characters, and
    look-alike forms (NFKC). Tabs and newlines become one space, so an attack split over lines is joined.
    Not handled: letters from other alphabets that look like Latin ones (a Cyrillic o), and leetspeak."""
    if not isinstance(text, str):
        return ""
    text = ANSI_PATTERN.sub("", text)
    chars = []
    for char in text:
        if char in WORD_SEPARATING_CONTROLS:
            chars.append(" ")
        elif unicodedata.category(char) in ("Cf", "Cc"):
            continue
        else:
            chars.append(char)
    return unicodedata.normalize("NFKC", "".join(chars))


def get_cleaned_prompt(ctx: RequestContext) -> str:
    """The text a control should inspect: ctx.metadata["cleaned_prompt"] when a caller set it, otherwise
    ctx.raw_prompt, and in both cases cleaned again (cleaning is idempotent). Never mutates ctx."""
    candidate = ctx.metadata.get("cleaned_prompt")
    if not isinstance(candidate, str):
        candidate = ctx.raw_prompt
    return clean_text(candidate)


def message_role(message) -> str:
    """Role of a history message, or "" when the message is not a dict or has no string role."""
    if isinstance(message, dict) and isinstance(message.get("role"), str):
        return message["role"]
    return ""


def message_text(message) -> str:
    """Plain text of a history message, whatever shape the host app uses. Never raises.

    Accepts content as a string, as a list of parts (strings, or dicts with a "text" string, as in
    multimodal chat formats), or None (for example a tool-call message). A bare string in the history is
    treated as the text itself. Anything else gives "".
    """
    if isinstance(message, str):
        return message
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return " ".join(parts)
    return ""