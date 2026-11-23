"""Shared helpers for Domain 2 controls (this domain's own code; no import from another domain)."""


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