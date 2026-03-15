import re


_FENCE_RE = re.compile(r"```[\s\S]*?```", re.MULTILINE)
_INLINE_CODE_RE = re.compile(r"`([^`]*)`")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+", re.MULTILINE)
_LIST_BULLET_RE = re.compile(r"^\s*[-*+]\s+", re.MULTILINE)
_NUM_LIST_RE = re.compile(r"^\s*\d+\.\s+", re.MULTILINE)
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^\)]+)\)")
_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^\)]+)\)")
_BLOCKQUOTE_RE = re.compile(r"^\s*>\s?", re.MULTILINE)


def strip_markdown(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    # Remove fenced code blocks entirely (they take lots of space in streaming)
    text = _FENCE_RE.sub("", text)
    # Replace inline code with its content
    text = _INLINE_CODE_RE.sub(r"\1", text)
    # Remove headings markers
    text = _HEADING_RE.sub("", text)
    # Remove list bullets and numbering
    text = _LIST_BULLET_RE.sub("", text)
    text = _NUM_LIST_RE.sub("", text)
    # Replace links with their label (drop URL)
    text = _LINK_RE.sub(r"\1", text)
    # Drop image markup
    text = _IMAGE_RE.sub(r"\1", text)
    # Remove blockquote markers
    text = _BLOCKQUOTE_RE.sub("", text)
    # Collapse multiple spaces and blank lines
    text = re.sub(r"\s+", " ", text).strip()
    return text

