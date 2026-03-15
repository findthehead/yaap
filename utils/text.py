import re

PROHIBITED_PATTERNS = [
    r"(?i)as an ai",
    r"(?i)simulated analysis",
    r"(?i)this is (only )?a simulation",
    r"(?i)i cannot perform (real[- ]?time|actual) (testing|actions)",
    r"(?i)i (do not|don't) have (browsing|internet) access",
    r"(?i)for educational purposes only",
    r"(?i)i cannot run tools here",
    r"(?i)hypothetical",
    r"(?i)publicly available (information|tools)",
    r"(?i)\bI('ll| will| am going to| plan to)\b",
]


def sanitize_model_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    lines = []
    for line in text.splitlines():
        if any(re.search(p, line) for p in PROHIBITED_PATTERNS):
            continue
        lines.append(line)
    out = "\n".join(lines).strip()
    return out
