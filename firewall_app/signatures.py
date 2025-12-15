# firewall_app/signatures.py

import re

SQLI_PATTERNS = [
    r"(\bor\b|\band\b)\s+\d+=\d+",
    r"(--|#)",
    r"(\bunion\b.*\bselect\b)",
    r"(\bselect\b.*\bfrom\b)",
    r"(\bdrop\b|\bdelete\b|\binsert\b|\bupdate\b)",
    r"('|\")\s*or\s*('|\")?\d+=\d+"
]

XSS_PATTERNS = [
    r"<\s*script\b",
    r"</\s*script\s*>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"<\s*img\b",
    r"<\s*iframe\b"
]

compiled_sqli = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]
compiled_xss = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]


def contains_sqli(payload: str) -> bool:
    if not payload:
        return False
    return any(p.search(payload) for p in compiled_sqli)


def contains_xss(payload: str) -> bool:
    if not payload:
        return False
    return any(p.search(payload) for p in compiled_xss)
