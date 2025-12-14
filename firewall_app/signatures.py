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

compiled_patterns = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]


def contains_sqli(payload: str) -> bool:
    if not payload:
        return False

    for pattern in compiled_patterns:
        if pattern.search(payload):
            return True

    return False
