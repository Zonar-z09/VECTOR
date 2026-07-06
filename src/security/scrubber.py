"""
src/security/scrubber.py

Mandatory scrubbing layer — strips sensitive data before any text
leaves the process for a cloud API call.

Redacts:
  - IPv4 addresses
  - IPv6 addresses
  - Internal hostnames (*.internal, *.local, *.corp, *.lan, *.intranet)
  - Windows file paths (C:\\...)
  - Unix file paths (/home/, /var/, /etc/, /usr/, /opt/, /tmp/, /root/)
  - Environment variable tokens (env.VAR_NAME patterns)
"""

import re

# ── Patterns ──────────────────────────────────────────────────────────────────

REDACTION_PATTERNS = {
    "IPV4": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "IPV6": r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b',
    "INTERNAL_HOSTNAME": r'\b[\w\-]+\.(?:internal|local|corp|lan|intranet|priv)\b',
    "WINDOWS_PATH": r'[A-Za-z]:\\(?:[\w\-. ]+\\)*[\w\-.]*',
    "UNIX_PATH": r'(?<!\w)/(?:home|var|etc|usr|opt|tmp|root|srv|proc|sys|dev|mnt)/[\w/.\-]+',
    "ENV_TOKEN": r'\benv\.([A-Z_][A-Z0-9_]*)\b',
}


def scrub(text: str) -> tuple:
    """
    Scrubs sensitive data from text before sending to a cloud API.

    Returns:
        (scrubbed_text, redaction_log)
        where redaction_log is a list of (label, original_value) tuples.
    """
    if not text:
        return text, []

    result = text
    redaction_log = []

    for label, pattern in REDACTION_PATTERNS.items():
        matches = re.findall(pattern, result, re.IGNORECASE)
        if matches:
            for match in matches:
                redaction_log.append((label, match))
            result = re.sub(
                pattern,
                f"[REDACTED_{label}]",
                result,
                flags=re.IGNORECASE,
            )

    return result, redaction_log


def scrub_dict(data: dict, fields: list) -> dict:
    """
    Scrubs specified string fields in a dictionary in-place copy.
    Returns a new dict with the specified fields scrubbed.
    """
    result = dict(data)
    all_redactions = []
    for field in fields:
        if field in result and isinstance(result[field], str):
            scrubbed, log = scrub(result[field])
            result[field] = scrubbed
            all_redactions.extend(log)
    return result, all_redactions


if __name__ == "__main__":
    test = (
        "Connect to server at 192.168.10.5 or db.internal on path "
        "/etc/ssl/certs/ca.pem from C:\\Users\\admin\\secrets.txt "
        "using env.DATABASE_PASSWORD"
    )
    scrubbed, log = scrub(test)
    print("Original:", test)
    print("Scrubbed:", scrubbed)
    print("Redacted:", log)
