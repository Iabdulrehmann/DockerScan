"""
secret_detector.py
------------------
Finds hardcoded secrets in text using (1) well-known regex patterns and
(2) Shannon-entropy analysis of values assigned in config-style files.
Matches are always REDACTED in the output so reports don't leak the secret.
"""
import math
import os
import re

from config_checker import make_finding

# (name, regex, severity, group holding the secret (0 = whole match))
PATTERNS = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"), "Critical", 0),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "Critical", 0),
    ("AWS secret access key", re.compile(r"(?i)aws.{0,25}(?:secret|private).{0,20}['\"=: ]([A-Za-z0-9/+=]{40})\b"), "Critical", 1),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "Critical", 0),
    ("Stripe live secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), "Critical", 0),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "High", 0),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "High", 0),
    ("Database URL with credentials", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@'\"]+:([^\s:/@'\"]{3,})@"), "High", 1),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "Medium", 0),
    ("Hardcoded credential",
     re.compile(r"(?i)\b[\w.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|auth[_\-]?token|token)[\w.\-]*\s*[:=]\s*['\"]?([^\s'\"#,;]{6,})"),
     "High", 1),
]

PLACEHOLDERS = ("changeme", "change_me", "example", "your_", "your-", "xxxx", "dummy", "placeholder",
                "redacted", "sample", "<", "${", "$(", "{{", "env.", "getenv", "os.environ", "process.env")
PLACEHOLDER_WORDS = {"null", "none", "false", "true", "password", "passwd", "secret", "token", "string", "value"}
CONFIG_EXT = {".env", ".conf", ".cfg", ".ini", ".json", ".yml", ".yaml", ".properties",
              ".toml", ".xml", ".sh", ".py", ".js", ".txt", ".pem", ".key", ".config", ""}
ENTROPY_RX = re.compile(r"[:=]\s*['\"]?([A-Za-z0-9+/=_\-]{20,})['\"]?\s*[,;]?\s*$")
MAX_PER_FILE = 15

RISK = {
    "Critical": "Anyone who obtains this image (registry, backup, CI cache) can use the credential "
                "immediately. Secrets baked into layers stay in the image even if later deleted.",
    "High": "The credential can give unauthorised access to a service or database.",
    "Medium": "The value may be a live credential or session token and could be abused.",
}
FIX = ("Revoke/rotate the exposed secret now. Remove it from the image, and inject secrets at runtime "
       "(environment from a secret store, Docker/Kubernetes secrets, or BuildKit --mount=type=secret).")


def shannon_entropy(s):
    """Bits of entropy per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def redact(value):
    """Show only the first 4 characters of a secret."""
    value = value.strip()
    return value[:4] + "*" * min(max(len(value) - 4, 4), 12)


def _is_placeholder(v):
    low = v.lower()
    if low in PLACEHOLDER_WORDS or any(p in low for p in PLACEHOLDERS):
        return True
    if re.search(r"[()\[\]{}$<>]", v):                       # code, not a literal value
        return True
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_.]+", v))   # attribute access


def _looks_random(v):
    if re.fullmatch(r"[0-9a-fA-F]{32,}", v):                 # md5/sha checksum
        return False
    if re.fullmatch(r"[0-9a-fA-F\-]{36}", v):                # UUID
        return False
    return any(c.isdigit() for c in v) and any(c.isalpha() for c in v) and shannon_entropy(v) >= 4.5


def scan_text(text, location, filename="", layer=None, path=None):
    """
    Scan text and return a list of finding dicts. `location` is shown in the report,
    `filename` only decides which checks apply, `path`/`layer` are stored on each finding.
    """
    findings, seen, occ = [], set(), {}
    base = os.path.basename(filename).lower()
    ext = os.path.splitext(base)[1]
    do_entropy = (ext in CONFIG_EXT or base.startswith(".env")) and not base.endswith((".lock", "-lock.json"))

    for lineno, line in enumerate(text.splitlines(), 1):
        if len(findings) >= MAX_PER_FILE:
            break
        line = line[:1500]
        hit_on_line = False
        for name, rx, sev, grp in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            secret = m.group(grp)
            if name == "Hardcoded credential" and _is_placeholder(secret):
                continue
            key = (name, location, lineno)
            if key in seen:
                continue
            seen.add(key)
            hit_on_line = True
            occ[name] = occ.get(name, 0) + 1
            findings.append(make_finding(
                f"{name} found", sev, "Secret",
                f"Line {lineno}: matched the '{name}' pattern. Value (redacted): {redact(secret)}",
                location, RISK.get(sev, RISK["High"]), FIX,
                path=path, line=lineno, layer=layer, ident=path or location, key=f"{name}#{occ[name]}"))
            break                                             # one finding per line is enough
        if hit_on_line or not do_entropy:
            continue
        m = ENTROPY_RX.search(line)
        if m and not _is_placeholder(m.group(1)) and _looks_random(m.group(1)):
            key = ("entropy", location, lineno)
            if key not in seen:
                seen.add(key)
                v = m.group(1)
                occ["entropy"] = occ.get("entropy", 0) + 1
                findings.append(make_finding(
                    "High-entropy string (possible secret)", "Medium", "Secret",
                    f"Line {lineno}: random-looking value ({shannon_entropy(v):.2f} bits/char). "
                    f"Value (redacted): {redact(v)}", location, RISK["Medium"], FIX,
                    path=path, line=lineno, layer=layer, ident=path or location, key=f"entropy#{occ['entropy']}"))
    return findings
