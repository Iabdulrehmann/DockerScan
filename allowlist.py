"""
allowlist.py
------------
Suppress known false positives. The allowlist is a JSON file:

{ "rules": [
    {"path": "/app/tests/*",        "reason": "test fixtures"},
    {"category": "Secret", "path": "*/.env.example"},
    {"package": "bash", "pattern": "CVE-2014-6271", "reason": "not reachable"},
    {"fingerprint": "0123456789abcdef"}
] }

A rule may combine: path (glob), pattern (regex over title/description/location),
category, severity, title (substring), package (glob), fingerprint.
A finding is suppressed when ALL fields of a rule match. Suppressed findings are
kept and listed separately in the report; they are not counted in the totals.
"""
import fnmatch
import json
import re

MATCHERS = ("path", "pattern", "category", "severity", "title", "package", "fingerprint")


def load_allowlist(path):
    """Load and validate an allowlist file. Raises ValueError/OSError with a clear message."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list):
        raise ValueError("allowlist must be a JSON object with a 'rules' list")
    out = []
    for i, r in enumerate(rules, 1):
        if not isinstance(r, dict) or not any(k in r for k in MATCHERS):
            raise ValueError(f"rule {i}: needs at least one of {', '.join(MATCHERS)}")
        unknown = set(r) - set(MATCHERS) - {"reason"}
        if unknown:
            raise ValueError(f"rule {i}: unknown field(s) {', '.join(sorted(unknown))}")
        rule = dict(r)
        if "pattern" in rule:
            try:
                rule["_rx"] = re.compile(rule["pattern"], re.I)
            except re.error as e:
                raise ValueError(f"rule {i}: invalid regex ({e})")
        out.append(rule)
    return out


def _matches(rule, f):
    p = f.get("path") or f["location"].split(" (layer")[0]
    checks = {
        "path": lambda: fnmatch.fnmatchcase(p, rule["path"]),
        "pattern": lambda: bool(rule["_rx"].search(f"{f['title']}\n{f['description']}\n{f['location']}")),
        "category": lambda: f["category"].lower() == str(rule["category"]).lower(),
        "severity": lambda: f["severity"].lower() == str(rule["severity"]).lower(),
        "title": lambda: str(rule["title"]).lower() in f["title"].lower(),
        "package": lambda: fnmatch.fnmatchcase(f.get("package") or "", rule["package"]),
        "fingerprint": lambda: f.get("fingerprint") == rule["fingerprint"],
    }
    return all(checks[k]() for k in MATCHERS if k in rule)


def apply_allowlist(findings, rules):
    """Return (kept, suppressed). Suppressed findings get 'suppressed_by' set to the reason."""
    kept, suppressed = [], []
    for f in findings:
        rule = next((r for r in rules if _matches(r, f)), None)
        if rule:
            f["suppressed_by"] = rule.get("reason") or "matched an allowlist rule"
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed
