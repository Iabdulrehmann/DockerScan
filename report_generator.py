"""report_generator.py - TXT / JSON / terminal reports (grouped by category) and diff of two scans."""
import json
import os

from config_checker import SEVERITY_ORDER

APP, AUTHOR = "DockerScan", "Muhammad Abdul Rehman"
CATEGORY_ORDER = ["Vulnerability", "Secret", "Configuration", "Filesystem", "Build history", "Information"]
ANSI = {"Critical": "\033[1;91m", "High": "\033[91m", "Medium": "\033[93m", "Low": "\033[92m",
        "Informational": "\033[96m", "bold": "\033[1m", "dim": "\033[2m", "end": "\033[0m"}


def format_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def image_label(result):
    img = result["image"]
    return ", ".join(img["tags"]) or os.path.basename(os.path.normpath(img["archive"]))


def to_json(result):
    """Full machine-readable report (also the input for diff mode)."""
    return json.dumps(result, indent=2, ensure_ascii=False)


def load_report(path):
    """Load a JSON report written by DockerScan. Raises ValueError with a clear message."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError(f"cannot read report '{os.path.basename(path)}': {e}")
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list) or "summary" not in data:
        raise ValueError(f"'{os.path.basename(path)}' is not a DockerScan JSON report")
    if any("fingerprint" not in f for f in data["findings"]):
        raise ValueError(f"'{os.path.basename(path)}' was made by an older version (no fingerprints); rescan it")
    return data


def _c(text, key, color):
    return f"{ANSI[key]}{text}{ANSI['end']}" if color else text


def _layer_text(result, f):
    n = f.get("layer")
    if not n:
        return None
    cmd = next((l["created_by"] for l in result["layers"] if l["index"] == n), "")
    return f"#{n}" + (f"  ({cmd.strip()[:90]})" if cmd else "")


def render(result, color=False, inventory=True):
    """Build the report text. color=True adds ANSI colours for terminals."""
    img, s = result["image"], result["summary"]
    bar = "=" * 78
    out = [bar, _c(f"  {APP} Security Report   (built by {AUTHOR})", "bold", color), bar,
           f"Scanned at : {result['scanned_at']}  ({result['duration_seconds']} s)",
           f"Input      : {img['archive']}  [{img.get('input_type', 'image')}]",
           f"Image      : {image_label(result)}",
           f"OS         : {img['os_name']}   Platform: {img['platform']}",
           f"Layers     : {len(result['layers'])}   Files: {img.get('files_in_final_filesystem', 'n/a')}   "
           f"Packages: {len(result['packages'])}", "", "SUMMARY", "-" * 78,
           f"Total findings: {s['Total']}   (suppressed by allowlist: {s.get('Suppressed', 0)})"]
    out += ["  " + _c(f"{sev:<14}: {s[sev]}", sev, color) for sev in SEVERITY_ORDER]
    for w in result.get("warnings", []):
        out.append(_c(f"  Note: {w}", "dim", color))

    out += ["", "FINDINGS BY CATEGORY", "-" * 78]
    cats = [c for c in CATEGORY_ORDER if any(f["category"] == c for f in result["findings"])]
    cats += sorted({f["category"] for f in result["findings"]} - set(CATEGORY_ORDER))
    if not cats:
        out.append("  No findings.")
    for cat in cats:
        items = [f for f in result["findings"] if f["category"] == cat]
        out += ["", _c(f"== {cat} ({len(items)}) ==", "bold", color)]
        for f in items:                                  # already sorted by severity
            out.append(f"[{f['id']}] " + _c(f"[{f['severity'].upper()}]", f["severity"], color) + f" {f['title']}")
            out.append(f"    Location   : {f['location']}")
            if f.get("line"):
                out.append(f"    Line       : {f['line']}")
            lt = _layer_text(result, f)
            if lt:
                out.append(f"    Layer      : {lt}")
            out += [f"    Description: {f['description']}", f"    Risk       : {f['risk']}", f"    Fix        : {f['fix']}"]

    if result.get("suppressed"):
        out += ["", "SUPPRESSED BY ALLOWLIST (not counted above)", "-" * 78]
        for f in result["suppressed"]:
            out.append(f"[{f['id']}] [{f['severity'].upper()}] {f['title']}  @ {f['location']}")
            out.append(f"    Reason: {f['suppressed_by']}")

    out += ["", "LAYERS (in order)", "-" * 78]
    for l in result["layers"]:
        out.append(f"  #{l['index']:<3} {l['id'][:14]:<14} files={l['files']:<6} size={format_size(l['size']):<9} "
                   f"{l['created_by'].strip()[:70]}")
    if not result["layers"]:
        out.append("  (no layers - input is a plain filesystem)")

    out += ["", f"PACKAGE INVENTORY ({len(result['packages'])})", "-" * 78]
    if not inventory:
        vuln = [p for p in result["packages"] if p.get("vulnerabilities")]
        out.append(f"  {len(vuln)} vulnerable package(s). Use --show-packages (or the saved report) for the full list.")
        pk = vuln
    else:
        pk = result["packages"]
    for p in sorted(pk, key=lambda x: (x["source"], x["name"])):
        lay = f" layer {p['layer']}" if p.get("layer") else ""
        bad = ("  VULNERABLE: " + ", ".join(p["vulnerabilities"])) if p.get("vulnerabilities") else ""
        out.append(f"  {p['source']:<5} {p['name']:<30} {p['version']:<28}{lay}{bad}")
    out += ["", bar, f"Generated by {APP} - Stay Curious, Stay Secure", bar]
    return "\n".join(out)


def to_txt(result):
    return render(result, color=False, inventory=True)


def save_txt(result, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_txt(result))


def save_json(result, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_json(result))


# ------------------------------------------------------------------------ diff mode
def diff_results(old, new):
    """Compare two scans of the same image. Returns only NEW and FIXED findings."""
    o = {f["fingerprint"]: f for f in old["findings"]}
    n = {f["fingerprint"]: f for f in new["findings"]}
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    key = lambda f: (rank[f["severity"]], f["category"], f["title"])
    return {"old_scan": old["scanned_at"], "new_scan": new["scanned_at"],
            "old_image": image_label(old), "new_image": image_label(new),
            "new": sorted((f for k, f in n.items() if k not in o), key=key),
            "fixed": sorted((f for k, f in o.items() if k not in n), key=key),
            "unchanged": len(set(o) & set(n))}


def diff_to_txt(diff, color=False):
    bar = "=" * 78
    out = [bar, _c(f"  {APP} Diff Report", "bold", color), bar,
           f"Old scan: {diff['old_scan']}  ({diff['old_image']})", f"New scan: {diff['new_scan']}  ({diff['new_image']})",
           f"New: {len(diff['new'])}   Fixed: {len(diff['fixed'])}   Unchanged (hidden): {diff['unchanged']}", ""]
    for title, key, tag in (("NEW FINDINGS (introduced since the old scan)", "new", "+ NEW  "),
                            ("FIXED FINDINGS (present before, gone now)", "fixed", "- FIXED")):
        out += [title, "-" * 78]
        if not diff[key]:
            out.append("  none")
        for f in diff[key]:
            out.append(f"  {tag} " + _c(f"[{f['severity'].upper()}]", f["severity"], color) + f" {f['title']}")
            out.append(f"           {f['location']}")
        out.append("")
    return "\n".join(out)
