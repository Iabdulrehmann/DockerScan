"""
cli.py - DockerScan command line.  Prints the report to the terminal AND saves it to files.

  python cli.py scan  image.tar  [--config cfg.json] [--db vulns.json] [--allowlist al.json]
                                 [--out report.txt] [--json report.json] [--fail-on High]
  python cli.py diff  old.json new.json [--out diff.txt]

Exit codes: 0 = ok, 1 = findings at/above --fail-on (scan) or new findings (diff), 2 = error.
"""
import argparse
import datetime
import os
import re
import sys

import report_generator as rg
from config_checker import SEVERITY_ORDER


def _setup_output(no_color):
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="replace")           # never crash on odd console encodings
        except Exception:
            pass
    use = sys.stdout.isatty() and not no_color and "NO_COLOR" not in os.environ
    if use and os.name == "nt":
        os.system("")                                 # enables ANSI colours in Windows terminals
    return use


def build_parser():
    p = argparse.ArgumentParser(prog="dockerscan", description="DockerScan - offline Docker image security scanner "
                                "(built by Muhammad Abdul Rehman)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a docker-save tarball, an unpacked image folder, or a filesystem folder")
    s.add_argument("path", help=".tar/.tar.gz file or a folder")
    s.add_argument("--config", help="image config JSON (only needed for a plain filesystem folder)")
    s.add_argument("--db", help="vulnerability database JSON (default: bundled sample)")
    s.add_argument("--allowlist", help="allowlist JSON to suppress known false positives")
    s.add_argument("--out", help="text report path (default: dockerscan_<name>_<time>.txt)")
    s.add_argument("--json", help="JSON report path (default: next to the text report)")
    s.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 1 if any finding is at/above this severity")
    s.add_argument("--show-packages", action="store_true", help="print the full package inventory in the terminal")
    s.add_argument("--quiet", action="store_true", help="no progress messages")
    s.add_argument("--no-color", action="store_true")
    d = sub.add_parser("diff", help="show only NEW and FIXED findings between two JSON reports")
    d.add_argument("old"), d.add_argument("new")
    d.add_argument("--out", help="save the diff as text")
    d.add_argument("--no-color", action="store_true")
    return p


def _scan(a):
    from scanner import DockerImageScanner, ScanError
    color = _setup_output(a.no_color)
    show = sys.stderr.isatty() and not a.quiet

    def progress(pct, msg):
        if show:
            sys.stderr.write(f"\r[{pct:3d}%] {msg[:60]:<60}")
            sys.stderr.flush()
    try:
        result = DockerImageScanner(a.db, progress, None, a.allowlist, a.config).scan(a.path)
    except ScanError as e:
        if show:
            sys.stderr.write("\n")
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if show:
        sys.stderr.write("\r" + " " * 70 + "\r")
    print(rg.render(result, color=color, inventory=a.show_packages))

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.basename(os.path.normpath(a.path)))[:40]
    txt = a.out or f"dockerscan_{name}_{stamp}.txt"
    js = a.json or os.path.splitext(txt)[0] + ".json"
    try:
        rg.save_txt(result, txt)
        rg.save_json(result, js)
    except OSError as e:
        print(f"ERROR: could not save report: {e}", file=sys.stderr)
        return 2
    print(f"\nSaved: {os.path.abspath(txt)}\nSaved: {os.path.abspath(js)}")
    if a.fail_on:
        limit = SEVERITY_ORDER.index(a.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) <= limit for f in result["findings"]):
            return 1
    return 0


def _diff(a):
    color = _setup_output(a.no_color)
    try:
        diff = rg.diff_results(rg.load_report(a.old), rg.load_report(a.new))
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    print(rg.diff_to_txt(diff, color))
    if a.out:
        try:
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(rg.diff_to_txt(diff))
            print(f"Saved: {os.path.abspath(a.out)}")
        except OSError as e:
            print(f"ERROR: could not save: {e}", file=sys.stderr)
            return 2
    return 1 if diff["new"] else 0


def main(argv=None):
    a = build_parser().parse_args(argv)
    return _scan(a) if a.cmd == "scan" else _diff(a)


if __name__ == "__main__":
    sys.exit(main())
