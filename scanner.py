"""
scanner.py
----------
Core engine. Accepts three kinds of input:
  1. a `docker save` tarball (.tar / .tar.gz / .tgz)
  2. an unpacked `docker save` directory (contains manifest.json)
  3. a plain filesystem directory (e.g. from `docker export`), optionally with a config JSON

Layers are extracted IN ORDER into a private temporary folder with whiteouts
applied, so what is scanned matches the image's FINAL filesystem. Files are only
written as data - nothing from the image is ever executed - and the temp folder is
deleted when the scan ends. Paths are normalised so "../" tricks cannot escape it.
Permissions (setuid etc.) are recorded from the tar headers, so they are detected
even on Windows, where the filesystem cannot store them.
"""
import datetime
import json
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import threading
import time
import zlib

import allowlist as allowlist_mod
import config_checker
import secret_detector
import vulnerability_checker
from config_checker import SEVERITY_ORDER

MAX_SCAN_BYTES = 1_000_000          # largest file read for secret scanning
MAX_DB_BYTES = 100_000_000          # package databases may be large
SKIP_PREFIXES = ("/proc/", "/sys/", "/dev/", "/usr/share/", "/usr/lib/", "/usr/include/",
                 "/usr/local/lib/", "/lib/", "/var/lib/dpkg/info/", "/var/cache/", "/var/lib/apt/")
SKIP_PARTS = ("/node_modules/", "/site-packages/", "/dist-packages/", "/.git/")
BINARY_EXT = {".so", ".a", ".o", ".png", ".jpg", ".jpeg", ".gif", ".gz", ".zip", ".xz", ".bz2", ".pyc",
              ".woff", ".woff2", ".ttf", ".ico", ".jar", ".whl", ".mo", ".db", ".bin", ".exe", ".dll"}
DB_FILES = {"/var/lib/dpkg/status", "/lib/apk/db/installed",
            "/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite"}
LEGACY_RPM = {"/var/lib/rpm/Packages", "/var/lib/rpm/Packages.db"}
OS_FILES = ("/etc/os-release", "/usr/lib/os-release")
PIP_RX = re.compile(r"/([^/]+)-(\d[^/]*)\.dist-info/METADATA$")
_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class ScanError(Exception):
    """A problem the user should be told about (bad file, corrupted archive...)."""


class ScanCancelled(Exception):
    """Raised when the user presses Cancel."""


class FileRec:
    """One file of the final filesystem. Only metadata is kept in memory."""
    __slots__ = ("disk", "mode", "size", "layer", "kind")

    def __init__(self, disk, mode, size, layer, kind):
        self.disk, self.mode, self.size, self.layer, self.kind = disk, mode, size, layer, kind


def _clean(name):
    """Normalise an archive path to an absolute POSIX path that can never climb above '/'."""
    return posixpath.normpath("/" + name.replace("\\", "/").lstrip("/"))


def _rel(name):
    name = name.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


def _safe_part(part):
    """Make one path component legal on Windows (bad characters, reserved names, trailing dots)."""
    part = _BAD_CHARS.sub("_", part).rstrip(". ") or "_"
    return "_" + part if part.split(".")[0].lower() in _RESERVED else part


def _lp(path):
    """Long-path-safe version of a path (Windows limits normal paths to 260 characters)."""
    path = os.path.abspath(path)
    return "\\\\?\\" + path if os.name == "nt" and not path.startswith("\\\\?\\") else path


# --------------------------------------------------------------------- input sources
class _TarSource:
    def __init__(self, path):
        self.tar = tarfile.open(path, "r:*")
        self.members = {_rel(m.name): m for m in self.tar.getmembers()}

    def open(self, name):
        m = self.members.get(_rel(name))
        return self.tar.extractfile(m) if m else None

    def close(self):
        self.tar.close()


class _DirSource:
    def __init__(self, root):
        self.root = os.path.realpath(root)

    def open(self, name):
        p = os.path.realpath(os.path.join(self.root, *_rel(name).split("/")))
        if not p.startswith(self.root) or not os.path.isfile(p):   # never read outside the folder
            return None
        return open(p, "rb")

    def close(self):
        pass


class DockerImageScanner:
    def __init__(self, db_path=None, progress=None, cancel_event=None, allowlist_path=None, config_path=None):
        self.db_path = db_path or vulnerability_checker.default_db_path()
        self.progress = progress or (lambda pct, msg: None)
        self.cancel = cancel_event or threading.Event()
        self.allowlist_path, self.config_path = allowlist_path, config_path

    def _p(self, pct, msg):
        self._check_cancel()
        self.progress(pct, msg)

    def _check_cancel(self):
        if self.cancel.is_set():
            raise ScanCancelled()

    # ------------------------------------------------------------------ public
    def scan(self, input_path):
        t0 = time.time()
        if not input_path or not os.path.exists(input_path):
            raise ScanError("The selected file or folder does not exist.")
        self._p(2, "Loading vulnerability database and allowlist...")
        try:
            db = vulnerability_checker.load_db(self.db_path)
        except (ValueError, OSError) as e:
            raise ScanError(f"Vulnerability database problem ({os.path.basename(self.db_path)}): {e}")
        rules = []
        if self.allowlist_path:
            try:
                rules = allowlist_mod.load_allowlist(self.allowlist_path)
            except (ValueError, OSError) as e:
                raise ScanError(f"Allowlist problem ({os.path.basename(self.allowlist_path)}): {e}")

        src = None
        try:
            if os.path.isdir(input_path):
                if os.path.isfile(os.path.join(input_path, "manifest.json")):
                    kind, src = "unpacked image directory", _DirSource(input_path)
                else:
                    kind = "filesystem directory"
            else:
                if not input_path.lower().endswith((".tar", ".tar.gz", ".tgz")):
                    raise ScanError("Unsupported file type. Choose a .tar / .tar.gz from 'docker save', or a folder.")
                self._p(4, "Opening archive...")
                try:
                    src, kind = _TarSource(input_path), "tarball"
                except (tarfile.TarError, OSError, EOFError, zlib.error):
                    raise ScanError("This file is not a readable tar/tar.gz archive. It may be corrupted, "
                                    "incomplete, or not created with 'docker save'.")
            self.root = tempfile.mkdtemp(prefix="dockerscan_")       # private extraction folder
            try:
                return self._run(input_path, kind, src, db, rules, t0)
            except (tarfile.TarError, EOFError, zlib.error) as e:
                raise ScanError(f"The image appears to be corrupted or truncated: {e}")
            except OSError as e:
                raise ScanError(f"A file operation failed during the scan: {e}")
            finally:
                shutil.rmtree(_lp(self.root), ignore_errors=True)    # always clean up
        finally:
            if src:
                src.close()

    # ------------------------------------------------------------- main routine
    def _read_json(self, src, name, what):
        f = src.open(name)
        if f is None:
            raise ScanError(f"The image is missing '{name}' ({what}). It is not a complete 'docker save' image.")
        try:
            with f:
                return json.loads(f.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ScanError(f"'{name}' is not valid JSON.")

    def _run(self, input_path, kind, src, db, rules, t0):
        self.index, self.kids, self.diskmap, self.used = {}, {}, {}, {}
        self.dbfiles, self.touched, self.intro, self.warnings, self.pkg_warn = set(), False, {}, [], set()
        findings, layers, config, manifest_n = [], [], {}, 1
        has_config = True

        if src is not None:
            self._p(7, "Reading image manifest...")
            manifest = self._read_json(src, "manifest.json", "image manifest")
            if not isinstance(manifest, list) or not manifest or "Layers" not in manifest[0] or "Config" not in manifest[0]:
                raise ScanError("manifest.json has an unexpected structure.")
            entry, manifest_n = manifest[0], len(manifest)
            config = self._read_json(src, entry["Config"], "image config")
            cmds = [h.get("created_by", "") for h in (config.get("history") or []) if not h.get("empty_layer")]
            names, total = entry["Layers"], len(entry["Layers"])
            tags = entry.get("RepoTags") or []
            for i, lname in enumerate(names):
                base_pct = 8 + int(52 * i / max(total, 1))
                self._p(base_pct, f"Extracting layer {i + 1}/{total} (whiteouts applied)...")
                fobj = src.open(lname)
                if fobj is None:
                    raise ScanError(f"Layer '{lname}' listed in the manifest is missing.")
                info = {"index": i + 1, "id": posixpath.basename(posixpath.dirname(_rel(lname))) or posixpath.basename(lname),
                        "files": 0, "size": 0, "whiteouts": 0, "created_by": cmds[i] if i < len(cmds) else ""}
                try:
                    with fobj, tarfile.open(fileobj=fobj, mode="r|*") as ltar:   # streamed, in order
                        self._extract_layer(ltar, i + 1, info, base_pct)
                except (tarfile.TarError, EOFError, zlib.error) as e:
                    raise ScanError(f"Layer {i + 1} is corrupted and could not be read: {e}")
                self._after_layer(i + 1)
                layers.append(info)
        else:
            tags = []
            self._p(8, "Indexing filesystem directory...")
            self._index_directory(input_path)
            if self.config_path:
                config = self._load_config_file(self.config_path)
            else:
                has_config = False
        cfg = config.get("config") or {}
        history = config.get("history") or []

        # ---- secrets in the FINAL filesystem
        cands = [(p, r) for p, r in self.index.items() if r.kind == "file" and r.disk and self._should_scan(p, r.size)]
        for n, (path, rec) in enumerate(cands):
            if n % 200 == 0:
                self._p(60 + int(25 * n / max(len(cands), 1)), f"Scanning files for secrets ({n}/{len(cands)})...")
            try:
                with open(_lp(rec.disk), "rb") as f:
                    data = f.read(MAX_SCAN_BYTES)
            except OSError:
                continue
            if b"\x00" in data[:2048]:
                continue
            loc = f"{path} (layer {rec.layer})" if rec.layer else path
            findings += secret_detector.scan_text(data.decode("utf-8", "replace"), loc, path, layer=rec.layer, path=path)
            if re.search(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$", path):
                findings.append(config_checker.make_finding(
                    f"SSH private key file: {path}", "Critical", "Secret",
                    "A file named like an SSH private key is present in the image.", loc,
                    secret_detector.RISK["Critical"], secret_detector.FIX,
                    path=path, layer=rec.layer, ident=path, key="ssh-key-file"))

        # ---- packages
        self._p(86, "Building package inventory (dpkg / apk / rpm / pip)...")
        packages = self._snapshot_packages()
        for p in packages:
            p["layer"] = self.intro.get((p["ecosystem"], p["name"], p["version"]))
        for path, rec in self.index.items():
            m = PIP_RX.search(path) if path.endswith("/METADATA") else None
            if m:
                packages.append({"name": m.group(1).lower().replace("_", "-"), "version": m.group(2),
                                 "source": "pip", "ecosystem": "pypi", "layer": rec.layer})
        for w in sorted(self.pkg_warn):
            findings.append(config_checker.make_finding(
                w, "Informational", "Information", w, "Package databases", "Packages from this database were not inventoried.",
                "Use an image with a supported package database.", ident="pkgdb", key=w))
        if LEGACY_RPM & set(self.index) and not any(p["source"] == "rpm" for p in packages):
            msg = "Legacy RPM database (BerkeleyDB/NDB) found but not supported"
            findings.append(config_checker.make_finding(
                msg, "Informational", "Information",
                "Only the SQLite RPM database (rpmdb.sqlite) can be parsed. RPM packages were not inventoried.",
                "/var/lib/rpm", "Vulnerable RPM packages in this image cannot be detected.",
                "Scan a newer image (Fedora 33+/RHEL 9+) or export its package list separately.", ident="rpm", key=msg))

        self._p(90, "Comparing packages with vulnerability database...")
        findings += vulnerability_checker.check_packages(packages, db)

        # ---- misconfiguration
        self._p(94, "Checking configuration and setuid files...")
        if has_config:
            findings += config_checker.check_config(cfg)
            hist, k = [], 0
            for h in history:
                if h.get("empty_layer"):
                    hist.append((None, h.get("created_by", "")))
                else:
                    k += 1
                    hist.append((k, h.get("created_by", "")))
            findings += config_checker.check_history(hist)
            for env in cfg.get("Env") or []:
                findings += secret_detector.scan_text(env, "Image config (ENV variable)", "config.env")
            for layer_no, cmd in hist:
                findings += secret_detector.scan_text(
                    cmd, f"Layer {layer_no} build command" if layer_no else "Image history", "history.sh", layer=layer_no)
        else:
            findings.append(config_checker.make_finding(
                "No image config supplied - user, port and healthcheck checks skipped", "Informational", "Information",
                "A plain filesystem folder carries no image configuration. Re-run with the image config JSON "
                "(--config in the CLI, or answer the prompt in the app) to enable those checks.",
                "Input", "Running as root, exposed ports and a missing HEALTHCHECK cannot be checked.",
                "Provide the config blob from 'docker save' or the output of 'docker inspect'.", ident="noconfig", key="noconfig"))
        setuid = [(p, r.layer, "setuid" if r.mode & 0o4000 else "setgid") for p, r in sorted(self.index.items())
                  if r.kind == "file" and r.mode & 0o6000]
        findings += config_checker.check_setuid(setuid)

        osrel = ""
        for p in OS_FILES:
            if p in self.index and self.index[p].disk:
                osrel = self._read_text(self.index[p].disk)
                break
        os_name = "Unknown"
        mt = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', osrel, re.M)
        if mt:
            os_name = mt.group(1)
            findings.append(config_checker.make_finding(
                f"Operating system detected: {os_name}", "Informational", "Information",
                f"The image is based on {os_name}.", "/etc/os-release",
                "Older or end-of-life operating systems no longer receive security updates.",
                "Use a currently supported base image and rebuild regularly.", ident="os", key="os"))

        # ---- allowlist, ordering, ids
        self._p(97, "Grading findings and building report...")
        findings, suppressed = allowlist_mod.apply_allowlist(findings, rules)
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        for lst, prefix in ((findings, "DS"), (suppressed, "SUP")):
            lst.sort(key=lambda f: (rank[f["severity"]], f["category"], f["title"]))
            for n, f in enumerate(lst, 1):
                f["id"] = f"{prefix}-{n:03d}"
        summary = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
        summary["Total"], summary["Suppressed"] = len(findings), len(suppressed)

        image = {
            "archive": input_path, "input_type": kind,
            "archive_size": os.path.getsize(input_path) if os.path.isfile(input_path) else 0,
            "tags": tags, "os_name": os_name, "platform": f"{config.get('os', '?')}/{config.get('architecture', '?')}",
            "created": config.get("created", "unknown"), "user": cfg.get("User") or "(root)" if has_config else "unknown",
            "entrypoint": cfg.get("Entrypoint") or [], "cmd": cfg.get("Cmd") or [], "env_count": len(cfg.get("Env") or []),
            "exposed_ports": sorted((cfg.get("ExposedPorts") or {}).keys()),
            "healthcheck": bool(cfg.get("Healthcheck")), "images_in_archive": manifest_n,
            "files_in_final_filesystem": len(self.index),
        }
        self._p(100, "Scan complete")
        return {"tool": "DockerScan", "author": "Muhammad Abdul Rehman",
                "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration_seconds": round(time.time() - t0, 2), "image": image, "layers": layers,
                "packages": packages, "findings": findings, "suppressed": suppressed,
                "summary": summary, "warnings": self.warnings}

    def _load_config_file(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise ScanError(f"Could not read the config JSON ({os.path.basename(path)}): {e}")
        if not isinstance(data, dict):
            raise ScanError("The config JSON must be an object.")
        return data if "config" in data else {"config": data}       # accept the inner object too

    # ---------------------------------------------------------- extraction helpers
    def _should_scan(self, path, size):
        if size == 0 or size > MAX_SCAN_BYTES:
            return False
        if path.startswith(SKIP_PREFIXES) or any(p in path for p in SKIP_PARTS):
            return False
        return os.path.splitext(path)[1].lower() not in BINARY_EXT

    def _wanted(self, path, size):
        """Only files the scanners may read are written to disk; the rest are tracked by metadata."""
        if path in DB_FILES or path in OS_FILES or path.startswith("/var/lib/dpkg/status.d/"):
            return size <= MAX_DB_BYTES
        return self._should_scan(path, size)

    def _register(self, path):
        while path != "/":
            parent = posixpath.dirname(path)
            kids = self.kids.setdefault(parent, set())
            if path in kids:
                break
            kids.add(path)
            path = parent

    def _rm_disk(self, disk):
        try:
            os.remove(_lp(disk))
        except OSError:
            pass

    def _add(self, path, rec):
        old = self.index.get(path)
        if old and old.disk and old.disk != rec.disk:
            self._rm_disk(old.disk)
        self.index[path] = rec
        self._register(path)

    def _remove(self, path, layer_no):
        """Whiteout: delete everything at/under `path` that came from LOWER layers."""
        stack = [path]
        while stack:
            p = stack.pop()
            rec = self.index.get(p)
            if rec and rec.layer < layer_no:
                del self.index[p]
                if rec.disk:
                    self._rm_disk(rec.disk)
            stack.extend(self.kids.get(p, ()))

    def _disk_path(self, path):
        if path in self.diskmap:
            return self.diskmap[path]
        d = os.path.join(self.root, *[_safe_part(p) for p in path.strip("/").split("/")])
        if self.used.get(d.lower(), path) != path:                  # case-insensitive filesystem clash
            d += f"~{len(self.used)}"
        self.used[d.lower()] = path
        self.diskmap[path] = d
        return d

    def _write(self, path, data):
        d = self._disk_path(path)
        try:
            os.makedirs(_lp(os.path.dirname(d)), exist_ok=True)
            with open(_lp(d), "wb") as f:
                f.write(data)
            return d
        except OSError:
            self.warnings.append(f"Could not extract {path} (name or path not allowed by this filesystem); skipped.")
            return None

    def _extract_layer(self, ltar, layer_no, info, base_pct):
        for m in ltar:
            info["files"] += 1
            if info["files"] % 250 == 0:
                self._p(base_pct, f"Layer {layer_no}: {info['files']} entries processed...")
            path = _clean(m.name)
            if path == "/":
                continue
            base, parent = posixpath.basename(path), posixpath.dirname(path)
            if base == ".wh..wh..opq":                              # opaque dir: hide all lower-layer content
                self._remove(parent, layer_no)
                info["whiteouts"] += 1
                continue
            if base.startswith(".wh."):                             # whiteout: delete one lower-layer entry
                self._remove(posixpath.join(parent, base[4:]), layer_no)
                info["whiteouts"] += 1
                continue
            if m.isdir():
                self._register(path)
            elif m.issym():
                self._add(path, FileRec(None, m.mode, 0, layer_no, "symlink"))   # recorded, never created
            elif m.islnk():
                tgt = self.index.get(_clean(m.linkname))
                self._add(path, FileRec(tgt.disk if tgt else None, m.mode, tgt.size if tgt else 0, layer_no, "file"))
            elif m.isfile():
                info["size"] += m.size
                disk = None
                if self._wanted(path, m.size):
                    f = ltar.extractfile(m)
                    disk = self._write(path, f.read()) if f else None
                self._add(path, FileRec(disk, m.mode, m.size, layer_no, "file"))
                if path in DB_FILES or path in LEGACY_RPM or path.startswith("/var/lib/dpkg/status.d/"):
                    self.dbfiles.add(path)
                    self.touched = True
            # devices, FIFOs etc. are ignored

    def _after_layer(self, layer_no):
        """Record which layer first introduced each (package, version)."""
        if self.touched:
            for p in self._snapshot_packages():
                self.intro.setdefault((p["ecosystem"], p["name"], p["version"]), layer_no)
            self.touched = False

    def _index_directory(self, root):
        for dp, _dirs, files in os.walk(root, followlinks=False):
            self._check_cancel()
            rel = os.path.relpath(dp, root)
            base = "/" if rel == "." else "/" + rel.replace(os.sep, "/")
            for fn in files:
                full, img = os.path.join(dp, fn), posixpath.join(base, fn)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    self._add(img, FileRec(None, st.st_mode & 0o7777, 0, None, "symlink"))
                elif stat.S_ISREG(st.st_mode):
                    self._add(img, FileRec(full, st.st_mode & 0o7777, st.st_size, None, "file"))
                    if img in DB_FILES or img in LEGACY_RPM or img.startswith("/var/lib/dpkg/status.d/"):
                        self.dbfiles.add(img)
        if os.name == "nt":
            self.warnings.append("Scanning a folder on Windows: setuid/setgid bits cannot be read from the filesystem. "
                                 "Scan a docker-save tarball instead to detect them.")

    def _read_text(self, disk):
        try:
            with open(_lp(disk), "rb") as f:
                return f.read(MAX_DB_BYTES).decode("utf-8", "replace")
        except OSError:
            return ""

    def _snapshot_packages(self):
        """Parse every package database present in the filesystem right now."""
        pkgs, dpkg = [], []
        for p in sorted(self.dbfiles):
            rec = self.index.get(p)
            if not rec or not rec.disk:
                continue
            if p.startswith("/var/lib/dpkg/"):
                dpkg.append(self._read_text(rec.disk))
            elif p == "/lib/apk/db/installed":
                pkgs += vulnerability_checker.parse_apk_installed(self._read_text(rec.disk))
            elif p.endswith("rpmdb.sqlite"):
                try:
                    pkgs += vulnerability_checker.parse_rpm_sqlite(rec.disk)
                except ValueError as e:
                    self.pkg_warn.add(f"RPM database could not be read: {e}")
        if dpkg:
            pkgs += vulnerability_checker.parse_dpkg_status("\n\n".join(dpkg))
        return pkgs
