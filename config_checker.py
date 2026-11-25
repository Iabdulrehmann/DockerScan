"""
config_checker.py
-----------------
Checks an image's configuration (the JSON config embedded in a `docker save`
archive) and its file metadata for dangerous settings:
  * running as root / missing USER instruction
  * sensitive exposed ports
  * missing HEALTHCHECK
  * setuid / setgid files
  * risky build commands (from the image history)

Also holds `make_finding()`, the single place where a finding dict is built,
so every module produces findings with the same shape.
"""
import hashlib
import posixpath
import re

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def make_finding(title, severity, category, description, location, risk, fix, *,
                 path=None, line=None, layer=None, package=None, ident=None, key=None):
    """
    Create a finding dictionary (the id is assigned later by the scanner).
    path/line/layer/package say where it was found. `ident` + `key` form a stable
    fingerprint so the same issue can be recognised in a later scan (diff mode).
    """
    fp = hashlib.sha1(f"{category}|{ident or path or location}|{key or title}".encode()).hexdigest()[:16]
    return {
        "id": "", "title": title, "severity": severity, "category": category,
        "description": description, "location": location, "risk": risk, "fix": fix,
        "path": path, "line": line, "layer": layer, "package": package,
        "fingerprint": fp, "suppressed_by": None,
    }


# port -> (service name, severity)
SENSITIVE_PORTS = {
    21: ("FTP", "Medium"), 22: ("SSH", "High"), 23: ("Telnet", "High"),
    445: ("SMB", "High"), 2375: ("Docker daemon (unencrypted API)", "Critical"),
    3306: ("MySQL", "Medium"), 3389: ("RDP", "High"), 5432: ("PostgreSQL", "Medium"),
    5900: ("VNC", "High"), 6379: ("Redis", "Medium"), 9200: ("Elasticsearch", "Medium"),
    11211: ("Memcached", "Medium"), 27017: ("MongoDB", "Medium"),
}

# setuid binaries that normally ship with a Linux base image
COMMON_SETUID = {"su", "mount", "umount", "passwd", "chsh", "chfn", "gpasswd",
                 "newgrp", "chage", "expiry", "ping", "ping6", "unix_chkpwd",
                 "wall", "write", "ssh-agent", "dotlockfile", "bbsuid"}

RISKY_COMMANDS = [
    (re.compile(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh", re.I),
     "Remote script piped into a shell", "Medium",
     "A script is downloaded and executed during the build without being verified."),
    (re.compile(r"chmod\s+(-R\s+)?0?777", re.I),
     "World-writable permissions (chmod 777)", "Medium",
     "Any user or process in the container can modify these files."),
    (re.compile(r"(curl\s[^|;&]*(-k|--insecure)|--no-check-certificate)", re.I),
     "TLS certificate verification disabled", "Medium",
     "Downloads can be tampered with by a man-in-the-middle attacker."),
]


def check_config(cfg):
    """Return findings for the image config block (User, ExposedPorts, Healthcheck)."""
    out = []
    user = (cfg.get("User") or "").strip()
    uname = user.split(":")[0]

    if user == "":
        out.append(make_finding(
            "Missing USER instruction", "Medium", "Configuration",
            "The Dockerfile never sets a USER, so Docker falls back to root.",
            "Image config (User)",
            "Every process starts with full privileges; a bug in the app becomes a root compromise.",
            "Create an unprivileged user and add 'USER appuser' near the end of the Dockerfile."))
    if uname in ("", "root", "0"):
        out.append(make_finding(
            "Container runs as root", "High", "Configuration",
            "The default user of this image is root (UID 0).",
            "Image config (User)",
            "If an attacker escapes the application they hold root inside the container, "
            "which makes container breakout and host damage much easier.",
            "Run as a non-root user: 'RUN useradd -r app' then 'USER app'. Drop capabilities at runtime."))

    for key in (cfg.get("ExposedPorts") or {}):
        try:
            port = int(str(key).split("/")[0])
        except ValueError:
            continue
        if port in SENSITIVE_PORTS:
            svc, sev = SENSITIVE_PORTS[port]
            out.append(make_finding(
                f"Sensitive port exposed: {key} ({svc})", sev, "Configuration",
                f"The image declares EXPOSE {key}, which is normally used by {svc}.",
                "Image config (ExposedPorts)",
                f"{svc} is a frequent attack target. Exposing it widens the attack surface and "
                "can leak data or give remote access if it is weakly protected.",
                f"Remove EXPOSE {port} unless it is required, never publish it publicly, "
                "and protect the service with authentication and network rules."))

    hc = cfg.get("Healthcheck") or {}
    if not hc or hc.get("Test") in (None, [], ["NONE"]):
        out.append(make_finding(
            "Missing HEALTHCHECK", "Low", "Configuration",
            "The image has no HEALTHCHECK instruction.",
            "Image config (Healthcheck)",
            "Docker cannot tell when the app is hung or broken, so failures can go unnoticed "
            "and unhealthy containers keep receiving traffic.",
            "Add a HEALTHCHECK, e.g. HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1"))
    return out


def check_setuid(entries):
    """entries: list of (path, layer_number, 'setuid'|'setgid')."""
    out = []
    for path, layer, kind in entries:
        common = posixpath.basename(path) in COMMON_SETUID
        out.append(make_finding(
            f"{kind.capitalize()} file: {path}", "Low" if common else "Medium", "Filesystem",
            f"The file has the {kind} permission bit, so it runs with its owner's privileges.",
            f"{path} (layer {layer})" if layer else path,
            "A vulnerability in a setuid/setgid program lets a normal user gain elevated privileges."
            + (" This one is a standard system utility." if common else
               " This is not a standard system utility, so it deserves review."),
            f"Remove the bit if it isn't needed: 'RUN chmod u-s,g-s {path}'.",
            path=path, layer=layer, ident=path, key=kind))
    return out


def check_history(entries):
    """entries: list of (layer_number_or_None, command_string) from the image history."""
    out = []
    for layer, cmd in entries:
        for rx, title, sev, risk in RISKY_COMMANDS:
            if rx.search(cmd):
                out.append(make_finding(
                    title, sev, "Build history",
                    "Build command: " + cmd.strip()[:300],
                    f"Layer {layer} build command" if layer else "Image history",
                    risk, "Download files with a pinned version and verify a checksum or signature.",
                    layer=layer, ident=f"history:{layer}", key=title))
    return out
