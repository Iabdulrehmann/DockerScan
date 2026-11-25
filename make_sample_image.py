"""
make_sample_image.py
--------------------
Creates test inputs WITHOUT needing Docker. They contain deliberately planted FAKE secrets,
old packages and risky settings; DockerScan reports whatever it genuinely detects.

  sample_vulnerable_image.tar        docker-save style tarball (3 layers, includes a whiteout)
  sample_vulnerable_image_fixed.tar  same image after "fixing" it (use for diff mode)
  sample_rpm_image.tar               image whose packages live in an rpmdb.sqlite
  sample_rootfs/ + sample_config.json  plain filesystem folder + its config
"""
import io
import json
import os
import sqlite3
import struct
import tarfile
import time


def add(tar, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), mode, time.time()
    tar.addfile(info, io.BytesIO(data))


def layer(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, (data, mode) in files.items():
            add(t, name, data.encode() if isinstance(data, str) else data, mode)
    return buf.getvalue()


def write_image(out, layers, config, tag):
    with tarfile.open(out, "w") as t:
        add(t, "manifest.json", json.dumps([{"Config": "cfg123.json", "RepoTags": [tag],
                                             "Layers": [f"l{i}/layer.tar" for i in range(1, len(layers) + 1)]}]).encode())
        add(t, "cfg123.json", json.dumps(config).encode())
        for i, data in enumerate(layers, 1):
            add(t, f"l{i}/layer.tar", data)


ENVFILE = """# fake test values only
DB_PASSWORD=Sup3rS3cret!Pass99
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5
DATABASE_URL=postgres://admin:hunter2pass@db.internal:5432/app
SESSION_KEY=q8Zr3KvP0xLm92TbWc7YdHs1NfEu6AaG
"""
KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEfakefakefakefakefake\n-----END RSA PRIVATE KEY-----\n"
OSREL = 'PRETTY_NAME="Debian GNU/Linux 7 (wheezy)"\nID=debian\n'


def dpkg(openssl):
    return (f"Package: openssl\nStatus: install ok installed\nVersion: {openssl}\n\n"
            "Package: bash\nStatus: install ok installed\nVersion: 4.2+dfsg-0.1\n\n"
            "Package: curl\nStatus: install ok installed\nVersion: 7.88.1-10\n\n"
            "Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.13.dfsg-1\n")


def build_dpkg_image(out, fixed):
    pk = "usr/lib/python3/dist-packages/"
    l1 = layer({"etc/os-release": (OSREL, 0o644),
                "var/lib/dpkg/status": (dpkg("1.1.1n-0+deb11u5" if fixed else "1.0.1e-2+deb7u4"), 0o644),
                "bin/su": ("#!fake", 0o4755),
                pk + ("requests-2.31.0" if fixed else "requests-2.25.0") + ".dist-info/METADATA": ("Name: requests\n", 0o644),
                pk + "PyYAML-5.3.dist-info/METADATA": ("Name: PyYAML\n", 0o644)})
    files2 = {"app/main.py": ("print('hello')\n", 0o644),
              "app/.env.example": ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", 0o644),   # allowlist demo
              "app/old_secret.txt": ("token=ghp_zZ9yY8xX7wW6vV5uU4tT3sS2rR1qQ0pP9oO8\n", 0o644)}  # removed in layer 3
    if not fixed:
        files2.update({"app/.env": (ENVFILE, 0o644), "root/.ssh/id_rsa": (KEY, 0o600),
                       "usr/local/bin/custom-tool": ("#!fake", 0o4755)})
    l2 = layer(files2)
    l3 = layer({"app/.wh.old_secret.txt": ("", 0o644)})                 # whiteout: deletes old_secret.txt
    cfg = {"Env": ["PATH=/usr/bin"], "Cmd": ["python", "/app/main.py"]}
    if fixed:
        cfg.update({"User": "app", "ExposedPorts": {"8080/tcp": {}}, "Healthcheck": {"Test": ["CMD", "true"]}})
    else:
        cfg.update({"ExposedPorts": {"22/tcp": {}, "6379/tcp": {}, "8080/tcp": {}},
                    "Env": ["PATH=/usr/bin", "API_TOKEN=AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"]})
    hist = [{"created_by": "/bin/sh -c #(nop) ADD file:abc in /"},
            {"created_by": "RUN /bin/sh -c cp -r /src /app"},
            {"created_by": "RUN /bin/sh -c rm /app/old_secret.txt"},
            {"created_by": "/bin/sh -c #(nop) CMD [\"python\"]", "empty_layer": True}]
    if not fixed:
        hist[1] = {"created_by": "RUN /bin/sh -c curl -s http://example.com/install.sh | sh && chmod 777 /app"}
    write_image(out, [l1, l2, l3], {"architecture": "amd64", "os": "linux", "created": "2020-01-01T00:00:00Z",
                                    "config": cfg, "history": hist}, "sample/vulnerable:2.0" if fixed else "sample/vulnerable:1.0")


def rpm_header(name, version, release, epoch=None):
    """Build an RPM header blob in the documented on-disk format (tags 1000-1003)."""
    entries, data = [], b""
    for tag, s in ((1000, name), (1001, version), (1002, release)):
        entries.append((tag, 6, len(data), 1))
        data += s.encode() + b"\0"
    if epoch is not None:
        data += b"\0" * (-len(data) % 4)
        entries.append((1003, 4, len(data), 1))
        data += struct.pack(">I", epoch)
    return (struct.pack(">II", len(entries), len(data))
            + b"".join(struct.pack(">IIII", *e) for e in entries) + data)


def build_rpm_image(out):
    db = "rpmdb.sqlite"
    if os.path.exists(db):
        os.remove(db)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
    for n, v, r, e in (("openssl", "1.0.1e", "60.el7", 1), ("bash", "5.1.8", "6.el9", None), ("curl", "7.76.1", "26.el9", None)):
        con.execute("INSERT INTO Packages (blob) VALUES (?)", (rpm_header(n, v, r, e),))
    con.commit()
    con.close()
    raw = open(db, "rb").read()
    os.remove(db)
    l1 = layer({"etc/os-release": ('PRETTY_NAME="Fedora Linux 36 (Sample)"\n', 0o644), "var/lib/rpm/rpmdb.sqlite": (raw, 0o644)})
    write_image(out, [l1], {"architecture": "amd64", "os": "linux",
                            "config": {"User": "root", "Healthcheck": {"Test": ["CMD", "true"]}}, "history": []},
                "sample/rpm:1.0")


def build_rootfs(folder):
    for rel, text in (("etc/os-release", OSREL), ("var/lib/dpkg/status", dpkg("1.0.1e-2+deb7u4")),
                      ("app/.env", ENVFILE), ("app/main.py", "print('hi')\n")):
        p = os.path.join(folder, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write(text)
    json.dump({"config": {"User": "", "ExposedPorts": {"23/tcp": {}}}, "history": []}, open("sample_config.json", "w"), indent=2)


if __name__ == "__main__":
    build_dpkg_image("sample_vulnerable_image.tar", fixed=False)
    build_dpkg_image("sample_vulnerable_image_fixed.tar", fixed=True)
    build_rpm_image("sample_rpm_image.tar")
    build_rootfs("sample_rootfs")
    print("Created: sample_vulnerable_image.tar, sample_vulnerable_image_fixed.tar, sample_rpm_image.tar, "
          "sample_rootfs/, sample_config.json")
