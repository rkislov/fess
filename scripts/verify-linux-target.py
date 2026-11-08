"""Smoke-test a release pair in an isolated CI runner, under qemu-user when necessary."""
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

target, version = sys.argv[1:]
emulators = {"386": "i386", "amd64": "x86_64", "arm5": "arm", "arm7": "arm", "arm64": "aarch64",
             "mipsle": "mipsel", "mips64le": "mips64el", "loong64": "loongarch64"}
run = ["qemu-" + emulators.get(target, target)]
base = Path("dist").resolve()
with tempfile.TemporaryDirectory() as work:
    for app in ("fess", "fess-xdp"):
        banner = subprocess.check_output([*run, base / f"{app}-linux-{target}", "version"], text=True)
        assert banner.split()[-1] == version, banner
    xdp = (base / f"fess-xdp-linux-{target}").read_bytes()
    bpf = Path("internal/xdpguard") / ("filter-be.o" if xdp[5] == 2 else "filter.o")
    assert bpf.read_bytes() in xdp, "embedded BPF must match the target ELF byte order"
    subprocess.run([*run, base / f"fess-xdp-linux-{target}", "--check", "--config", "packaging/xdp.json.example"], check=True)
    proc = subprocess.Popen([*run, base / f"fess-linux-{target}", "--data-dir", work, "--admin", "127.0.0.1:18082",
                             "--http", "127.0.0.1:18080", "--https", ""])
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"FESS exited with status {proc.returncode}")
            try:
                with urllib.request.urlopen("http://127.0.0.1:18082/healthz", timeout=2) as response:
                    assert response.read().strip() == b"ok"
                    break
            except OSError:
                time.sleep(0.5)
        else:
            raise RuntimeError("Timed out waiting for FESS to start")
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=15)
    with sqlite3.connect(Path(work) / "fess.db") as db:
        assert db.execute("PRAGMA quick_check").fetchone() == ("ok",)
        assert db.execute("SELECT count(*) FROM fence_schema_migrations").fetchone()[0] > 0
print(f"PASS {target}: both binaries run, XDP config validated, SQLite migrated, HTTP healthy")
