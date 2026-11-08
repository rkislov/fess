#!/usr/bin/env python3
"""Install the official fess and fess-xdp DEBs using Ubuntu's APT."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

API = "https://api.github.com/repos/rkislov/fess"


def fetch(url, accept, path):
    subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3",
        "--retry-all-errors", "--connect-timeout", "10", "--max-time", "120",
        "--header", "Accept: " + accept, "--output", str(path), url,
    ], check=True)


def download(asset, directory):
    path = directory / asset["name"]
    fetch(asset["url"] + "?download=1", "application/octet-stream", path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if asset.get("digest") != "sha256:" + digest:
        raise ValueError(f"Не совпала контрольная сумма GitHub для {path.name}")
    return path, digest


def install(args):
    arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
    if arch not in ("amd64", "arm64"):
        raise ValueError(f"Для архитектуры {arch} в релизе нет пакетов")
    selector = "latest"
    if args.version:
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
            raise ValueError("Укажите номер версии без буквы v, например 2.2.7")
        selector = "tags/v" + args.version
    with tempfile.TemporaryDirectory(prefix="fess-deb-") as tmp:
        directory = Path(tmp)
        metadata = directory / "release.json"
        fetch(f"{API}/releases/{selector}", "application/vnd.github+json", metadata)
        release = json.loads(metadata.read_text())
        tag = release["tag_name"]
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) or (args.version and tag != "v" + args.version):
            raise ValueError(f"Неожиданный тег релиза: {tag}")
        assets = {a["name"]: a for a in release["assets"]}
        manifest, _ = download(assets["SHA256SUMS"], directory)
        sums = {name: digest for digest, name in (line.split() for line in manifest.read_text().splitlines())}
        paths = []
        for package in ("fess", "fess-xdp"):
            name = f"{package}_{tag[1:]}_{arch}.deb"
            path, digest = download(assets[name], directory)
            if sums.get(name) != digest:
                raise ValueError(f"Не совпала сумма из SHA256SUMS для {name}")
            paths.append(str(path))
            print(f"{name}: SHA-256 OK", flush=True)
        # Allow APT's _apt user to read the verified local DEBs.
        directory.chmod(0o755)
        for path in paths:
            Path(path).chmod(0o644)
        apt = (["sudo"] if os.geteuid() else []) + ["apt-get"]
        subprocess.run(apt + ["update"], check=True)
        subprocess.run(apt + ["install"] + (["-y"] if args.yes else []) + paths, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="версия без v (по умолчанию — последний релиз)")
    parser.add_argument("-y", "--yes", action="store_true", help="подтвердить установку зависимостей")
    try:
        install(parser.parse_args())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"Установка FESS: {error}")
