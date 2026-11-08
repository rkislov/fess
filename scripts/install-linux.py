#!/usr/bin/env python3
"""Install or update FESS on Linux from verified GitHub release artifacts."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

API = "https://api.github.com/repos/rkislov/fess"
APPS = ("fess", "fess-xdp")
VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"


def fetch(url, accept, path):
    subprocess.run(["curl", "-fsSL", "--retry", "3", "--retry-all-errors",
                    "--connect-timeout", "10", "--max-time", "240",
                    "-H", "Accept: " + accept, "-o", str(path), url], check=True)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class Release:
    def __init__(self, version, tmp):
        if version is not None and not re.fullmatch(VERSION, version):
            raise ValueError("Укажите числовую версию без v, например 2.2.8")
        selector = "tags/v" + version if version else "latest"
        self.tmp = tmp
        metadata = tmp / "release.json"
        fetch(f"{API}/releases/{selector}", "application/vnd.github+json", metadata)
        release = json.loads(metadata.read_text())
        tag = release["tag_name"]
        if not re.fullmatch("v" + VERSION, tag) or (version and tag != "v" + version):
            raise ValueError(f"Неожиданный тег релиза: {tag}")
        self.version = tag[1:]
        items = release["assets"]
        # The embedded asset list may be truncated for a multi-architecture release.
        if len(items) >= 30:
            items = []
            page = 1
            while True:
                fetch(f"{release['assets_url']}?per_page=100&page={page}",
                      "application/vnd.github+json", metadata)
                batch = json.loads(metadata.read_text())
                items.extend(batch)
                if len(batch) < 100:
                    break
                page += 1
        self.assets = {item["name"]: item for item in items}
        self.sums = {}
        manifest = self.get("SHA256SUMS")
        self.sums = {n: h for h, n in (line.split() for line in manifest.read_text().splitlines())}

    def get(self, name):
        if name not in self.assets or Path(name).name != name:
            raise ValueError(f"В релизе {self.version} нет {name}")
        path = self.tmp / name
        asset = self.assets[name]
        fetch(asset["url"] + "?download=1", "application/octet-stream", path)
        digest = sha256(path)
        if (asset.get("digest") != "sha256:" + digest or
                (name != "SHA256SUMS" and self.sums.get(name) != digest)):
            raise ValueError(f"Не совпала контрольная сумма для {name}")
        print(f"{name}: SHA-256 OK", flush=True)
        return path


def linux_cpu():
    # Read the ABI of this userspace. uname alone reports the 64-bit kernel on
    # a 32-bit system and does not distinguish little/big-endian MIPS.
    with open("/proc/self/exe", "rb") as executable:
        elf = executable.read(20)
    if elf[:4] != b"\x7fELF" or elf[4] not in (1, 2) or elf[5] not in (1, 2):
        raise ValueError("Не удалось определить архитектуру Linux ELF")
    big = elf[5] == 2
    machine = int.from_bytes(elf[18:20], "big" if big else "little")
    if machine == 8:
        return ("mips64" if elf[4] == 2 else "mips") + ("" if big else "le")
    targets = {(3, 1, False): "386", (62, 2, False): "amd64", (40, 1, False): "arm5",
               (183, 2, False): "arm64", (21, 2, False): "ppc64le", (21, 2, True): "ppc64",
               (22, 2, True): "s390x", (243, 2, False): "riscv64", (258, 2, False): "loong64"}
    return targets.get((machine, elf[4], big), f"elf-{machine}-{elf[4]}-{elf[5]}")


def distro_family():
    for name in ("/etc/os-release", "/usr/lib/os-release"):
        path = Path(name)
        if path.is_file():
            values = {}
            for line in path.read_text().splitlines():
                key, sep, value = line.partition("=")
                if sep:
                    values[key] = value.strip().strip('"').strip("'")
            return set((values.get("ID", "") + " " + values.get("ID_LIKE", "")).split())
    return set()


def native_plan(release, family):
    version = release.version
    if family.intersection({"debian", "ubuntu"}) and shutil.which("apt-get") and shutil.which("dpkg"):
        arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        return "apt-get", [f"{app}_{version}_{arch}.deb" for app in APPS]
    if family.intersection({"fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn"}) and shutil.which("rpm"):
        manager = shutil.which("dnf") or shutil.which("yum")
        if manager:
            arch = subprocess.check_output(["rpm", "--eval", "%{_arch}"], text=True).strip()
            if re.fullmatch(r"i[4-6]86", arch):
                arch = "i386"
            candidates = []
            for app in APPS:
                matches = [n for n in release.assets if re.fullmatch(
                    re.escape(f"{app}-{version}-") + r"[0-9][A-Za-z0-9_.]*\." + re.escape(arch) + r"\.rpm", n)]
                if len(matches) != 1:
                    return None
                candidates.append(matches[0])
            return manager, candidates
    return None


def native_install(release, manager, names, yes):
    paths = [release.get(name) for name in names]
    release.tmp.chmod(0o755)
    for path in paths:
        path.chmod(0o644)
    command = ([] if os.geteuid() == 0 else ["sudo"]) + [manager]
    if manager == "apt-get":
        subprocess.run(command + ["update"], check=True)
    subprocess.run(command + ["install"] + (["-y"] if yes else []) + paths, check=True)


def unpack(archive, dest, wanted=None):
    found = set()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError(f"Недопустимый путь в архиве: {name}")
            if member.isdir() or (wanted is not None and str(name) not in wanted):
                continue
            if not member.isfile():
                raise ValueError(f"Недопустимый тип файла в архиве: {name}")
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
            found.add(str(name))
    if wanted is not None and not wanted.issubset(found):
        raise ValueError(f"Неполный архив: {wanted - found}")


def source_build(release, dest):
    if not shutil.which("go"):
        raise ValueError("Для сборки из исходников нужен Go версии из go.mod релиза")
    archive = release.get(f"fess_{release.version}_source.tar.gz")
    source = release.tmp / "source"
    source.mkdir()
    unpack(archive, source)
    env = dict(os.environ, CGO_ENABLED="0", GOOS="linux")
    env["GOARCH"] = subprocess.check_output(["go", "env", "GOHOSTARCH"], text=True).strip()
    for app in APPS:
        subprocess.run(["go", "build", "-trimpath", "-ldflags", f"-s -w -X main.version={release.version}",
                        "-o", str(dest / app), "./cmd/" + app], cwd=source, env=env, check=True)
    shutil.copyfile(source / "packaging/xdp.json.example", dest / "xdp.json.example")


def portable_install(release, root, force_source):
    target = linux_cpu()
    archives = [f"{app}_{release.version}_linux_{target}.tar.gz" for app in APPS]
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".fess-install.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Do not take over a directory used by another installation.
        marker = root / ".fess-portable"
        if not marker.exists() and any(p.name != ".fess-install.lock" for p in root.iterdir()):
            raise ValueError(f"Выберите пустой каталог для --prefix: {root}")
        marker.touch()
        releases = root / "releases"
        releases.mkdir(exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".new-", dir=releases))
        try:
            if not force_source and all(name in release.assets for name in archives):
                for name, wanted in zip(archives, [{"fess"}, {"fess-xdp", "xdp.json.example"}]):
                    unpack(release.get(name), stage, wanted)
            else:
                source_build(release, stage)
            for app in APPS:
                banner = subprocess.check_output([stage / app, "version"], text=True).split()
                if not banner or banner[-1] != release.version:
                    raise ValueError(f"Неверная версия {app}: {banner}")
            config = root / "etc"
            config.mkdir(mode=0o700, exist_ok=True)
            (root / "data").mkdir(mode=0o700, exist_ok=True)
            env = config / "fess.env"
            if not env.exists():
                env.write_text("FESS_ADMIN_ADDR=127.0.0.1:8082\nWAF_LISTEN_ADDR=:8080\n"
                               "WAF_TLS_LISTEN_ADDR=:8443\n# FESS_ADMIN_PASSWORD=choose-a-password\n")
                env.chmod(0o600)
            launcher = stage / "start-fess"
            launcher.write_text('#!/bin/sh\nset -eu\nroot=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n'
                                'export FESS_CONFIG="${FESS_CONFIG:-$root/etc/fess.env}"\n'
                                'export FESS_DATA_DIR="${FESS_DATA_DIR:-$root/data}"\n'
                                'exec "$root/current/fess" "$@"\n')
            launcher.chmod(0o755)
            # Switch both executables together after they have passed the version check.
            hashes = "".join(sha256(path) for path in sorted(stage.iterdir()))
            key = hashlib.sha256(hashes.encode()).hexdigest()[:16]
            installed = releases / f"{release.version}-{target}-{key}"
            if not installed.is_dir():
                stage.rename(installed)
            link = root / ".fess-next"
            link.unlink(missing_ok=True)
            link.symlink_to(installed.relative_to(root))
            os.replace(link, root / "current")
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    print(f"Конфигурация: {env}\nЗапуск: {root}/current/start-fess\n"
          "После обновления перезапустите работающий процесс через свой менеджер служб.")


def install(args):
    if sys.platform != "linux":
        raise ValueError("Установщик предназначен для Linux")
    default = Path.home() / ".local/share/fess"
    root = (args.prefix or default).expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="fess-install-") as work:
        release = Release(args.version, Path(work))
        portable = args.prefix or args.portable or args.source or (root / ".fess-portable").exists()
        system_package = Path("/etc/fess/fess.env").exists()
        use_native = not portable and (system_package or Path("/run/systemd/system").is_dir())
        plan = native_plan(release, distro_family()) if use_native else None
        if plan and all(name in release.assets for name in plan[1]):
            native_install(release, *plan, args.yes)
        else:
            if not portable and system_package:
                raise ValueError("Обнаружена системная установка FESS. В релизе нет подходящей пары "
                                 "пакетов. Для отдельной переносимой установки явно укажите --prefix.")
            portable_install(release, root, args.source)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="версия без v (по умолчанию последний релиз)")
    parser.add_argument("-y", "--yes", action="store_true", help="подтвердить установку зависимостей")
    parser.add_argument("--portable", action="store_true", help="использовать переносимые бинарники")
    parser.add_argument("--prefix", type=Path, help="каталог переносимой установки")
    parser.add_argument("--source", action="store_true", help="собрать переносимые бинарники из исходного релиза")
    try:
        install(parser.parse_args())
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        sys.exit(f"Установка FESS: {error}")
