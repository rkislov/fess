#!/usr/bin/env python3
"""Compatibility entry point for the original standalone download URL."""
from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="fess-bootstrap-") as directory:
    installer = Path(directory) / "install-linux.py"
    subprocess.run(["curl", "-fsSL", "--retry", "3", "--retry-all-errors", "-o", str(installer),
                    "https://raw.githubusercontent.com/rkislov/fess/main/scripts/install-linux.py"], check=True)
    sys.exit(subprocess.call([sys.executable, str(installer), *sys.argv[1:]]))
