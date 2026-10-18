#!/usr/bin/python3
"""Moduli aedificati in ambitu temporario probantur, sine rete."""
from pathlib import Path
import subprocess
import sys
import tempfile
import venv

built = Path.cwd().resolve()
with tempfile.TemporaryDirectory(prefix="test-environment-", dir=built) as temporary:
    environment = Path(temporary)
    venv.EnvBuilder(system_site_packages=True, with_pip=False).create(environment)
    python = environment / "bin" / "python3"
    location = subprocess.check_output([str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"], text=True).strip()
    (Path(location) / "probentium-build-test.pth").write_text(str(built) + "\n", encoding="utf-8")
    for directory in ("tests", "tests_r1"):
        result = subprocess.run([str(python), "-m", "unittest", "discover", "-s", directory, "-v"], check=False)
        if result.returncode:
            raise SystemExit(result.returncode)
