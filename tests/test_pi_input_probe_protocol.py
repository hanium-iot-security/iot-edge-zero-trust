"""Run the same small C++ ICMP parser used by the ESP32, without sockets."""
from pathlib import Path
import shutil
import subprocess

import pytest


def test_native_icmp_echo_parser(tmp_path):
    compiler = shutil.which("c++")
    if not compiler:
        pytest.skip("native C++ compiler unavailable; Arduino compile is separate")
    root = Path(__file__).resolve().parents[1]
    fixture = root / "tests/fixtures/pi_input_probe_protocol_test.cpp"
    include = root / "firmware/esp32/pi_input_isolation_probe"
    executable = tmp_path / "icmp-protocol-test"
    build = subprocess.run([compiler, "-std=c++11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(include), str(fixture), "-o", str(executable)],
                           capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, build.stdout + build.stderr
    run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "ICMP_PROTOCOL_CASES=23" in run.stdout
