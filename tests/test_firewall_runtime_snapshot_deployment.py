from __future__ import annotations

from configparser import ConfigParser
from pathlib import Path

from backend.app.services import recovery_command_service
from backend.app.services.firewall_runtime_verifier import verify_runtime_firewall


SNAPSHOT_SERVICE = Path("infra/systemd/firewall-runtime-snapshot.service")
SNAPSHOT_TIMER = Path("infra/systemd/firewall-runtime-snapshot.timer")
API_SERVICE = Path("infra/systemd/iot-edge-api.service")


def _load_unit(path: Path) -> ConfigParser:
    parser = ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with path.open(encoding="utf-8") as unit_file:
        parser.read_file(unit_file)
    return parser


def test_snapshot_service_runs_dedicated_read_only_observer_as_pi() -> None:
    unit = _load_unit(SNAPSHOT_SERVICE)
    service = unit["Service"]

    assert service["Type"] == "oneshot"
    assert service["User"] == "pi"
    assert service["Group"] == "pi"
    assert service["WorkingDirectory"] == "/home/pi/iot-edge-zero-trust"
    assert service["EnvironmentFile"] == "/home/pi/iot-edge-zero-trust/.env"
    assert service["ExecStart"] == (
        "/home/pi/iot-edge-zero-trust/venv/bin/python "
        "-m edge.trust.run_firewall_runtime_snapshot"
    )
    assert service["NoNewPrivileges"] == "false"
    assert service["ReadOnlyPaths"] == "/etc/hanium"


def test_api_service_keeps_no_new_privileges_enabled() -> None:
    api = _load_unit(API_SERVICE)
    assert api["Service"]["NoNewPrivileges"] == "true"
    assert "sudo" not in api["Service"]["ExecStart"]
    assert "iptables" not in api["Service"]["ExecStart"]


def test_snapshot_timer_refreshes_more_often_than_default_verifier_ttl() -> None:
    timer = _load_unit(SNAPSHOT_TIMER)["Timer"]
    assert timer["OnBootSec"] == "2s"
    assert timer["OnUnitActiveSec"] == "5s"
    assert timer["AccuracySec"] == "1s"
    assert timer["Unit"] == "firewall-runtime-snapshot.service"


def test_fastapi_composition_root_wires_snapshot_verifier() -> None:
    # Importing backend.app.main is the application composition step that replaces
    # Recovery's fail-closed default with the configured read-only verifier.
    import backend.app.main  # noqa: F401

    assert recovery_command_service.firewall_runtime_verifier is verify_runtime_firewall


def test_snapshot_units_use_linux_line_endings() -> None:
    assert b"\r\n" not in SNAPSHOT_SERVICE.read_bytes()
    assert b"\r\n" not in SNAPSHOT_TIMER.read_bytes()


def test_worker_and_wrapper_use_root_controlled_protection_configuration():
    worker = _load_unit(Path("infra/systemd/firewall-worker.service"))["Service"]
    assert worker["ReadOnlyPaths"] == "/etc/hanium"
    example = Path("infra/firewall-protected-ipv4.conf.example").read_text()
    assert "root:root" in example and "0644" in example
    assert "No guessed addresses" in example
