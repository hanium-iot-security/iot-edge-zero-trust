from configparser import ConfigParser
from pathlib import Path


UNIT_PATH = Path("infra/systemd/mqtt-subscriber.service")
RUNBOOK_PATH = Path("docs/mqtt-subscriber-deployment-runbook.md")


def _load_unit() -> ConfigParser:
    parser = ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with UNIT_PATH.open(encoding="utf-8") as unit_file:
        parser.read_file(unit_file)
    return parser


def test_mqtt_subscriber_service_runs_as_pi_from_the_project_environment() -> None:
    service = _load_unit()["Service"]

    assert service["User"] == "pi"
    assert service["Group"] == "pi"
    assert service["WorkingDirectory"] == "/home/pi/iot-edge-zero-trust"
    assert service["EnvironmentFile"] == "/home/pi/iot-edge-zero-trust/.env"
    assert service["ExecStart"] == (
        "/home/pi/iot-edge-zero-trust/venv/bin/python -m edge.mqtt.subscriber"
    )


def test_mqtt_subscriber_service_waits_for_network_time_and_broker() -> None:
    unit = _load_unit()["Unit"]

    assert set(unit["After"].split()) == {
        "network-online.target",
        "systemd-time-wait-sync.service",
        "mosquitto.service",
    }
    assert set(unit["Wants"].split()) == {
        "network-online.target",
        "systemd-time-wait-sync.service",
    }
    assert unit["Requires"] == "mosquitto.service"
    assert unit["StartLimitIntervalSec"] == "300"
    assert unit["StartLimitBurst"] == "5"


def test_mqtt_subscriber_service_has_bounded_restart_and_shutdown() -> None:
    service = _load_unit()["Service"]

    assert service["Restart"] == "on-failure"
    assert service["RestartSec"] == "5"
    assert service["KillSignal"] == "SIGTERM"
    assert service["TimeoutStopSec"] == "15"
    assert service["NoNewPrivileges"] == "true"
    assert service["StandardOutput"] == "journal"
    assert service["StandardError"] == "journal"
    assert service["SyslogIdentifier"] == "mqtt-subscriber"
    assert _load_unit()["Install"]["WantedBy"] == "multi-user.target"


def test_mqtt_subscriber_service_uses_linux_line_endings() -> None:
    assert b"\r\n" not in UNIT_PATH.read_bytes()


def test_runbook_covers_installation_observation_restart_and_reboot() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    for required in (
        "Mosquitto",
        "systemctl is-active mosquitto.service",
        "/home/pi/iot-edge-zero-trust/.env",
        "/home/pi/iot-edge-zero-trust/venv/bin/python",
        'stamp="$(date -u +%Y%m%dT%H%M%SZ)"',
        '"/etc/systemd/system/mqtt-subscriber.service.${stamp}.bak"',
        "sudo install -m 0644",
        "infra/systemd/mqtt-subscriber.service",
        "/etc/systemd/system/mqtt-subscriber.service",
        "sudo systemctl daemon-reload",
        "sudo systemctl enable --now mqtt-subscriber.service",
        "systemctl is-enabled mqtt-subscriber.service",
        "systemctl is-active mqtt-subscriber.service",
        "sudo systemd-analyze verify /etc/systemd/system/mqtt-subscriber.service",
        "sha256sum infra/systemd/mqtt-subscriber.service",
        "sha256sum /etc/systemd/system/mqtt-subscriber.service",
        "journalctl --utc -u mqtt-subscriber.service -n 100 --no-pager",
        "sudo systemctl restart mqtt-subscriber.service",
        "SELECT COUNT(*) FROM mqtt_logs",
        "sudo reboot",
        "운영자 승인",
    ):
        assert required in runbook


def test_runbook_covers_troubleshooting_safe_rollback_and_secret_boundaries() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert "장애 확인" in runbook
    assert "Rollback" in runbook
    assert "sudo systemctl disable --now mqtt-subscriber.service" in runbook
    assert "sudo cp -a" in runbook
    assert "sudo systemctl reset-failed mqtt-subscriber.service" in runbook
    assert "실제 운영 DB" in runbook
    assert ".env" in runbook
    assert "Git에 포함하지" in runbook
