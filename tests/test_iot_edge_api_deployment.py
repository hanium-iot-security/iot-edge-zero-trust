from configparser import ConfigParser
from pathlib import Path


UNIT_PATH = Path("infra/systemd/iot-edge-api.service")
RUNBOOK_PATH = Path("docs/phase4-api-deployment-runbook.md")


def _load_unit() -> ConfigParser:
    parser = ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with UNIT_PATH.open(encoding="utf-8") as unit_file:
        parser.read_file(unit_file)
    return parser


def test_iot_edge_api_service_runs_full_fastapi_app_from_required_environment() -> None:
    unit = _load_unit()
    service = unit["Service"]

    assert service["User"] == "pi"
    assert service["Group"] == "pi"
    assert service["WorkingDirectory"] == "/home/pi/iot-edge-zero-trust"
    assert service["EnvironmentFile"] == "/home/pi/iot-edge-zero-trust/.env"
    assert service["ExecStart"] == (
        "/home/pi/iot-edge-zero-trust/venv/bin/python "
        "-m uvicorn backend.app.main:app "
        "--host ${API_HOST} --port ${API_PORT}"
    )
    assert "--reload" not in service["ExecStart"]


def test_iot_edge_api_service_has_bounded_restart_and_graceful_shutdown() -> None:
    unit = _load_unit()

    assert unit["Unit"]["StartLimitIntervalSec"] == "300"
    assert unit["Unit"]["StartLimitBurst"] == "5"

    service = unit["Service"]
    assert service["Restart"] == "on-failure"
    assert service["RestartSec"] == "5"
    assert service["KillSignal"] == "SIGTERM"
    assert service["TimeoutStopSec"] == "15"
    assert service["NoNewPrivileges"] == "true"
    assert service["StandardOutput"] == "journal"
    assert service["StandardError"] == "journal"
    assert service["SyslogIdentifier"] == "iot-edge-api"


def test_iot_edge_api_service_waits_for_network_and_starts_on_normal_boot() -> None:
    unit = _load_unit()

    assert unit["Unit"]["After"] == "network-online.target"
    assert unit["Unit"]["Wants"] == "network-online.target"
    assert unit["Install"]["WantedBy"] == "multi-user.target"


def test_iot_edge_api_service_uses_linux_line_endings() -> None:
    assert b"\r\n" not in UNIT_PATH.read_bytes()
    attributes = Path(".gitattributes").read_text(encoding="utf-8")
    assert "*.service text eol=lf" in attributes


def test_api_deployment_runbook_installs_and_observes_the_service() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert (
        "sudo install -m 0644 infra/systemd/iot-edge-api.service "
        "/etc/systemd/system/iot-edge-api.service"
    ) in runbook
    assert "sudo systemctl daemon-reload" in runbook
    assert "sudo systemctl enable --now iot-edge-api.service" in runbook
    assert "systemctl is-enabled iot-edge-api.service" in runbook
    assert "systemctl is-active iot-edge-api.service" in runbook
    assert "journalctl --utc -u iot-edge-api.service -n 100 --no-pager" in runbook


def test_api_deployment_runbook_verifies_health_and_exact_cors_origin() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert "curl --fail --silent --show-error http://127.0.0.1:8000/api/health" in runbook
    assert "http://192.168.0.20:8000/api/health" in runbook
    assert 'Origin: http://192.168.0.3:5173' in runbook
    assert "Access-Control-Allow-Origin: http://192.168.0.3:5173" in runbook
    assert "API_ALLOWED_ORIGINS" in runbook
    assert "Wildcard" in runbook


def test_api_deployment_runbook_verifies_phase4_schema_and_representative_apis() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert "SELECT version, name" in runbook
    assert "FROM schema_migrations" in runbook
    assert "1|init" in runbook
    assert "2|packet_gateway" in runbook
    assert "3|phase4_detection" in runbook
    assert "/api/packet-feature-logs?limit=1&offset=0" in runbook
    assert "/api/firewall-rules?limit=1&offset=0" in runbook


def test_api_deployment_runbook_covers_restart_reboot_and_safe_rollback() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert "sudo systemctl restart iot-edge-api.service" in runbook
    assert "sudo reboot" in runbook
    assert "sudo systemctl disable --now iot-edge-api.service" in runbook
    assert (
        "python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"
        in runbook
    )
    assert "Port Forwarding" in runbook
    assert "공인망" in runbook


def test_api_deployment_docs_distinguish_local_reload_from_pi_service() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    pi_setup = Path("docs/raspberry-pi-setup.md").read_text(encoding="utf-8")
    demo_guide = Path("docs/demo-guide.md").read_text(encoding="utf-8")

    assert "`--reload`는 로컬 개발용" in readme
    assert "iot-edge-api.service" in readme
    assert "docs/phase4-api-deployment-runbook.md" in readme

    assert "Pi 운영" in pi_setup
    assert "sudo systemctl enable --now iot-edge-api.service" in pi_setup
    assert "docs/phase4-api-deployment-runbook.md" in pi_setup

    assert "로컬 개발" in demo_guide
    assert "Pi 운영" in demo_guide
    assert "sudo systemctl start iot-edge-api.service" in demo_guide
    assert "BOOTSTRAP-MQTT-FEATURE-CHECKPOINT" in demo_guide
    assert "기존 운영 DB는 Phase 4" in demo_guide


def test_env_example_explains_exact_dashboard_origin_for_cors() -> None:
    env_example = Path(".env.example").read_text(encoding="utf-8")

    assert "# Dashboard를 실제로 여는 Origin만 쉼표로 나열합니다." in env_example
    assert "# 예: http://192.168.0.3:5173" in env_example
    assert "API_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173" in env_example
    assert "API_ALLOW_CREDENTIALS=true" in env_example
