from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVICE_PATH = ROOT / "infra/systemd/packet-feature-extractor.service"
TIMER_PATH = ROOT / "infra/systemd/packet-feature-extractor.timer"
RUNBOOK_PATH = ROOT / "docs/packet-feature-runbook.md"


def test_packet_feature_extractor_service_contract() -> None:
    assert SERVICE_PATH.exists(), "packet-feature-extractor.service must be tracked"

    unit = SERVICE_PATH.read_text(encoding="utf-8")

    assert "Type=oneshot" in unit
    assert "User=pi" in unit
    assert "Group=pi" in unit
    assert "WorkingDirectory=/home/pi/iot-edge-zero-trust" in unit
    assert "EnvironmentFile=/home/pi/iot-edge-zero-trust/.env" in unit
    assert "EnvironmentFile=-/home/pi/iot-edge-zero-trust/.env" not in unit
    assert (
        "ExecStart=/home/pi/iot-edge-zero-trust/venv/bin/python "
        "-m edge.features.run_packet_feature_extractor --limit 20"
    ) in unit
    assert "--session-id" not in unit
    assert "NoNewPrivileges=true" in unit
    assert "StandardOutput=journal" in unit
    assert "StandardError=journal" in unit
    assert "SyslogIdentifier=packet-feature-extractor" in unit


def test_packet_feature_extractor_timer_contract() -> None:
    assert TIMER_PATH.exists(), "packet-feature-extractor.timer must be tracked"

    timer = TIMER_PATH.read_text(encoding="utf-8")

    assert "OnBootSec=5s" in timer
    assert "OnUnitActiveSec=5s" in timer
    assert "AccuracySec=1s" in timer
    assert "Unit=packet-feature-extractor.service" in timer
    assert "WantedBy=timers.target" in timer


def test_packet_feature_runbook_documents_systemd_cutover_contract() -> None:
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    assert "packet-feature-extractor.service" in runbook
    assert "packet-feature-extractor.timer" in runbook
    assert "--limit 20" in runbook
    assert "5초" in runbook
    assert "ORCHESTRATOR_ENABLED_STAGES=mqtt_feature_rule,mqtt_message_rule" in runbook
    assert "sudo systemctl enable --now packet-feature-extractor.timer" in runbook
    assert "sudo systemctl disable --now packet-feature-extractor.timer" in runbook
    assert "READY Backlog" in runbook
