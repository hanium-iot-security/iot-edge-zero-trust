"""Phase 5 Raspberry Pi Scenario Hook 최소 계약 테스트."""

from __future__ import annotations

import sqlite3
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

import pytest

from edge.scenarios.cleanup import (
    ScenarioHookContext,
    pi_baseline_check,
    pi_cleanup_hook,
)
from edge.scenarios.run_scenario import ScenarioExecStatus, ScenarioRunner


def _context(**overrides: str | None) -> ScenarioHookContext:
    values: dict[str, str | None] = {
        "run_id": "run-001",
        "scenario_id": "mqtt_abnormal_publish_rate",
        "session_id": "session-001",
        "target_device_id": "esp32_02",
        "source_ip": "192.168.0.30",
        "target_host": "192.168.0.20",
        "evaluation_scope": "FULL_E2E",
        "execution_node": "iot-gateway",
    }
    values.update(overrides)
    return ScenarioHookContext(**values)


def _create_baseline_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE devices (
                device_id TEXT PRIMARY KEY,
                ip_address TEXT,
                status TEXT NOT NULL,
                trust_score INTEGER NOT NULL
            );
            CREATE TABLE firewall_rules (
                id INTEGER PRIMARY KEY,
                device_id TEXT,
                source_ip TEXT,
                status TEXT NOT NULL
            );
            CREATE TABLE packet_capture_sessions (
                id INTEGER PRIMARY KEY,
                session_id TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                ended_at TEXT
            );
            INSERT INTO devices(device_id, ip_address, status, trust_score)
            VALUES ('esp32_02', '192.168.0.30', 'normal', 100);
            INSERT INTO packet_capture_sessions(session_id, status, ended_at)
            VALUES ('session-001', 'RUNNING', NULL);
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_scenario_hook_context_is_frozen():
    context = _context()
    with pytest.raises(FrozenInstanceError):
        context.run_id = "changed"  # type: ignore[misc]


def test_runner_passes_same_context_object_to_baseline_and_cleanup(tmp_path: Path):
    received: list[ScenarioHookContext] = []

    def baseline(context: ScenarioHookContext) -> tuple[bool, str | None]:
        received.append(context)
        return True, None

    def cleanup(context: ScenarioHookContext) -> tuple[bool, str | None]:
        received.append(context)
        return True, None

    runner = ScenarioRunner(
        execution_node="iot-gateway",
        execution_node_registered=True,
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=baseline,
        cleanup_hook=cleanup,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, _manifest = runner.run(
            "mqtt_abnormal_publish_rate",
            run_id="context-run",
            target_device_id="esp32_02",
            source_ip="192.168.0.30",
            target_host="192.168.0.20",
            session_id="session-001",
            dry_run=False,
        )

    assert result.scenario_runner_status == ScenarioExecStatus.SUCCESS
    assert len(received) == 2
    assert received[0] is received[1]
    assert received[0] == ScenarioHookContext(
        run_id="context-run",
        scenario_id="mqtt_abnormal_publish_rate",
        session_id="session-001",
        target_device_id="esp32_02",
        source_ip="192.168.0.30",
        target_host="192.168.0.20",
        evaluation_scope="FULL_E2E",
        execution_node="iot-gateway",
    )


def test_dry_run_does_not_call_context_hooks(tmp_path: Path):
    calls = {"baseline": 0, "cleanup": 0}

    def baseline(_context: ScenarioHookContext) -> tuple[bool, str | None]:
        calls["baseline"] += 1
        return True, None

    def cleanup(_context: ScenarioHookContext) -> tuple[bool, str | None]:
        calls["cleanup"] += 1
        return True, None

    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        baseline_check=baseline,
        cleanup_hook=cleanup,
    )
    result, _manifest = runner.run("mqtt_unknown_device", dry_run=True)

    assert result.scenario_runner_status == ScenarioExecStatus.DRY_RUN
    assert calls == {"baseline": 0, "cleanup": 0}


def test_pi_baseline_accepts_read_only_normal_running_session(tmp_path: Path):
    db_path = tmp_path / "iot_security.db"
    _create_baseline_db(db_path)

    with (
        patch("edge.scenarios.cleanup.settings.database_url", f"sqlite:///{db_path}"),
        patch(
            "edge.scenarios.cleanup._read_service_states",
            return_value={
                "mosquitto": "active",
                "mqtt-subscriber": "active",
                "mqtt-feature-builder": "active",
                "detection-orchestrator": "active",
                "firewall-worker": "active",
                "gateway-metrics": "active",
                "iot-edge-api": "active",
                "packet-capture": "active",
            },
        ),
        patch("edge.scenarios.cleanup._find_conflicting_processes", return_value=[]),
        patch("edge.scenarios.cleanup._list_project_firewall_rules", return_value=[]),
    ):
        assert pi_baseline_check(_context()) == (True, None)


def test_pi_baseline_rejects_non_normal_device(tmp_path: Path):
    db_path = tmp_path / "iot_security.db"
    _create_baseline_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE devices SET status='isolated' WHERE device_id='esp32_02'")
        conn.commit()
    finally:
        conn.close()

    with patch("edge.scenarios.cleanup.settings.database_url", f"sqlite:///{db_path}"):
        ok, reason = pi_baseline_check(_context())

    assert ok is False
    assert reason and "device_not_normal" in reason


def test_pi_baseline_rejects_active_firewall_rule(tmp_path: Path):
    db_path = tmp_path / "iot_security.db"
    _create_baseline_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO firewall_rules(id, device_id, source_ip, status) "
            "VALUES (1, 'esp32_02', '192.168.0.30', 'APPLIED')"
        )
        conn.commit()
    finally:
        conn.close()

    with patch("edge.scenarios.cleanup.settings.database_url", f"sqlite:///{db_path}"):
        ok, reason = pi_baseline_check(_context())

    assert ok is False
    assert reason and "active_firewall_rule" in reason


def test_pi_baseline_rejects_actual_iptables_rule_without_db_row(tmp_path: Path):
    db_path = tmp_path / "iot_security.db"
    _create_baseline_db(db_path)

    with (
        patch("edge.scenarios.cleanup.settings.database_url", f"sqlite:///{db_path}"),
        patch(
            "edge.scenarios.cleanup._list_project_firewall_rules",
            return_value=[
                '-A INPUT -p tcp -s 192.168.0.30/32 --dport 1883 '
                '-m comment --comment "hanium-firewall:91" -j DROP'
            ],
        ),
    ):
        ok, reason = pi_baseline_check(_context())

    assert ok is False
    assert reason and "active_iptables_rule" in reason
    assert "hanium-firewall:91" in reason


def test_pi_baseline_fails_closed_when_firewall_inventory_cannot_be_read(tmp_path: Path):
    db_path = tmp_path / "iot_security.db"
    _create_baseline_db(db_path)

    with (
        patch("edge.scenarios.cleanup.settings.database_url", f"sqlite:///{db_path}"),
        patch(
            "edge.scenarios.cleanup._list_project_firewall_rules",
            return_value=["firewall_inventory_error: sudo denied"],
        ),
    ):
        ok, reason = pi_baseline_check(_context())

    assert ok is False
    assert reason == "firewall_inventory_error: sudo denied"


def test_pi_cleanup_reports_residual_attack_process():
    with patch(
        "edge.scenarios.cleanup._find_conflicting_processes",
        return_value=["1234 python -m attacks.flooding_attack --count 30"],
    ):
        ok, reason = pi_cleanup_hook(_context())

    assert ok is False
    assert reason and "residual_attack_process" in reason


def test_pi_cleanup_does_not_run_state_mutation_commands():
    with (
        patch("edge.scenarios.cleanup._find_conflicting_processes", return_value=[]),
        patch("edge.scenarios.cleanup.subprocess.run") as mock_run,
    ):
        assert pi_cleanup_hook(_context()) == (True, None)

    mock_run.assert_not_called()
