"""edge/scenarios/run_scenario.py 단위 테스트.

검증 기준 + ``edge/evaluation/export_phase5_results.py``가 강제하는 scenario-result 행 계약을 함께 검증한다.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import subprocess

import pytest

from edge.phase5.contracts import EvaluationScope, ManifestStatus
from edge.scenarios.run_scenario import (
    DuplicateRunIdError,
    MissingRequiredInputError,
    ScenarioExecStatus,
    ScenarioRunner,
    compare_event_types,
    run_repeated,
)


# ---------------------------------------------------------------------------
# 입력 검증
# ---------------------------------------------------------------------------
def test_unknown_scenario_is_rejected(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    with pytest.raises(KeyError):
        runner.run("does_not_exist", dry_run=True)


def test_missing_required_target_device_id_is_rejected(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    with pytest.raises(MissingRequiredInputError):
        runner.run("mqtt_device_id_mismatch", dry_run=True)


def test_missing_required_source_ip_is_rejected(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        with pytest.raises(MissingRequiredInputError):
            runner.run("packet_rate_flood", dry_run=True)


def test_duplicate_run_id_is_rejected(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    runner.run("mqtt_unknown_device", run_id="fixed-id", dry_run=True)
    with pytest.raises(DuplicateRunIdError):
        runner.run("mqtt_unknown_device", run_id="fixed-id", dry_run=True)


# ---------------------------------------------------------------------------
# Packet Rule Gate / HOLD
# ---------------------------------------------------------------------------
def test_packet_scenario_holds_when_gate_not_confirmed(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=False
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, manifest = runner.run(
            "packet_rate_flood", source_ip="192.168.0.10", dry_run=True
        )
    assert result.scenario_runner_status == ScenarioExecStatus.HOLD
    assert result.scenario_status == ManifestStatus.HOLD.value
    assert manifest.statuses.scenario_status == ManifestStatus.HOLD
    assert manifest.failure_reason_code == "HOLD"
    assert result.capture_eligible is False
    assert result.capture_exclusion_reason


def test_mqtt_scenario_runs_normally_even_when_packet_gate_not_confirmed(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=False
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, _manifest = runner.run("mqtt_unknown_device", dry_run=True)
    assert result.scenario_runner_status == ScenarioExecStatus.SUCCESS


def test_packet_scenario_runs_when_gate_confirmed(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, _manifest = runner.run(
            "packet_rate_flood", source_ip="192.168.0.10", dry_run=True
        )
    assert result.scenario_runner_status == ScenarioExecStatus.SUCCESS


# ---------------------------------------------------------------------------
# 미등록 Attack Node → DETECTION_ONLY 강제 하향
# ---------------------------------------------------------------------------
def test_unregistered_node_downgrades_full_e2e_to_detection_only(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(
            execution_node="unit-test-node",
            execution_node_registered=False,
            runs_root=tmp_path,
        )
        _result, manifest = runner.run(
            "packet_rate_flood", source_ip="192.168.0.10", dry_run=True
        )
    assert manifest.evaluation_scope == EvaluationScope.DETECTION_ONLY
    assert manifest.expected_outcome.evaluation_scope == EvaluationScope.DETECTION_ONLY
    assert manifest.expected_outcome.firewall_expected is False
    assert manifest.expected_outcome.block_expected is False


def test_registered_node_keeps_full_e2e(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(
            execution_node="unit-test-node",
            execution_node_registered=True,
            runs_root=tmp_path,
        )
        _result, manifest = runner.run(
            "packet_rate_flood", source_ip="192.168.0.10", dry_run=True
        )
    assert manifest.evaluation_scope == EvaluationScope.FULL_E2E


# ---------------------------------------------------------------------------
# Mock — 실제 공격 명령 실행 안 함
# ---------------------------------------------------------------------------
def test_mocked_success_exit_code_maps_to_success(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert result.scenario_runner_status == ScenarioExecStatus.SUCCESS
    assert result.scenario_status == ManifestStatus.SUCCESS.value
    assert result.exit_code == 0
    assert manifest.statuses.scenario_status == ManifestStatus.SUCCESS
    _args, kwargs = mock_run.call_args
    assert kwargs.get("shell") is False


def test_mocked_non_zero_exit_code_maps_to_failed(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        result, manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert result.scenario_runner_status == ScenarioExecStatus.SCENARIO_FAILED
    assert result.scenario_status == ManifestStatus.FAILED.value  # exporter 공식 값
    assert result.exit_code == 1
    assert manifest.statuses.scenario_status == ManifestStatus.FAILED


def test_mocked_timeout_maps_to_failed(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["x"], timeout=1.0)
        result, _manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert result.scenario_runner_status == ScenarioExecStatus.SCENARIO_FAILED
    assert result.error_reason == "command_timeout"


def test_mocked_os_error_maps_to_environment_error(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("python 실행 파일을 찾을 수 없음")
        result, manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert result.scenario_runner_status == ScenarioExecStatus.ENVIRONMENT_ERROR
    assert result.scenario_status == ManifestStatus.ENVIRONMENT_ERROR.value
    assert manifest.statuses.scenario_status == ManifestStatus.ENVIRONMENT_ERROR
    # attack_started_at은 subprocess.run 호출 직전에 기록되므로, OSError가 나도 "공격을 시도는 했다"는 뜻에서 capture_eligible=True로 남는다. Baseline 실패(공격 시도 자체를 안 함)와는 다른 경로다.
    assert result.capture_eligible is True


def test_cleanup_failure_maps_to_reset_failed(tmp_path: Path):
    def failing_cleanup() -> tuple[bool, str | None]:
        return False, "iptables rule 제거 실패"

    runner = ScenarioRunner(
        execution_node="unit-test-node", runs_root=tmp_path, cleanup_hook=failing_cleanup
    )
    result, manifest = runner.run("mqtt_unknown_device", dry_run=True)
    assert result.scenario_runner_status == ScenarioExecStatus.RESET_FAILED
    assert result.cleanup_ok is False
    # exporter 계약에는 RESET_FAILED 개념이 없어 ENVIRONMENT_ERROR로 보수적으로 매핑
    assert result.scenario_status == ManifestStatus.ENVIRONMENT_ERROR.value
    assert manifest.statuses.scenario_status == ManifestStatus.ENVIRONMENT_ERROR
    # 공격 자체는 실행됐으므로 capture_eligible은 True로 남는다
    assert result.capture_eligible is True


# ---------------------------------------------------------------------------
# scenario-result.jsonl — exporter 공식 계약 필드
# ---------------------------------------------------------------------------
def test_scenario_result_satisfies_exporter_contract_fields(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, manifest = runner.run(
        "mqtt_abnormal_publish_rate", target_device_id="esp32_02", dry_run=True
    )

    row = result.to_dict()
    # 필수 4종
    assert row["run_id"] == manifest.run_id
    assert row["scenario_id"] == manifest.scenario.scenario_id
    assert row["session_id"] == manifest.session_id
    assert ManifestStatus(row["scenario_status"])  # 유효한 ManifestStatus 값이어야 함
    assert isinstance(row["capture_eligible"], bool)
    # block_confirmed를 채우지 않았으면 키 자체가 없어야 한다 (exporter가 None 값을 bool 타입 위반으로 거부하기 때문).
    assert "block_confirmed" not in row
    assert "block_confirmed_at" not in row


def test_scenario_result_contains_own_extra_fields(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, _manifest = runner.run(
        "mqtt_abnormal_publish_rate", target_device_id="esp32_02", dry_run=True
    )

    assert result.target_device_id == "esp32_02"
    assert result.command and result.started_at and result.ended_at
    assert result.expected_event_types == ["ABNORMAL_PUBLISH_RATE"]
    assert result.execution_volume["planned"] == 30
    assert result.exit_code == 0
    assert result.cleanup_attempted is True
    assert result.cleanup_ok is True


def test_packet_execution_volume_uses_duration_x_rate(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, _manifest = runner.run(
            "packet_rate_flood", source_ip="192.168.0.10", dry_run=True
        )
    assert result.execution_volume == {"unit": "packets", "planned": 960, "basis": "duration_x_rate"}


def test_port_scan_execution_volume_uses_port_range(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, _manifest = runner.run(
            "packet_port_scan", source_ip="192.168.0.10", dry_run=True
        )
    assert result.execution_volume == {"unit": "ports", "planned": 1024, "basis": "port_range"}


# ---------------------------------------------------------------------------
# 타임스탬프는 항상 초 단위 (마이크로초 없음) — 실제 evaluator와 대조해서
# 확인한 버그(초 경계 불일치로 탐지 매칭 실패) 재발 방지
# ---------------------------------------------------------------------------
def test_all_manifest_timestamps_have_zero_microseconds(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    _result, manifest = runner.run(
        "mqtt_abnormal_publish_rate", target_device_id="esp32_02", dry_run=True
    )
    for value in (
        manifest.started_at,
        manifest.attack_started_at,
        manifest.observation_deadline_at,
        manifest.ended_at,
    ):
        assert value is not None
        assert value.microsecond == 0


# ---------------------------------------------------------------------------
# 반복 실행
# ---------------------------------------------------------------------------
def test_repeated_runs_use_identical_command_and_get_unique_run_ids(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    summary = run_repeated(runner, "mqtt_unknown_device", times=3, dry_run=True)

    assert summary.executed_runs == 3
    assert summary.success_runs == 3
    commands = {tuple(r.command) for r in summary.results}
    assert len(commands) == 1
    run_ids = {r.run_id for r in summary.results}
    assert len(run_ids) == 3


def test_batch_stops_on_reset_failed(tmp_path: Path):
    call_count = {"n": 0}

    def flaky_cleanup() -> tuple[bool, str | None]:
        call_count["n"] += 1
        if call_count["n"] == 2:
            return False, "iptables rule 제거 실패"
        return True, None

    runner = ScenarioRunner(
        execution_node="unit-test-node", runs_root=tmp_path, cleanup_hook=flaky_cleanup
    )
    summary = run_repeated(runner, "mqtt_unknown_device", times=5, dry_run=True)

    assert summary.executed_runs == 2
    assert summary.stopped_early is True
    assert summary.results[-1].scenario_runner_status == ScenarioExecStatus.RESET_FAILED


# ---------------------------------------------------------------------------
# 예상 Event Type vs 실제 Event 비교
# ---------------------------------------------------------------------------
def test_compare_event_types_reports_matched_missing_unexpected():
    comparison = compare_event_types(
        expected_event_types=["ABNORMAL_PUBLISH_RATE"],
        actual_event_types=["ABNORMAL_PUBLISH_RATE", "AI_ANOMALY"],
    )
    assert comparison == {
        "matched": ["ABNORMAL_PUBLISH_RATE"],
        "missing": [],
        "unexpected": ["AI_ANOMALY"],
    }


# ---------------------------------------------------------------------------
# packet 계열은 --device_id를 받지 않는다
# ---------------------------------------------------------------------------
def test_packet_scenarios_do_not_receive_device_id_arg(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, manifest = runner.run(
            "packet_port_scan",
            target_device_id="esp32_01",
            source_ip="192.168.0.10",
            dry_run=True,
        )
    assert "--device_id" not in result.command
    assert "--target" in result.command
    assert manifest.target_device_id == "esp32_01"
    assert manifest.source_ip == "192.168.0.10"


# ---------------------------------------------------------------------------
# run-manifest.json이 실제 contracts.py 스키마 검증을 통과하는지 (round-trip)
# ---------------------------------------------------------------------------
def test_written_manifest_round_trips_through_real_contracts_schema(tmp_path: Path):
    from edge.phase5.contracts import RunManifest

    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, _manifest = runner.run(
        "mqtt_abnormal_publish_rate", target_device_id="esp32_02", dry_run=True
    )
    text = (tmp_path / result.run_id / "run-manifest.json").read_text(encoding="utf-8")
    reloaded = RunManifest.from_json(text)
    assert reloaded.run_id == result.run_id