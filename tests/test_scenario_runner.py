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
    InvalidRunIdError,
    MissingRequiredInputError,
    ScenarioExecStatus,
    ScenarioRunner,
    UnsafeExecutionRefusedError,
    _load_hook_from_module_path,
    compare_event_types,
    run_repeated,
)


def _noop_but_real_baseline_check() -> tuple[bool, str | None]:
    """``default_baseline_check``와 identity가 다른, 테스트 전용 더미 훅.

    ``ScenarioRunner``는 ``allow_execute=True`` (non-dry-run)로 생성할 때 ``baseline_check``/``cleanup_hook``이 여전히
    ``default_baseline_check``/``default_cleanup_hook``과 동일 객체이면 실행 자체를 거부한다. 테스트에서 dry-run이 아닌 실행 경로를 검증하려면, 동작은
    no-op이더라도 identity가 다른 별도 함수를 명시적으로 넘겨야 한다.
    """
    return True, None


def _noop_but_real_cleanup_hook() -> tuple[bool, str | None]:
    """``default_cleanup_hook``와 identity가 다른, 테스트 전용 더미 훅."""
    return True, None


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
# run_id 경로 안전성
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_run_id",
    [
        "../escape",
        "../../etc/passwd",
        "/absolute/path",
        "a/b",
        "a\\b",
        "",
        ".",
        "..",
    ],
)
def test_unsafe_run_id_is_rejected(tmp_path: Path, bad_run_id: str):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    with pytest.raises(InvalidRunIdError):
        runner.run("mqtt_unknown_device", run_id=bad_run_id, dry_run=True)


def test_safe_run_id_is_accepted(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, _manifest = runner.run(
        "mqtt_unknown_device", run_id="run-2026_08_04.001", dry_run=True
    )
    assert result.run_id == "run-2026_08_04.001"
    assert (tmp_path / "run-2026_08_04.001").exists()


# ---------------------------------------------------------------------------
# Dry-run은 공식 실행과 완전히 분리된다
# ---------------------------------------------------------------------------
def test_dry_run_is_default_and_isolated_from_official_metrics(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    # dry_run 인자를 생략해도 기본값이 True여야 한다 (실공격 오발동 방지).
    result, manifest = runner.run("mqtt_unknown_device")

    assert result.is_dry_run is True
    assert result.scenario_runner_status == ScenarioExecStatus.DRY_RUN
    assert result.attack_started_at is None
    assert result.capture_eligible is False
    assert result.capture_exclusion_reason == "DRY_RUN"
    assert result.scenario_status == ManifestStatus.NOT_EVALUATED.value
    assert manifest.statuses.scenario_status == ManifestStatus.NOT_EVALUATED
    assert manifest.attack_started_at is None


def test_dry_run_true_explicit_matches_default_behavior(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, _manifest = runner.run("mqtt_unknown_device", dry_run=True)
    assert result.scenario_runner_status == ScenarioExecStatus.DRY_RUN
    assert result.exit_code is None


# ---------------------------------------------------------------------------
# non-dry-run 실행은 allow_execute=True가 없으면 거부된다
# ---------------------------------------------------------------------------
def test_non_dry_run_refused_without_allow_execute(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    with pytest.raises(UnsafeExecutionRefusedError):
        runner.run("mqtt_unknown_device", dry_run=False)


def test_non_dry_run_allowed_with_allow_execute(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, _manifest = runner.run("mqtt_unknown_device", dry_run=False)
    assert result.scenario_runner_status == ScenarioExecStatus.SUCCESS
    assert result.is_dry_run is False


# ---------------------------------------------------------------------------
# FULL_E2E 공식 실행은 session_id를 사전에 요구한다
# ---------------------------------------------------------------------------
def test_full_e2e_non_dry_run_requires_session_id(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        execution_node_registered=True,
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        with pytest.raises(MissingRequiredInputError):
            runner.run(
                "mqtt_abnormal_publish_rate",
                target_device_id="esp32_02",
                session_id=None,
                dry_run=False,
            )


def test_full_e2e_non_dry_run_requires_source_ip_before_attack(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        execution_node_registered=True,
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        with pytest.raises(MissingRequiredInputError, match="source_ip"):
            runner.run(
                "mqtt_abnormal_publish_rate",
                target_device_id="esp32_02",
                session_id="sess-source-required",
                source_ip=None,
                dry_run=False,
            )
    mock_run.assert_not_called()


def test_packet_full_e2e_non_dry_run_requires_target_device_id_before_attack(
    tmp_path: Path,
):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        execution_node_registered=True,
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with (
        patch(
            "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed",
            return_value=True,
        ),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        with pytest.raises(MissingRequiredInputError, match="target_device_id"):
            runner.run(
                "packet_rate_flood",
                target_device_id=None,
                source_ip="192.168.0.10",
                target_host="192.168.0.5",
                session_id="sess-target-required",
                dry_run=False,
            )
    mock_run.assert_not_called()


def test_full_e2e_non_dry_run_succeeds_with_session_id(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, _manifest = runner.run(
            "mqtt_abnormal_publish_rate",
            target_device_id="esp32_02",
            source_ip="192.168.0.10",
            session_id="sess-1",
            dry_run=False,
        )
    assert result.scenario_runner_status == ScenarioExecStatus.SUCCESS


def test_detection_only_non_dry_run_does_not_require_session_id(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, _manifest = runner.run(
            "mqtt_unknown_device", session_id=None, dry_run=False
        )
    assert result.scenario_runner_status == ScenarioExecStatus.SUCCESS


def test_hook_loader_rejects_missing_module_with_input_error():
    with pytest.raises(MissingRequiredInputError, match="로드할 수 없습니다"):
        _load_hook_from_module_path("does.not.exist:baseline")


def test_hook_loader_rejects_non_callable_attribute():
    with pytest.raises(MissingRequiredInputError, match="호출 가능한 함수가 아닙니다"):
        _load_hook_from_module_path(
            "edge.scenarios.run_scenario:DEFAULT_COMMAND_TIMEOUT_SECONDS"
        )


# ---------------------------------------------------------------------------
# Packet Rule Gate / HOLD
# ---------------------------------------------------------------------------
def test_packet_scenario_holds_when_gate_not_confirmed(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=False
    ):
        runner = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path,
            allow_execute=True,
            baseline_check=_noop_but_real_baseline_check,
            cleanup_hook=_noop_but_real_cleanup_hook,
        )
        result, manifest = runner.run(
            "packet_rate_flood", source_ip="192.168.0.10", dry_run=False
        )
    assert result.scenario_runner_status == ScenarioExecStatus.HOLD
    assert result.scenario_status == ManifestStatus.HOLD.value
    assert manifest.statuses.scenario_status == ManifestStatus.HOLD
    assert manifest.failure_reason_code == "HOLD"
    assert result.capture_eligible is False
    assert result.capture_exclusion_reason


def test_mqtt_scenario_runs_normally_even_when_packet_gate_not_confirmed(
    tmp_path: Path,
):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=False
    ):
        runner = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path,
            allow_execute=True,
            baseline_check=_noop_but_real_baseline_check,
            cleanup_hook=_noop_but_real_cleanup_hook,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            result, _manifest = runner.run("mqtt_unknown_device", dry_run=False)
    assert result.scenario_runner_status == ScenarioExecStatus.SUCCESS


def test_packet_scenario_runs_when_gate_confirmed(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path,
            allow_execute=True,
            baseline_check=_noop_but_real_baseline_check,
            cleanup_hook=_noop_but_real_cleanup_hook,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            result, _manifest = runner.run(
                "packet_rate_flood", source_ip="192.168.0.10", dry_run=False
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
            allow_execute=True,
            baseline_check=_noop_but_real_baseline_check,
            cleanup_hook=_noop_but_real_cleanup_hook,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            _result, manifest = runner.run(
                "packet_rate_flood", source_ip="192.168.0.10", dry_run=False
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
            allow_execute=True,
            baseline_check=_noop_but_real_baseline_check,
            cleanup_hook=_noop_but_real_cleanup_hook,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            _result, manifest = runner.run(
                "packet_rate_flood",
                target_device_id="esp32_01",
                source_ip="192.168.0.10",
                session_id="sess-registered-full-e2e",
                dry_run=False,
            )
    assert manifest.evaluation_scope == EvaluationScope.FULL_E2E


# ---------------------------------------------------------------------------
# Mock — 실제 공격 명령 실행 안 함
# ---------------------------------------------------------------------------
def test_mocked_success_exit_code_maps_to_success(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
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
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        result, manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert result.scenario_runner_status == ScenarioExecStatus.SCENARIO_FAILED
    assert result.scenario_status == ManifestStatus.FAILED.value  # exporter 공식 값
    assert result.exit_code == 1
    assert manifest.statuses.scenario_status == ManifestStatus.FAILED


def test_mocked_timeout_maps_to_failed(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["x"], timeout=1.0)
        result, _manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert result.scenario_runner_status == ScenarioExecStatus.SCENARIO_FAILED
    assert result.error_reason == "command_timeout"


def test_mocked_os_error_maps_to_environment_error(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
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
        execution_node="unit-test-node",
        runs_root=tmp_path,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=failing_cleanup,
        allow_execute=True,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, manifest = runner.run("mqtt_unknown_device", dry_run=False)
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
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, manifest = runner.run(
            "mqtt_abnormal_publish_rate",
            target_device_id="esp32_02",
            session_id="sess-contract",
            dry_run=False,
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
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, _manifest = runner.run(
            "mqtt_abnormal_publish_rate",
            target_device_id="esp32_02",
            session_id="sess-extra",
            dry_run=False,
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
        runner = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path,
            allow_execute=True,
            baseline_check=_noop_but_real_baseline_check,
            cleanup_hook=_noop_but_real_cleanup_hook,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            result, _manifest = runner.run(
                "packet_rate_flood", source_ip="192.168.0.10", dry_run=False
            )
    assert result.execution_volume == {
        "unit": "packets",
        "planned": 960,
        "basis": "duration_x_rate",
    }


def test_port_scan_execution_volume_uses_port_range(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path,
            allow_execute=True,
            baseline_check=_noop_but_real_baseline_check,
            cleanup_hook=_noop_but_real_cleanup_hook,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            result, _manifest = runner.run(
                "packet_port_scan", source_ip="192.168.0.10", dry_run=False
            )

    assert result.execution_volume == {
        "unit": "ports",
        "planned": 256,
        "basis": "port_range",
    }


# ---------------------------------------------------------------------------
# 타임스탬프는 항상 초 단위 (마이크로초 없음) — 실제 evaluator와 대조해서
# 확인한 버그(초 경계 불일치로 탐지 매칭 실패) 재발 방지
# ---------------------------------------------------------------------------
def test_all_manifest_timestamps_have_zero_microseconds(tmp_path: Path):
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        _result, manifest = runner.run(
            "mqtt_abnormal_publish_rate",
            target_device_id="esp32_02",
            session_id="sess-ts",
            dry_run=False,
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
        execution_node="unit-test-node",
        runs_root=tmp_path,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=flaky_cleanup,
        allow_execute=True,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        summary = run_repeated(runner, "mqtt_unknown_device", times=5, dry_run=False)

    assert summary.executed_runs == 2
    assert summary.stopped_early is True
    assert summary.results[-1].scenario_runner_status == ScenarioExecStatus.RESET_FAILED


def test_batch_summary_has_failures_true_when_scenario_failed_present(tmp_path: Path):
    """SCENARIO_FAILED가 있으면 조기 중단은 안 하더라도 has_failures는 True여야 한다."""
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        summary = run_repeated(runner, "mqtt_unknown_device", times=2, dry_run=False)

    assert summary.stopped_early is False  # SCENARIO_FAILED는 조기 중단 대상이 아님
    assert summary.has_failures is True


def test_batch_summary_has_failures_false_when_all_dry_run_or_success(tmp_path: Path):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    summary = run_repeated(runner, "mqtt_unknown_device", times=3, dry_run=True)
    assert summary.has_failures is False


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
        runner = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path,
            allow_execute=True,
            baseline_check=_noop_but_real_baseline_check,
            cleanup_hook=_noop_but_real_cleanup_hook,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            result, manifest = runner.run(
                "packet_port_scan",
                target_device_id="esp32_01",
                source_ip="192.168.0.10",
                dry_run=False,
            )
    assert "--device_id" not in result.command
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


# ---------------------------------------------------------------------------
# mqtt_device_id_mismatch 명령 계약
# ---------------------------------------------------------------------------
def test_mqtt_device_id_mismatch_command_uses_correct_flags_not_device_id(
    tmp_path: Path,
):
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, _manifest = runner.run(
        "mqtt_device_id_mismatch",
        target_device_id="esp32_01",
        session_id="sess-1",
        dry_run=True,
    )
    assert "--device_id" not in result.command
    assert "--topic-device-id" in result.command
    assert "--payload-device-id" in result.command
    topic_idx = result.command.index("--topic-device-id")
    assert result.command[topic_idx + 1] == "esp32_01"
    payload_idx = result.command.index("--payload-device-id")
    assert (
        result.command[payload_idx + 1] != "esp32_01"
    )  # mismatch 조건: topic과 달라야 함


def test_mqtt_device_id_mismatch_manifest_target_matches_topic_device_id(
    tmp_path: Path,
):
    """Manifest의 target_device_id(실제 감점 대상)와 command의
    --topic-device-id(실제로 위조 없이 접속한 등록 기기)가 항상 일치해야 한다.
    payload_device_id는 target_device_id와 달라야 mismatch 조건이 성립한다."""
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, manifest = runner.run(
        "mqtt_device_id_mismatch",
        target_device_id="esp32_02",
        session_id="sess-2",
        dry_run=True,
    )
    assert manifest.target_device_id == "esp32_02"
    topic_idx = result.command.index("--topic-device-id")
    assert result.command[topic_idx + 1] == manifest.target_device_id
    payload_idx = result.command.index("--payload-device-id")
    assert result.command[payload_idx + 1] != manifest.target_device_id


def test_mqtt_device_id_mismatch_dry_run_and_real_execution_build_identical_command(
    tmp_path: Path,
):
    """Dry-run과 실제 실행이 동일한 command 조립 경로(_build_args)를 거치는지 확인한다."""
    runner_dry = ScenarioRunner(
        execution_node="unit-test-node", runs_root=tmp_path / "dry"
    )
    result_dry, _ = runner_dry.run(
        "mqtt_device_id_mismatch",
        target_device_id="esp32_01",
        session_id="sess-3",
        dry_run=True,
    )

    runner_real = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path / "real",
        allow_execute=True,
        baseline_check=_noop_but_real_baseline_check,
        cleanup_hook=_noop_but_real_cleanup_hook,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result_real, _ = runner_real.run(
            "mqtt_device_id_mismatch",
            target_device_id="esp32_01",
            session_id="sess-3",
            dry_run=False,
        )

    assert result_dry.command == result_real.command


def test_mqtt_device_id_mismatch_secondary_device_id_unavailable_raises(tmp_path: Path):
    """등록 기기가 1개뿐이면(REGISTERED_DEVICES 설정 이상) 결정적으로 두 번째
    기기를 고를 수 없으므로 명확한 예외를 던져야 한다 (조용히 잘못된 값을
    쓰지 않음)."""
    from edge.scenarios.run_scenario import SecondaryDeviceIdUnavailableError

    with patch("attacks.config.REGISTERED_DEVICES", ["esp32_01"]):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        with pytest.raises(SecondaryDeviceIdUnavailableError):
            runner.run(
                "mqtt_device_id_mismatch",
                target_device_id="esp32_01",
                session_id="sess-4",
                dry_run=True,
            )


# ---------------------------------------------------------------------------
# Packet Source/Target 분리
# ---------------------------------------------------------------------------
def test_packet_rate_flood_uses_target_host_flag(tmp_path: Path):
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, _manifest = runner.run(
            "packet_rate_flood",
            source_ip="192.168.0.10",
            target_host="192.168.0.99",
            dry_run=True,
        )
    assert "--target-host" in result.command
    idx = result.command.index("--target-host")
    assert result.command[idx + 1] == "192.168.0.99"
    assert result.target_host == "192.168.0.99"
    # source_ip는 여전히 별도로 보존되어야 하고, --target-host 값과 혼동되지 않아야 한다
    assert result.source_ip == "192.168.0.10"
    assert result.source_ip != result.target_host


def test_packet_port_scan_uses_target_flag_not_target_host(tmp_path: Path):
    """port_scan_attack.py는 --target-host가 아니라 --target을 받는다
    (packet_rate_flood_attack.py와 스크립트별 플래그 이름이 다름)."""
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, _manifest = runner.run(
            "packet_port_scan",
            source_ip="192.168.0.10",
            target_host="192.168.0.55",
            dry_run=True,
        )
    assert "--target" in result.command
    assert "--target-host" not in result.command
    idx = result.command.index("--target")
    assert result.command[idx + 1] == "192.168.0.55"


def test_target_host_not_added_when_not_provided(tmp_path: Path):
    """target_host를 지정하지 않으면 command에 관련 플래그가 전혀 추가되지
    않고, attack 스크립트 자체 기본값(BROKER_HOST)이 사용된다."""
    with patch(
        "edge.scenarios.run_scenario.is_packet_rule_gate_confirmed", return_value=True
    ):
        runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
        result, _manifest = runner.run(
            "packet_rate_flood", source_ip="192.168.0.10", dry_run=True
        )
    assert "--target-host" not in result.command
    assert result.target_host is None


def test_non_packet_scenario_ignores_target_host(tmp_path: Path):
    """PACKET_ANOMALY가 아닌 시나리오는 target_host를 넘겨도 command에
    반영하지 않는다 (target_host_arg_name 기본값 None)."""
    runner = ScenarioRunner(execution_node="unit-test-node", runs_root=tmp_path)
    result, _manifest = runner.run(
        "mqtt_unknown_device", target_host="should-be-ignored", dry_run=True
    )
    assert "--target-host" not in result.command
    assert "--target" not in result.command
