"""edge/scenarios/cleanup.py + Baseline 실패 경로 테스트."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from edge.phase5.contracts import ManifestStatus
from edge.scenarios.cleanup import default_baseline_check, default_cleanup_hook
from edge.scenarios.run_scenario import ScenarioExecStatus, ScenarioRunner


def test_default_hooks_are_no_op_success():
    assert default_baseline_check() == (True, None)
    assert default_cleanup_hook() == (True, None)


def test_baseline_failure_marks_environment_error_and_skips_execution(tmp_path: Path):
    calls = {"baseline": 0, "cleanup": 0}

    def baseline() -> tuple[bool, str | None]:
        calls["baseline"] += 1
        return False, "활성 Firewall Rule 존재"

    def cleanup() -> tuple[bool, str | None]:
        calls["cleanup"] += 1
        return True, None

    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        baseline_check=baseline,
        cleanup_hook=cleanup,
        allow_execute=True,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert result.scenario_runner_status == ScenarioExecStatus.ENVIRONMENT_ERROR
    assert calls["baseline"] == 1
    assert calls["cleanup"] == 0  # Baseline 실패 시 공격을 실행하지 않으므로 Cleanup도 호출 안 함
    assert result.cleanup_attempted is False
    assert result.capture_eligible is False
    assert manifest.statuses.scenario_status == ManifestStatus.ENVIRONMENT_ERROR
    assert "baseline_check_failed" in (manifest.failure_reason or "")


def test_baseline_exception_is_recorded_and_attack_is_not_started(tmp_path: Path):
    def baseline() -> tuple[bool, str | None]:
        raise RuntimeError("baseline hook crashed")

    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        baseline_check=baseline,
        cleanup_hook=lambda: (True, None),
        allow_execute=True,
    )
    with patch("subprocess.run") as mock_run:
        result, manifest = runner.run("mqtt_unknown_device", dry_run=False)

    mock_run.assert_not_called()
    assert result.scenario_runner_status == ScenarioExecStatus.ENVIRONMENT_ERROR
    assert result.cleanup_attempted is False
    assert result.capture_eligible is False
    assert result.error_reason == "baseline_check_exception: baseline hook crashed"
    assert manifest.statuses.scenario_status == ManifestStatus.ENVIRONMENT_ERROR
    run_dir = tmp_path / result.run_id
    assert (run_dir / "scenario-result.jsonl").is_file()
    assert (run_dir / "run-manifest.json").is_file()


def test_cleanup_is_attempted_after_execution(tmp_path: Path):
    calls = {"cleanup": 0}

    def baseline() -> tuple[bool, str | None]:
        return True, None

    def cleanup() -> tuple[bool, str | None]:
        calls["cleanup"] += 1
        return True, None

    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        baseline_check=baseline,
        cleanup_hook=cleanup,
        allow_execute=True,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, _manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert calls["cleanup"] == 1
    assert result.cleanup_attempted is True
    assert result.cleanup_ok is True


def test_cleanup_exception_is_recorded_as_reset_failed_after_execution(tmp_path: Path):
    def baseline() -> tuple[bool, str | None]:
        return True, None

    def cleanup() -> tuple[bool, str | None]:
        raise RuntimeError("cleanup hook crashed")

    runner = ScenarioRunner(
        execution_node="unit-test-node",
        runs_root=tmp_path,
        baseline_check=baseline,
        cleanup_hook=cleanup,
        allow_execute=True,
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        result, manifest = runner.run("mqtt_unknown_device", dry_run=False)

    assert result.scenario_runner_status == ScenarioExecStatus.RESET_FAILED
    assert result.cleanup_attempted is True
    assert result.cleanup_ok is False
    assert result.cleanup_failure_reason == "cleanup_hook_exception: cleanup hook crashed"
    assert manifest.statuses.scenario_status == ManifestStatus.ENVIRONMENT_ERROR
    run_dir = tmp_path / result.run_id
    assert (run_dir / "scenario-result.jsonl").is_file()
    assert (run_dir / "run-manifest.json").is_file()


def test_three_failure_modes_are_distinguishable_in_scenario_runner_status(tmp_path: Path):
    def real_baseline() -> tuple[bool, str | None]:
        return True, None

    def real_cleanup() -> tuple[bool, str | None]:
        return True, None

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        runner_ok = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path / "a",
            allow_execute=True,
            baseline_check=real_baseline,
            cleanup_hook=real_cleanup,
        )
        result_ok, _ = runner_ok.run("mqtt_unknown_device", dry_run=False)
        assert result_ok.scenario_runner_status == ScenarioExecStatus.SUCCESS

        runner_reset_failed = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path / "b",
            baseline_check=real_baseline,
            cleanup_hook=lambda: (False, "정리 실패"),
            allow_execute=True,
        )
        result_reset_failed, _ = runner_reset_failed.run("mqtt_unknown_device", dry_run=False)
        assert result_reset_failed.scenario_runner_status == ScenarioExecStatus.RESET_FAILED

        runner_env_error = ScenarioRunner(
            execution_node="unit-test-node",
            runs_root=tmp_path / "c",
            baseline_check=lambda: (False, "환경 오류"),
            cleanup_hook=real_cleanup,
            allow_execute=True,
        )
        result_env_error, _ = runner_env_error.run("mqtt_unknown_device", dry_run=False)
        assert result_env_error.scenario_runner_status == ScenarioExecStatus.ENVIRONMENT_ERROR

    statuses = {
        result_ok.scenario_runner_status,
        result_reset_failed.scenario_runner_status,
        result_env_error.scenario_runner_status,
    }
    assert len(statuses) == 3

    # 하지만 공식 scenario_status는 RESET_FAILED와 ENVIRONMENT_ERROR가 동일하게
    # 수렴한다 (exporter의 ManifestStatus에는 RESET_FAILED가 없음).
    assert result_reset_failed.scenario_status == result_env_error.scenario_status
