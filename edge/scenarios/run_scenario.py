"""Scenario Runner 실행 엔진 + CLI.

P5-SW-01 담당 작업 구현. ``edge/phase5/contracts.py``의 ``RunManifest``로 ``run-manifest.json``을 쓰고,
``edge/evaluation/export_phase5_results.py``가 실제로 요구하는 계약에 맞춰 ``scenario-result.jsonl``을 쓴다.

.. important::
   ``export_phase5_results._scenario_result_common_contract_issue`` /
   ``_scenario_result_manifest_contract_issue`` 가 강제하는 ``scenario-result`` 행 계약 (``docs/phase5-evaluation-contract.md`` 참고):

   - ``run_id``, ``scenario_id``: 비어있지 않은 문자열 (Manifest와 동일)
   - ``session_id``: Manifest.session_id가 있으면 동일한 값(비어있지 않은 문자열)이어야 하고, Manifest.session_id가 None이면 null 또는 생략해야 함
   - ``scenario_status``: **반드시 ``ManifestStatus`` 값** 중 하나 (SUCCESS/FAILED/HOLD/NOT_APPLICABLE/ENVIRONMENT_ERROR/CAPTURE_INELIGIBLE/NOT_EVALUATED)
     SCENARIO_FAILED/RESET_FAILED 같은 임의 문자열은 이 필드에 그대로 쓰면 안 된다.
   - ``capture_eligible``: bool 필수. False면 ``capture_exclusion_reason`` 필수
   - ``block_confirmed``/``block_confirmed_at``: 있을 때만 서로 짝을 맞춰 검증됨

   파일 형식도 JSON이 아니라 **JSONL**이다 (``_load_jsonl``로 라인 단위 파싱).

   ``capture_eligible`` 판정 기준(Packet Capture Timing/Window 등)은 Scenario Runner가 실행 시점에 알 수 없는 정보라,
   여기서는 "공격 Process가 실제로 시작됐는가"만으로 보수적으로 True/False를 정한다. 실제 Packet Capture 적격성을 보고 이 값을 재작성해야 하는지 PR에서 확인 필요.**

.. important:: Dry-run은 공식 실행이 아니다.
   ``dry_run=True``인 실행은 실제로 공격 Process를 실행하지 않으므로 다음처럼 완전히 분리해서 기록한다.

   - ``attack_started_at=None``
   - ``capture_eligible=False`` / ``capture_exclusion_reason="DRY_RUN"``
   - ``scenario_status=NOT_EVALUATED`` (exporter의 공식 TP/FP/TN/FN 집계에서 자동 제외됨)
   - ``scenario_runner_status="DRY_RUN"`` (SUCCESS와 구분되는 별도 상태)

   Dry-run 산출물을 evaluation exporter에 그대로 넣어 공식 지표로 집계하지 않아야 한다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from edge.phase5.contracts import (
    RUN_MANIFEST_SCHEMA_VERSION,
    EvaluationScope,
    ExecutionNode,
    ExpectedOutcome,
    ManifestStatus,
    RunManifest,
    RunManifestValidationError,
    RunStageStatuses,
    ScenarioReference,
    run_manifest_sha256,
)
from edge.scenarios.cleanup import (
    BaselineCheck,
    CleanupHook,
    default_baseline_check,
    default_cleanup_hook,
)
from edge.scenarios.packet_scenarios import is_packet_rule_gate_confirmed
from edge.scenarios.scenario_registry import (
    SCENARIOS,
    ScenarioDefinition,
    get_scenario,
)

DEFAULT_RUNS_ROOT = Path("data/phase5/runs")
DEFAULT_COMMAND_TIMEOUT_SECONDS = 120.0
DEFAULT_OBSERVATION_BUFFER_SECONDS = 30.0

AWAITING_SESSION_CORRELATION = "AWAITING_SESSION_CORRELATION"
DRY_RUN_EXCLUSION_REASON = "DRY_RUN"

# run_id는 파일시스템 경로(``runs_root / run_id``)로 그대로 사용되므로, 경로 순회
# (``../``)나 절대경로/구분자 주입을 막기 위해 허용 문자를 제한한다.
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ScenarioExecStatus(str, Enum):
    SUCCESS = "SUCCESS"
    SCENARIO_FAILED = "SCENARIO_FAILED"
    RESET_FAILED = "RESET_FAILED"
    ENVIRONMENT_ERROR = "ENVIRONMENT_ERROR"
    HOLD = "HOLD"
    DRY_RUN = "DRY_RUN"


class DuplicateRunIdError(ValueError):
    """이미 사용된 run_id를 다시 사용하려는 경우."""


class MissingRequiredInputError(ValueError):
    """필수 인자 누락."""


class InvalidRunIdError(ValueError):
    """허용되지 않는 문자·경로 형태의 run_id."""


class UnsafeExecutionRefusedError(RuntimeError):
    """non-dry-run 실행에 필요한 안전 조건이 갖춰지지 않은 경우."""


def _validate_run_id(run_id: str) -> str:
    """run_id를 ``runs_root / run_id`` 경로에 안전하게 쓸 수 있는지 검증한다.

    허용 문자 패턴으로 제한하고, 절대경로/``..``/구분자를 거부하며, 최종적으로
    ``Path.resolve()`` 결과가 ``runs_root`` 하위인지까지 :func:`ScenarioRunner.run`에서 다시 확인한다.
    """
    if not _RUN_ID_PATTERN.match(run_id):
        raise InvalidRunIdError(
            f"run_id={run_id!r}는 허용되지 않는 형식입니다. 영문/숫자/'-'/'_'/'.'만 "
            "허용하며 경로 구분자·절대경로·'..'는 사용할 수 없습니다."
        )
    if run_id in {".", ".."}:
        raise InvalidRunIdError(f"run_id={run_id!r}는 사용할 수 없습니다.")
    return run_id


class SecondaryDeviceIdUnavailableError(ValueError):
    """target_device_id와 다른 두 번째 등록 기기를 REGISTERED_DEVICES에서
    찾을 수 없는 경우 (예: 등록 기기가 1개뿐이거나 설정이 비어있음)."""


def _pick_secondary_device_id(target_device_id: str) -> str:
    """``target_device_id``와 다른 등록 기기를 결정적으로 하나 고른다.

    ``mqtt_device_id_mismatch``처럼 topic/payload에 서로 다른 두 등록 기기가
    필요한 시나리오에서 사용한다. ``REGISTERED_DEVICES``를 정렬한 뒤
    ``target_device_id``와 다른 첫 값을 고정 순서로 반환해, 반복 실행해도
    항상 같은 두 번째 기기가 선택되도록 한다 (무작위 선택 금지).
    """
    from attacks.config import REGISTERED_DEVICES

    candidates = sorted(d for d in REGISTERED_DEVICES if d != target_device_id)
    if not candidates:
        raise SecondaryDeviceIdUnavailableError(
            f"target_device_id={target_device_id!r}와 다른 등록 기기를 "
            f"REGISTERED_DEVICES={REGISTERED_DEVICES!r}에서 찾을 수 없습니다. "
            "등록 기기가 최소 2개 이상 필요합니다."
        )
    return candidates[0]


def compare_event_types(
    expected_event_types: list[str] | tuple[str, ...],
    actual_event_types: list[str] | tuple[str, ...],
) -> dict[str, list[str]]:
    """예상 Event Type과 실제 Detection Event Type을 비교한다 (순수 함수)."""
    expected = set(expected_event_types)
    actual = set(actual_event_types)
    return {
        "matched": sorted(expected & actual),
        "missing": sorted(expected - actual),
        "unexpected": sorted(actual - expected),
    }


def _compute_execution_volume(
    defn: ScenarioDefinition, args: dict[str, str]
) -> dict[str, Any]:
    try:
        if defn.volume_strategy == "count_arg":
            planned = int(args.get(defn.volume_arg_name, 0))
        elif defn.volume_strategy == "duration_x_rate":
            duration = float(args.get("duration", defn.duration_seconds))
            rate = float(args.get("rate_pps", 0))
            planned = int(duration * rate)
        elif defn.volume_strategy == "port_range":
            start = int(args.get("start_port", 0))
            end = int(args.get("end_port", 0))
            planned = max(end - start + 1, 0)
        else:
            planned = 0
    except (TypeError, ValueError):
        planned = 0
    return {"unit": defn.volume_unit, "planned": planned, "basis": defn.volume_strategy}


def _utc_now() -> datetime:
    """UTC 현재 시각을 '초 단위'로 내림 처리해 반환한다.

    ``detection_events.detected_at``(및 evaluator의 ``parse_db_utc``)은 초
    단위 정밀도만 허용한다. Scenario Runner가 마이크로초까지 포함된 ``attack_started_at``을 쓰면, 같은 초에 기록된(초 단위로 truncate된)
    실제 Detection Event가 "공격 시작 이전"으로 오판되어 탐지 매칭이 실패하는 경계 문제가 생기므로 항상 초 단위로 맞춘다.
    """
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _exec_status_to_manifest_status(status: str) -> ManifestStatus:
    return {
        ScenarioExecStatus.SUCCESS: ManifestStatus.SUCCESS,
        ScenarioExecStatus.SCENARIO_FAILED: ManifestStatus.FAILED,
        ScenarioExecStatus.RESET_FAILED: ManifestStatus.ENVIRONMENT_ERROR,
        ScenarioExecStatus.ENVIRONMENT_ERROR: ManifestStatus.ENVIRONMENT_ERROR,
        ScenarioExecStatus.HOLD: ManifestStatus.HOLD,
        # Dry-run은 공식 평가 대상이 아니므로 NOT_EVALUATED로 수렴한다 (피드백 #1).
        ScenarioExecStatus.DRY_RUN: ManifestStatus.NOT_EVALUATED,
    }[status]


# ---------------------------------------------------------------------------
# scenario-result.jsonl 행 — export_phase5_results.py가 강제하는 계약을 따른다
# ---------------------------------------------------------------------------
@dataclass
class ScenarioResultRow:
    # --- exporter 공식 계약 (docs/phase5-evaluation-contract.md) ---
    run_id: str
    scenario_id: str
    session_id: str | None
    scenario_status: str  # ManifestStatus.value 중 하나 (필수)
    capture_eligible: bool  # 필수
    capture_exclusion_reason: str | None  # capture_eligible=False면 필수
    block_confirmed: bool | None = None
    block_confirmed_at: str | None = None

    scenario_version: str = ""
    target_device_id: str | None = None
    source_ip: str | None = None
    target_host: str | None = None
    execution_node: str = ""
    command: list[str] = field(default_factory=list)
    started_at: str | None = None
    attack_started_at: str | None = None
    ended_at: str | None = None
    expected_event_types: list[str] = field(default_factory=list)
    execution_volume: dict[str, Any] = field(default_factory=dict)
    exit_code: int | None = None
    scenario_runner_status: str = ""  # ScenarioExecStatus 값 (SCENARIO_FAILED/RESET_FAILED/DRY_RUN 등 세부 구분)
    cleanup_attempted: bool = False
    cleanup_ok: bool = True
    cleanup_failure_reason: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    error_reason: str | None = None
    is_dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if payload.get("block_confirmed") is None:
            payload.pop("block_confirmed", None)
        if payload.get("block_confirmed_at") is None:
            payload.pop("block_confirmed_at", None)
        return payload


def _write_scenario_result_jsonl(run_dir: Path, row: ScenarioResultRow) -> None:
    """단일 Run은 단일 행(JSONL 1줄)만 남긴다 — exporter는 run_id+scenario_id로 정확히 1개 행을 찾는다."""
    path = run_dir / "scenario-result.jsonl"
    line = json.dumps(row.to_dict(), ensure_ascii=False, sort_keys=True)
    path.write_text(line + "\n", encoding="utf-8")
    digest = hashlib.sha256((line + "\n").encode("utf-8")).hexdigest()
    path.with_suffix(path.suffix + ".sha256").write_text(digest + "\n", encoding="utf-8")


class ScenarioRunner:
    """단일 시나리오를 1회 실행하고 run_id 기준 증적을 남긴다."""

    def __init__(
        self,
        *,
        execution_node: str,
        execution_node_registered: bool = False,
        runs_root: Path = DEFAULT_RUNS_ROOT,
        baseline_check: BaselineCheck = default_baseline_check,
        cleanup_hook: CleanupHook = default_cleanup_hook,
        command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
        observation_buffer_seconds: float = DEFAULT_OBSERVATION_BUFFER_SECONDS,
        python_executable: str = sys.executable,
        allow_execute: bool = False,
    ) -> None:
        self.execution_node = execution_node
        self.execution_node_registered = execution_node_registered
        self.runs_root = Path(runs_root)
        self.baseline_check = baseline_check
        self.cleanup_hook = cleanup_hook
        self.command_timeout_seconds = command_timeout_seconds
        self.observation_buffer_seconds = observation_buffer_seconds
        self.python_executable = python_executable
        # non-dry-run(``dry_run=False``) 실행을 허용할지 여부. 기본값 False —
        # 실제 DB·iptables·Device·MQTT 상태를 확인하는 훅이 연결되기 전까지
        # 실공격 실행을 거부한다. Pi에서 실제 훅을 연결한 뒤 CLI의 ``--execute`` 플래그로만 True가 된다.
        self.allow_execute = allow_execute

    def run(
        self,
        scenario_id: str,
        *,
        run_id: str | None = None,
        target_device_id: str | None = None,
        source_ip: str | None = None,
        target_host: str | None = None,
        session_id: str | None = None,
        extra_args: dict[str, str] | None = None,
        dry_run: bool = True,
    ) -> tuple[ScenarioResultRow, RunManifest]:
        """단일 시나리오를 1회 실행한다.

        target_host: PACKET_ANOMALY 계열에서 공격 패킷을 실제로 받는 목적지
        (Raspberry Pi/Broker) IP. source_ip(Attack Node 자신의 IP, Manifest
        관찰용)와 의미가 다르므로 별도 인자로 분리했다.
        RunManifest 스키마에는 없고 scenario-result.jsonl과 실행 command에만
        기록된다. 지정하지 않으면 attack 스크립트 자체 기본값(BROKER_HOST)이
        사용된다.
        """
        defn = get_scenario(scenario_id)

        if defn.requires_target_device_id and not target_device_id:
            raise MissingRequiredInputError(
                f"{scenario_id}는 target_device_id가 필요합니다."
            )
        if defn.requires_target_source_ip and not source_ip:
            raise MissingRequiredInputError(f"{scenario_id}는 source_ip가 필요합니다.")

        if not dry_run and not self.allow_execute:
            raise UnsafeExecutionRefusedError(
                f"{scenario_id}의 실공격 실행이 거부되었습니다: 이 ScenarioRunner는 "
                "allow_execute=False(기본값)입니다. 실제 DB·iptables·Device·MQTT "
                "상태를 확인하는 Baseline/Cleanup 훅이 연결된 뒤에만 "
                "allow_execute=True로 생성하세요 (CLI에서는 --execute)."
            )

        if not dry_run and (
            self.baseline_check is default_baseline_check
            or self.cleanup_hook is default_cleanup_hook
        ):
            raise UnsafeExecutionRefusedError(
                f"{scenario_id}의 실공격 실행이 거부되었습니다: baseline_check/"
                "cleanup_hook이 아직 기본 no-op 구현(default_baseline_check/"
                "default_cleanup_hook)입니다. Pi에서 실제 DB·iptables·Device·"
                "MQTT 상태를 확인·복구하는 훅으로 교체한 뒤 ScenarioRunner에 "
                "전달하세요 (edge/scenarios/cleanup.py의 예시 뼈대 참고)."
            )

        run_id = run_id if run_id is not None else str(uuid.uuid4())
        run_id = _validate_run_id(run_id)
        run_dir = (self.runs_root / run_id).resolve()
        runs_root_resolved = self.runs_root.resolve()
        if runs_root_resolved not in run_dir.parents and run_dir != runs_root_resolved:
            raise InvalidRunIdError(
                f"run_id={run_id!r}가 runs_root({runs_root_resolved}) 밖의 경로로 "
                f"해석되었습니다: {run_dir}"
            )
        if run_dir.exists():
            raise DuplicateRunIdError(f"run_id 중복: {run_id!r} ({run_dir})")

        if dry_run:
            return self._finalize(
                defn=defn,
                run_id=run_id,
                session_id=session_id,
                target_device_id=target_device_id,
                source_ip=source_ip,
                run_dir=run_dir,
                exec_status=ScenarioExecStatus.DRY_RUN,
                command=self._build_command(
                    defn,
                    self._build_args(defn, target_device_id=target_device_id, target_host=target_host, extra_args=extra_args),
                ),
                exit_code=None,
                started_at=_utc_now(),
                attack_started_at=None,
                ended_at=None,
                stdout_path=None,
                stderr_path=None,
                error_reason=None,
                cleanup_attempted=False,
                cleanup_ok=True,
                cleanup_failure_reason=None,
                is_dry_run=True,
                target_host=target_host,
            )

        evaluation_scope = EvaluationScope(defn.evaluation_scope)
        if not self.execution_node_registered and evaluation_scope == EvaluationScope.FULL_E2E:
            evaluation_scope = EvaluationScope.DETECTION_ONLY

        if evaluation_scope == EvaluationScope.FULL_E2E:
            required_identity = {
                "session_id": session_id,
                "target_device_id": target_device_id,
                "source_ip": source_ip,
            }
            missing_fields = [
                field_name
                for field_name, value in required_identity.items()
                if value is None
            ]
            if missing_fields:
                raise MissingRequiredInputError(
                    f"{scenario_id}는 FULL_E2E 공식 실행이므로 {', '.join(missing_fields)}를 "
                    "실행 전에 모두 확정해야 합니다 (Exporter는 Manifest를 사후에 "
                    "재작성하지 않습니다). 상관관계가 아직 없다면 별도 Session "
                    "상관분석 단계를 먼저 수행하거나 dry_run=True로 Local 검증만 "
                    "수행하세요."
                )

        if defn.requires_packet_rule_gate and not is_packet_rule_gate_confirmed():
            return self._finalize(
                defn=defn,
                run_id=run_id,
                session_id=session_id,
                target_device_id=target_device_id,
                source_ip=source_ip,
                run_dir=run_dir,
                exec_status=ScenarioExecStatus.HOLD,
                command=self._build_command(
                    defn,
                    self._build_args(defn, target_device_id=target_device_id, target_host=target_host, extra_args=extra_args),
                ),
                exit_code=None,
                started_at=_utc_now(),
                attack_started_at=None,
                ended_at=None,
                stdout_path=None,
                stderr_path=None,
                error_reason=(
                    "packet_rule_gate_not_confirmed: Phase 4 Packet Rule "
                    "Orchestrator 등록·Local Smoke Test 결과가 아직 확인되지 "
                    "않았습니다."
                ),
                cleanup_attempted=False,
                cleanup_ok=True,
                cleanup_failure_reason=None,
                evaluation_scope=evaluation_scope,
                target_host=target_host,
            )

        args = self._build_args(
            defn, target_device_id=target_device_id, target_host=target_host, extra_args=extra_args
        )

        command = self._build_command(defn, args)
        started_at = _utc_now()

        try:
            baseline_ok, baseline_reason = self.baseline_check()
        except Exception as exc:
            baseline_ok = False
            baseline_reason = f"baseline_check_exception: {exc}"
        if not baseline_ok:
            baseline_error_reason = (
                baseline_reason
                if baseline_reason and baseline_reason.startswith("baseline_check_exception:")
                else f"baseline_check_failed: {baseline_reason}"
            )
            return self._finalize(
                defn=defn,
                run_id=run_id,
                session_id=session_id,
                target_device_id=target_device_id,
                source_ip=source_ip,
                run_dir=run_dir,
                exec_status=ScenarioExecStatus.ENVIRONMENT_ERROR,
                command=command,
                exit_code=None,
                started_at=started_at,
                attack_started_at=None,
                ended_at=None,
                stdout_path=None,
                stderr_path=None,
                error_reason=baseline_error_reason,
                cleanup_attempted=False,
                cleanup_ok=True,
                cleanup_failure_reason=None,
                evaluation_scope=evaluation_scope,
                target_host=target_host,
            )

        attack_started_at = _utc_now()
        exit_code: int | None = None
        stdout_path: Path | None = None
        stderr_path: Path | None = None
        error_reason: str | None = None
        exec_status = ScenarioExecStatus.SUCCESS

        logs_dir = run_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = logs_dir / f"{defn.scenario_id}__{run_id}__stdout.log"
        stderr_path = logs_dir / f"{defn.scenario_id}__{run_id}__stderr.log"
        try:
            with stdout_path.open("w", encoding="utf-8") as out_fh, stderr_path.open(
                "w", encoding="utf-8"
            ) as err_fh:
                completed = subprocess.run(
                    command,
                    stdout=out_fh,
                    stderr=err_fh,
                    timeout=self.command_timeout_seconds,
                    check=False,
                    shell=False,  # shell=True 없이 실행
                )
            exit_code = completed.returncode
            if exit_code != 0:
                exec_status = ScenarioExecStatus.SCENARIO_FAILED
                error_reason = f"non_zero_exit_code={exit_code}"
        except subprocess.TimeoutExpired:
            exec_status = ScenarioExecStatus.SCENARIO_FAILED
            error_reason = "command_timeout"
        except OSError as exc:
            return self._finalize(
                defn=defn,
                run_id=run_id,
                session_id=session_id,
                target_device_id=target_device_id,
                source_ip=source_ip,
                run_dir=run_dir,
                exec_status=ScenarioExecStatus.ENVIRONMENT_ERROR,
                command=command,
                exit_code=None,
                started_at=started_at,
                attack_started_at=attack_started_at,
                ended_at=_utc_now(),
                stdout_path=None,
                stderr_path=None,
                error_reason=f"environment_error: {exc}",
                cleanup_attempted=False,
                cleanup_ok=True,
                cleanup_failure_reason=None,
                evaluation_scope=evaluation_scope,
                target_host=target_host,
            )

        ended_at = _utc_now()
        try:
            cleanup_ok, cleanup_reason = self.cleanup_hook()
        except Exception as exc:
            cleanup_ok = False
            cleanup_reason = f"cleanup_hook_exception: {exc}"
        if not cleanup_ok:
            exec_status = ScenarioExecStatus.RESET_FAILED

        execution_volume = _compute_execution_volume(defn, args)

        return self._finalize(
            defn=defn,
            run_id=run_id,
            session_id=session_id,
            target_device_id=target_device_id,
            source_ip=source_ip,
            run_dir=run_dir,
            exec_status=exec_status,
            command=command,
            exit_code=exit_code,
            started_at=started_at,
            attack_started_at=attack_started_at,
            ended_at=ended_at,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            error_reason=error_reason,
            cleanup_attempted=True,
            cleanup_ok=cleanup_ok,
            cleanup_failure_reason=cleanup_reason,
            execution_volume=execution_volume,
            evaluation_scope=evaluation_scope,
            target_host=target_host,
        )

    # ------------------------------------------------------------------
    def _finalize(
        self,
        *,
        defn: ScenarioDefinition,
        run_id: str,
        session_id: str | None,
        target_device_id: str | None,
        source_ip: str | None,
        run_dir: Path,
        exec_status: str,
        command: list[str],
        exit_code: int | None,
        started_at: datetime,
        attack_started_at: datetime | None,
        ended_at: datetime | None,
        stdout_path: Path | None,
        stderr_path: Path | None,
        error_reason: str | None,
        cleanup_attempted: bool,
        cleanup_ok: bool,
        cleanup_failure_reason: str | None,
        execution_volume: dict[str, Any] | None = None,
        evaluation_scope: EvaluationScope | None = None,
        is_dry_run: bool = False,
        target_host: str | None = None,
    ) -> tuple[ScenarioResultRow, RunManifest]:
        execution_volume = execution_volume or _compute_execution_volume(
            defn, dict(defn.default_args)
        )
        evaluation_scope = evaluation_scope or EvaluationScope(defn.evaluation_scope)
        manifest_status = _exec_status_to_manifest_status(exec_status)

        # capture_eligible: 공격 Process가 실제로 시작됐는지만으로 보수적으로 판정한다.
        # Dry-run은 애초에 공격을 실행하지 않으므로 항상 False로 강제한다.
        capture_eligible = (not is_dry_run) and attack_started_at is not None
        if is_dry_run:
            capture_exclusion_reason = DRY_RUN_EXCLUSION_REASON
        else:
            capture_exclusion_reason = (
                None if capture_eligible else (error_reason or exec_status)
            )

        row = ScenarioResultRow(
            run_id=run_id,
            scenario_id=defn.scenario_id,
            session_id=session_id,
            scenario_status=manifest_status.value,
            capture_eligible=capture_eligible,
            capture_exclusion_reason=capture_exclusion_reason,
            scenario_version=defn.scenario_version,
            target_device_id=target_device_id,
            source_ip=source_ip,
            target_host=target_host,
            execution_node=self.execution_node,
            command=command,
            started_at=_iso(started_at),
            attack_started_at=_iso(attack_started_at),
            ended_at=_iso(ended_at),
            expected_event_types=list(defn.expected_event_types),
            execution_volume=execution_volume,
            exit_code=exit_code,
            scenario_runner_status=exec_status,
            cleanup_attempted=cleanup_attempted,
            cleanup_ok=cleanup_ok,
            cleanup_failure_reason=cleanup_failure_reason,
            stdout_path=str(stdout_path) if stdout_path else None,
            stderr_path=str(stderr_path) if stderr_path else None,
            error_reason=error_reason,
            is_dry_run=is_dry_run,
        )

        manifest = self._build_run_manifest(
            defn=defn,
            run_id=run_id,
            session_id=session_id,
            target_device_id=target_device_id,
            source_ip=source_ip,
            started_at=started_at,
            attack_started_at=attack_started_at,
            ended_at=ended_at,
            evaluation_scope=evaluation_scope,
            manifest_status=manifest_status,
            exec_status=exec_status,
            error_reason=error_reason,
        )

        run_dir.mkdir(parents=True, exist_ok=True)
        _write_scenario_result_jsonl(run_dir, row)
        self._write_run_manifest(run_dir, manifest)
        return row, manifest

    def _build_run_manifest(
        self,
        *,
        defn: ScenarioDefinition,
        run_id: str,
        session_id: str | None,
        target_device_id: str | None,
        source_ip: str | None,
        started_at: datetime,
        attack_started_at: datetime | None,
        ended_at: datetime | None,
        evaluation_scope: EvaluationScope,
        manifest_status: ManifestStatus,
        exec_status: str,
        error_reason: str | None,
    ) -> RunManifest:
        observation_deadline_at = (
            ended_at + timedelta(seconds=self.observation_buffer_seconds)
            if ended_at is not None
            else started_at
        )

        downgraded = evaluation_scope != EvaluationScope(defn.evaluation_scope)
        expected_outcome = ExpectedOutcome(
            expected_event_types=tuple(defn.expected_event_types),
            detection_expected=defn.detection_expected,
            trust_score_change_expected=defn.trust_change_expected and not downgraded,
            firewall_expected=defn.firewall_rule_expected and not downgraded,
            block_expected=defn.block_expected and not downgraded,
            evaluation_scope=evaluation_scope,
        )

        identity_missing = (
            session_id is None or target_device_id is None or source_ip is None
        )
        if exec_status == ScenarioExecStatus.DRY_RUN:
            failure_stage = "dry_run"
            failure_reason_code = DRY_RUN_EXCLUSION_REASON
            failure_reason = (
                "Dry-run 실행이므로 공식 평가 대상에서 제외됩니다. 실제 공격은 "
                "실행되지 않았습니다."
            )
        elif exec_status != ScenarioExecStatus.SUCCESS:
            failure_stage = "scenario_execution"
            failure_reason_code = exec_status
            failure_reason = error_reason or exec_status
        elif identity_missing:
            failure_stage = "session_correlation"
            failure_reason_code = AWAITING_SESSION_CORRELATION
            failure_reason = (
                "Scenario Runner 실행은 완료되었으나 session_id/target_device_id/"
                "source_ip 중 일부가 아직 확정되지 않았습니다. FULL_E2E 공식 실행은 "
                "이 상태로 진입할 수 없으며(사전 확정 필요), DETECTION_ONLY로 하향된 "
                "경우에만 이 상태가 남을 수 있습니다."
            )
        else:
            failure_stage = None
            failure_reason_code = None
            failure_reason = None

        statuses = RunStageStatuses(
            scenario_status=manifest_status,
            detection_status=ManifestStatus.NOT_EVALUATED,
            trust_status=ManifestStatus.NOT_EVALUATED,
            firewall_status=ManifestStatus.NOT_EVALUATED,
            block_status=ManifestStatus.NOT_EVALUATED,
            data_status=ManifestStatus.NOT_EVALUATED,
            final_status=(
                manifest_status
                if manifest_status != ManifestStatus.SUCCESS
                else ManifestStatus.NOT_EVALUATED
            ),
        )

        return RunManifest(
            run_manifest_schema_version=RUN_MANIFEST_SCHEMA_VERSION,
            run_id=run_id,
            session_id=session_id,
            scenario=ScenarioReference(
                scenario_id=defn.scenario_id,
                scenario_version=defn.scenario_version,
            ),
            target_device_id=target_device_id,
            source_ip=source_ip,
            execution_node=ExecutionNode(
                node_id=self.execution_node,
                registered=self.execution_node_registered,
            ),
            evaluation_scope=evaluation_scope,
            is_active=False,
            started_at=started_at,
            attack_started_at=attack_started_at,
            observation_deadline_at=observation_deadline_at,
            ended_at=ended_at,
            expected_outcome=expected_outcome,
            statuses=statuses,
            failure_stage=failure_stage,
            failure_reason_code=failure_reason_code,
            failure_reason=failure_reason,
        )

    def _write_run_manifest(self, run_dir: Path, manifest: RunManifest) -> None:
        manifest_json = manifest.to_json()
        (run_dir / "run-manifest.json").write_text(manifest_json, encoding="utf-8")
        (run_dir / "run-manifest.json.sha256").write_text(
            run_manifest_sha256(manifest) + "\n", encoding="utf-8"
        )

    def _build_args(
        self,
        defn: ScenarioDefinition,
        *,
        target_device_id: str | None,
        target_host: str | None = None,
        extra_args: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """attack 스크립트에 전달할 최종 인자 dict를 조립한다.

        Dry-run·HOLD·실제 실행이 모두 이 메서드를 거쳐야 한다.
        """
        args = dict(defn.default_args)
        if extra_args:
            args.update(extra_args)

        if target_device_id:
            for arg_name in defn.target_device_id_arg_names:
                args[arg_name] = target_device_id

        if target_device_id and defn.secondary_device_id_arg_name:
            args[defn.secondary_device_id_arg_name] = _pick_secondary_device_id(
                target_device_id
            )

        if target_host and defn.target_host_arg_name:
            args[defn.target_host_arg_name] = target_host
        return args

    def _build_command(
        self, defn: ScenarioDefinition, args: dict[str, str]
    ) -> list[str]:
        command = [self.python_executable, "-m", defn.module]
        for key, value in args.items():
            if value is None:
                continue
            command.append(f"--{key}")
            command.append(str(value))
        return command


# ---------------------------------------------------------------------------
# 반복 실행
# ---------------------------------------------------------------------------
@dataclass
class BatchSummary:
    scenario_id: str
    requested_runs: int
    executed_runs: int = 0
    success_runs: int = 0
    status_counts: dict[str, int] = field(default_factory=dict)
    stopped_early: bool = False
    stop_reason: str | None = None
    results: list[ScenarioResultRow] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        """SCENARIO_FAILED를 포함해 SUCCESS/DRY_RUN이 아닌 결과가 하나라도 있으면 True.

        기존에는 RESET_FAILED/HOLD만 조기 중단시키고 SCENARIO_FAILED는 배치
        전체의 성공 여부에 반영하지 않아, 실패 Run이 있어도 CLI가 0을 반환할 수 있었다.
        """
        ok_statuses = {ScenarioExecStatus.SUCCESS, ScenarioExecStatus.DRY_RUN}
        return any(result.scenario_runner_status not in ok_statuses for result in self.results)


def run_repeated(
    runner: ScenarioRunner,
    scenario_id: str,
    times: int,
    *,
    target_device_id: str | None = None,
    source_ip: str | None = None,
    target_host: str | None = None,
    session_id: str | None = None,
    dry_run: bool = True,
) -> BatchSummary:
    summary = BatchSummary(scenario_id=scenario_id, requested_runs=times)

    for _ in range(times):
        result, _manifest = runner.run(
            scenario_id,
            target_device_id=target_device_id,
            source_ip=source_ip,
            target_host=target_host,
            session_id=session_id,
            dry_run=dry_run,
        )
        summary.executed_runs += 1
        summary.results.append(result)
        status = result.scenario_runner_status
        summary.status_counts[status] = summary.status_counts.get(status, 0) + 1
        if status in (ScenarioExecStatus.SUCCESS, ScenarioExecStatus.DRY_RUN):
            summary.success_runs += 1

        if status == ScenarioExecStatus.RESET_FAILED:
            summary.stopped_early = True
            summary.stop_reason = "RESET_FAILED: Baseline 복구 실패로 반복 실행을 중단했습니다."
            break
        if status == ScenarioExecStatus.HOLD:
            summary.stopped_early = True
            summary.stop_reason = "HOLD: Packet Rule Gate가 아직 확인되지 않았습니다."
            break

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 5 Scenario Runner")
    p.add_argument("--scenario")
    p.add_argument("--list", action="store_true")
    p.add_argument("--target-device-id", default=None)
    p.add_argument("--source-ip", default=None, help="Packet 계열 시나리오의 대상 IP (Attack Node 자신의 IP, Manifest 관찰용)")
    p.add_argument(
        "--target-host",
        default=None,
        help="Packet 계열 시나리오의 공격 목적지(Raspberry Pi/Broker) IP. "
        "--source-ip(Attack Node 자신의 IP)와 다른 값이다. "
        "지정하지 않으면 attack 스크립트 자체 기본값(BROKER_HOST)이 사용된다.",
    )
    p.add_argument(
        "--execution-node-registered",
        action="store_true",
        help="Attack Node가 DB에 등록된 IP인 경우에만 지정. 지정하지 않으면 "
        "FULL_E2E가 DETECTION_ONLY로 강제 하향됩니다.",
    )
    p.add_argument("--execution-node", default="unspecified-node")
    p.add_argument("--session-id", default=None)
    p.add_argument("--run-id", default=None)
    p.add_argument("--times", default=1, type=int)
    p.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    p.add_argument(
        "--execute",
        action="store_true",
        help="실제 공격 명령을 실행한다. 지정하지 않으면 항상 Dry-run으로 동작한다 "
        "(기본값). 실기기에서 실제 DB·iptables·Device·MQTT 상태를 확인하는 "
        "Baseline/Cleanup 훅이 연결된 뒤에만 사용해야 한다.",
    )
    p.add_argument(
        "--baseline-check-module",
        default=None,
        help="--execute와 함께 사용. 실제 Baseline 확인 함수를 "
        "'module.submodule:function_name' 형식으로 지정한다 "
        "(예: 'edge.scenarios.cleanup:pi_baseline_check'). 지정하지 않으면 "
        "기본 no-op 훅이 남아있는 것으로 간주해 --execute가 거부된다.",
    )
    p.add_argument(
        "--cleanup-hook-module",
        default=None,
        help="--execute와 함께 사용. 실제 Cleanup 함수를 "
        "'module.submodule:function_name' 형식으로 지정한다 "
        "(예: 'edge.scenarios.cleanup:pi_cleanup_hook'). 지정하지 않으면 "
        "기본 no-op 훅이 남아있는 것으로 간주해 --execute가 거부된다.",
    )
    return p.parse_args()


def _load_hook_from_module_path(module_path: str) -> Any:
    """'module.submodule:function_name' 형식 문자열을 실제 함수 객체로 로드한다."""
    if ":" not in module_path:
        raise MissingRequiredInputError(
            f"모듈 경로 형식이 올바르지 않습니다: {module_path!r} "
            "('module.submodule:function_name' 형식이어야 합니다)"
        )
    module_name, func_name = module_path.rsplit(":", 1)
    import importlib

    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise MissingRequiredInputError(
            f"{module_name!r} 모듈을 로드할 수 없습니다: {exc}"
        ) from exc
    try:
        hook = getattr(module, func_name)
    except AttributeError as exc:
        raise MissingRequiredInputError(
            f"{module_name!r} 모듈에 {func_name!r} 함수가 없습니다."
        ) from exc
    if not callable(hook):
        raise MissingRequiredInputError(
            f"{module_name!r} 모듈의 {func_name!r} 속성은 호출 가능한 함수가 아닙니다."
        )
    return hook


def main() -> int:
    args = _parse_args()

    if args.list or not args.scenario:
        print("사용 가능한 scenario_id:")
        for scenario_id, defn in sorted(SCENARIOS.items()):
            hw = " (실기기 전용/Packet Gate 필요)" if defn.requires_packet_rule_gate else ""
            print(f"  - {scenario_id} [{defn.evaluation_scope}]{hw}: {defn.description}")
            print(
                f"      최소 실행 {defn.min_functional_runs}회, "
                f"정량 기준선 목표 {defn.target_baseline_runs}회 (문서 4.6)"
            )
        return 0

    dry_run = not args.execute

    runner_kwargs: dict[str, Any] = dict(
        execution_node=args.execution_node,
        execution_node_registered=args.execution_node_registered,
        runs_root=Path(args.runs_root),
        allow_execute=args.execute,
    )
    if args.baseline_check_module:
        try:
            runner_kwargs["baseline_check"] = _load_hook_from_module_path(
                args.baseline_check_module
            )
        except MissingRequiredInputError as exc:
            print(f"[ScenarioRunner] 실행 거부: {exc}", file=sys.stderr)
            return 2
    if args.cleanup_hook_module:
        try:
            runner_kwargs["cleanup_hook"] = _load_hook_from_module_path(
                args.cleanup_hook_module
            )
        except MissingRequiredInputError as exc:
            print(f"[ScenarioRunner] 실행 거부: {exc}", file=sys.stderr)
            return 2

    runner = ScenarioRunner(**runner_kwargs)

    try:
        if args.times == 1 and args.run_id:
            result, _manifest = runner.run(
                args.scenario,
                run_id=args.run_id,
                target_device_id=args.target_device_id,
                source_ip=args.source_ip,
                target_host=args.target_host,
                session_id=args.session_id,
                dry_run=dry_run,
            )
            print(
                f"[ScenarioRunner] run_id={result.run_id} "
                f"scenario_status={result.scenario_status} "
                f"scenario_runner_status={result.scenario_runner_status}"
            )
            ok_statuses = {ScenarioExecStatus.SUCCESS.value, ScenarioExecStatus.DRY_RUN.value}
            return 0 if result.scenario_runner_status in ok_statuses else 1

        summary = run_repeated(
            runner,
            args.scenario,
            args.times,
            target_device_id=args.target_device_id,
            source_ip=args.source_ip,
            target_host=args.target_host,
            session_id=args.session_id,
            dry_run=dry_run,
        )
    except (
        KeyError,
        DuplicateRunIdError,
        MissingRequiredInputError,
        InvalidRunIdError,
        UnsafeExecutionRefusedError,
        RunManifestValidationError,
    ) as exc:
        print(f"[ScenarioRunner] 실행 거부: {exc}", file=sys.stderr)
        return 2

    print(f"[ScenarioRunner] scenario_id={summary.scenario_id}")
    print(
        f"  requested={summary.requested_runs} executed={summary.executed_runs} "
        f"success={summary.success_runs}"
    )
    print(f"  status_counts={summary.status_counts}")
    if summary.stopped_early:
        print(f"  [중단] {summary.stop_reason}")
    for result in summary.results:
        print(
            f"  - run_id={result.run_id} scenario_status={result.scenario_status} "
            f"exit_code={result.exit_code}"
        )

    if summary.stopped_early or summary.has_failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
