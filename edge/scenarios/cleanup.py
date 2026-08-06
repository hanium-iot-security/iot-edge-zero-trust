"""Scenario Runner 실행 전 Baseline 확인과 실행 후 안전 점검.

실제 공격 실행용 Hook은 :class:`ScenarioHookContext`를 받아 현재 Run의 대상
Session·Device·IP를 명시적으로 확인한다. Raspberry Pi Hook은 읽기 전용 점검만
수행하며 Trust Score, Device 상태, Firewall Rule, iptables 상태를 자동 복구하지
않는다.

승인된 복구가 필요하면 기존 Firewall Release, Baseline Recovery, Trust Score
Compensation 절차를 별도로 사용한다. Scenario Runner Cleanup에서 DB 이력 삭제,
Trust Score 초기화, Device 상태 초기화 또는 iptables Rule 삭제를 수행하지 않는다.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

from backend.app.config import settings


REQUIRED_RUNTIME_SERVICES: tuple[str, ...] = (
    "mosquitto",
    "mqtt-subscriber",
    "mqtt-feature-builder",
    "detection-orchestrator",
    "firewall-worker",
    "gateway-metrics",
    "iot-edge-api",
)

_CONFLICT_PROCESS_MARKERS: tuple[str, ...] = (
    " -m attacks.",
    "edge.detection.run_packet_rule_detector",
    "edge.detection.run_packet_if_detector",
    "edge.detection.run_packet_checkpoint_recovery",
    "edge.packet.run_packet_feature_extractor",
    "packet_checkpoint_recovery",
    "phase5_packet_rule_resume",
)


@dataclass(frozen=True)
class ScenarioHookContext:
    """Baseline과 Cleanup이 공유하는 단일 Run의 불변 식별 정보."""

    run_id: str
    scenario_id: str
    session_id: str | None
    target_device_id: str | None
    source_ip: str | None
    target_host: str | None
    evaluation_scope: str
    execution_node: str


class BaselineCheck(Protocol):
    """실행 전 읽기 전용 Baseline 확인 계약."""

    def __call__(
        self, context: ScenarioHookContext
    ) -> tuple[bool, str | None]: ...


class CleanupHook(Protocol):
    """공격 명령 종료 후 잔여 공격 프로세스 확인 계약."""

    def __call__(
        self, context: ScenarioHookContext
    ) -> tuple[bool, str | None]: ...


def default_baseline_check(
    _context: ScenarioHookContext | None = None,
) -> tuple[bool, str | None]:
    """Local 개발과 Dry-run용 no-op Hook.

    실제 실행에서는 :class:`~edge.scenarios.run_scenario.ScenarioRunner`가 이 함수의
    identity를 확인해 실행을 거부한다. 선택적 인자는 기존 Local 테스트의 직접 호출
    호환성만 유지한다.
    """

    return True, None


def default_cleanup_hook(
    _context: ScenarioHookContext | None = None,
) -> tuple[bool, str | None]:
    """Local 개발과 Dry-run용 no-op Hook."""

    return True, None


def _absolute_sqlite_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise ValueError(
            "database_url_not_sqlite: Pi Baseline은 sqlite:/// 절대경로만 허용합니다"
        )

    raw_path = database_url.removeprefix(prefix)
    if not raw_path or raw_path == ":memory:":
        raise ValueError("database_path_invalid: 실제 SQLite 파일 경로가 필요합니다")

    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        raise ValueError(
            f"database_path_not_absolute: DATABASE_URL={database_url!r}"
        )
    if not path.is_file():
        raise ValueError(f"database_file_missing: path={path}")
    return path.resolve()


def _connect_sqlite_read_only(database_url: str) -> sqlite3.Connection:
    path = _absolute_sqlite_path(database_url)
    uri_path = quote(path.as_posix(), safe="/:")
    connection = sqlite3.connect(
        f"file:{uri_path}?mode=ro",
        uri=True,
        timeout=5.0,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def _read_service_states() -> dict[str, str]:
    """필수 Runtime과 Packet Capture의 현재 systemd 상태를 조회한다."""

    states: dict[str, str] = {}
    for service in (*REQUIRED_RUNTIME_SERVICES, "packet-capture"):
        try:
            completed = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            states[service] = f"ERROR:{exc}"
            continue
        state = completed.stdout.strip() or completed.stderr.strip() or "unknown"
        states[service] = state
    return states


def _find_conflicting_processes() -> list[str]:
    """공격·수동 Detector·Recovery 계열의 잔존 프로세스를 읽기 전용 조회한다."""

    try:
        completed = subprocess.run(
            ["ps", "-eo", "pid=,args="],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"process_inventory_error: {exc}"]

    if completed.returncode != 0:
        reason = completed.stderr.strip() or f"exit_code={completed.returncode}"
        return [f"process_inventory_error: {reason}"]

    current_pid = os.getpid()
    matches: list[str] = []
    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        pid_text, _, command = line.partition(" ")
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        if pid == current_pid:
            continue
        if any(marker in f" {command}" for marker in _CONFLICT_PROCESS_MARKERS):
            matches.append(line)
    return matches


def _list_project_firewall_rules(source_ip: str | None) -> list[str]:
    """기존 root Wrapper의 list 명령으로 실제 프로젝트 Rule을 읽기 전용 조회한다."""

    try:
        completed = subprocess.run(
            [
                settings.firewall_sudo_path,
                "-n",
                settings.firewall_wrapper_path,
                "list",
            ],
            capture_output=True,
            text=True,
            timeout=settings.firewall_command_timeout_seconds,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"firewall_inventory_error: {exc}"]

    if completed.returncode != 0:
        reason = completed.stderr.strip() or f"exit_code={completed.returncode}"
        return [f"firewall_inventory_error: {reason}"]

    project_rules = [
        line.strip()
        for line in completed.stdout.splitlines()
        if "hanium-firewall:" in line
    ]
    if source_ip:
        project_rules = [
            line
            for line in project_rules
            if f"-s {source_ip} " in f"{line} "
            or f"-s {source_ip}/32 " in f"{line} "
        ]
    return project_rules


def _active_firewall_rows(
    connection: sqlite3.Connection,
    *,
    target_device_id: str | None,
    source_ip: str | None,
) -> list[sqlite3.Row]:
    conditions: list[str] = []
    params: list[str] = []
    if target_device_id:
        conditions.append("device_id = ?")
        params.append(target_device_id)
    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)
    if not conditions:
        return []

    sql = (
        "SELECT id, device_id, source_ip, status "
        "FROM firewall_rules "
        "WHERE status IN ('PENDING', 'APPLIED') AND ("
        + " OR ".join(conditions)
        + ") ORDER BY id"
    )
    return list(connection.execute(sql, params).fetchall())


def pi_baseline_check(
    context: ScenarioHookContext,
) -> tuple[bool, str | None]:
    """Raspberry Pi 실공격 직전의 최소 읽기 전용 안전 Gate.

    DB Row나 운영 상태를 변경하지 않는다. 실패 시 공격은 시작되지 않으며 구체적인
    원인을 반환한다.
    """

    try:
        connection = _connect_sqlite_read_only(settings.database_url)
    except (OSError, sqlite3.Error, ValueError) as exc:
        return False, str(exc)

    try:
        if context.target_device_id:
            device = connection.execute(
                "SELECT device_id, ip_address, status, trust_score "
                "FROM devices WHERE device_id = ?",
                (context.target_device_id,),
            ).fetchone()
            if device is None:
                return (
                    False,
                    f"device_not_found: device_id={context.target_device_id}",
                )
            if device["status"] != "normal":
                return (
                    False,
                    "device_not_normal: "
                    f"device_id={context.target_device_id} "
                    f"status={device['status']} trust_score={device['trust_score']}",
                )

        active_rules = _active_firewall_rows(
            connection,
            target_device_id=context.target_device_id,
            source_ip=context.source_ip,
        )
        if active_rules:
            summaries = [
                f"id={row['id']},device={row['device_id']},"
                f"source_ip={row['source_ip']},status={row['status']}"
                for row in active_rules
            ]
            return False, "active_firewall_rule: " + "; ".join(summaries)

        if context.session_id:
            capture_session = connection.execute(
                "SELECT session_id, status, ended_at "
                "FROM packet_capture_sessions WHERE session_id = ?",
                (context.session_id,),
            ).fetchone()
            if capture_session is None:
                return False, f"capture_session_not_found: {context.session_id}"
            if (
                capture_session["status"] != "RUNNING"
                or capture_session["ended_at"] is not None
            ):
                return (
                    False,
                    "capture_session_not_running: "
                    f"session_id={context.session_id} "
                    f"status={capture_session['status']} "
                    f"ended_at={capture_session['ended_at']}",
                )
    except sqlite3.Error as exc:
        return False, f"baseline_db_query_failed: {exc}"
    finally:
        connection.close()

    actual_firewall_rules = _list_project_firewall_rules(context.source_ip)
    inventory_errors = [
        item for item in actual_firewall_rules if item.startswith("firewall_inventory_error:")
    ]
    if inventory_errors:
        return False, inventory_errors[0]
    if actual_firewall_rules:
        return False, "active_iptables_rule: " + " | ".join(actual_firewall_rules)

    conflicts = _find_conflicting_processes()
    if conflicts:
        return False, "conflicting_process: " + " | ".join(conflicts)

    states = _read_service_states()
    inactive_required = {
        service: states.get(service, "missing")
        for service in REQUIRED_RUNTIME_SERVICES
        if states.get(service) != "active"
    }
    if inactive_required:
        details = ", ".join(
            f"{service}={state}"
            for service, state in sorted(inactive_required.items())
        )
        return False, f"runtime_service_not_active: {details}"

    capture_state = states.get("packet-capture", "missing")
    expected_capture_state = "active" if context.session_id else "inactive"
    if capture_state != expected_capture_state:
        return (
            False,
            "packet_capture_state_mismatch: "
            f"session_id={context.session_id} expected={expected_capture_state} "
            f"actual={capture_state}",
        )

    return True, None


def pi_cleanup_hook(
    context: ScenarioHookContext,
) -> tuple[bool, str | None]:
    """공격 명령 종료 후 잔여 공격·수동 실행 프로세스만 확인한다.

    이 함수는 DB, Trust Score, Device 상태, Firewall Rule, iptables를 변경하지
    않는다. Observation과 승인형 복구가 필요한 상태는 그대로 보존한다.
    """

    conflicts = _find_conflicting_processes()
    if conflicts:
        return (
            False,
            "residual_attack_process: "
            f"run_id={context.run_id} "
            + " | ".join(conflicts),
        )
    return True, None
