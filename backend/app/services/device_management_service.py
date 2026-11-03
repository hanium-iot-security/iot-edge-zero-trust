"""Audited deletion of unused registrations and independent list visibility.

No telemetry, firewall, broker or ACL command is issued here. Commands acquire
the existing Worker lock before BEGIN IMMEDIATE and recheck their full preview.
"""
import json
from datetime import datetime, timedelta
from uuid import uuid4

from backend.app.services import device_policy_service as policy_service
from edge.policy.device_ai_policy import INITIAL_AI_REASON
from edge.policy.device_ai_policy_repository import get_ai_policy_snapshot
from edge.policy.device_management_history import has_non_sqlite_json_device_history
from edge.policy.device_policy import (
    DeviceNotFoundError, DevicePolicyError, PolicyUnavailableError,
    StateTransitionBlockedError, format_utc_millis, validate_actor,
)
from edge.policy.device_policy_repository import get_policy_snapshot, write_transaction


class DeviceManagementUnavailable(PolicyUnavailableError):
    code = "DEVICE_MANAGEMENT_UNAVAILABLE"


class ManagementConflict(DevicePolicyError):
    code = "MANAGEMENT_CONFLICT"


class ManagementActionBlocked(DevicePolicyError):
    code = "MANAGEMENT_ACTION_BLOCKED"


def _require_schema(connection):
    columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
    audit_columns = {row[1] for row in connection.execute("PRAGMA table_info(device_management_audits)")}
    objects = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
    required = {
        "device_management_history", "device_management_audits_no_update",
        "device_management_audits_no_delete", "device_management_audits_no_replace",
        "devices_registration_instance_insert", "devices_registration_instance_immutable", "devices_management_delete_guard",
    }
    if (not {"hidden_at", "registration_instance_id"} <= columns or not required <= objects or not {
        "operation_id", "device_id", "action", "requested_at", "requested_by", "reason", "payload_json",
    } <= audit_columns):
        raise DeviceManagementUnavailable("Device-management migration 019 must be completed")


def _rows(connection, table, device_id):
    cursor = connection.execute(f"SELECT * FROM {table} WHERE device_id = ? ORDER BY revision", (device_id,))
    return [dict(zip((column[0] for column in cursor.description), row)) for row in cursor.fetchall()]


def _state(connection, device_id, now, *, check_runtime=True):
    _require_schema(connection)
    device = policy_service._device_row(connection, device_id)
    if device is None:
        raise DeviceNotFoundError(f"Device {device_id!r} is not registered")
    rule = get_policy_snapshot(connection, device_id, server_time=now)
    ai = get_ai_policy_snapshot(connection, device_id, server_time=now)
    rules = _rows(connection, "device_policy_revisions", device_id)
    ais = _rows(connection, "device_ai_policy_revisions", device_id)
    initial_rule = rules[0]
    initial_ai = ais[0]
    delete_blockers = []
    if not (
        len(rules) == 1 and initial_rule["revision"] == 1
        and initial_rule["registration_state"] == "PENDING"
        and device["registration_effective_from"] is not None
        and initial_rule["effective_from"] == device["registration_effective_from"]
    ):
        delete_blockers.append("INITIAL_REGISTRATION_REQUIRED")
    if not (
        len(ais) == 1 and initial_ai["revision"] == 1 and initial_ai["mode"] == "OFF"
        and initial_ai["reason"] == INITIAL_AI_REASON
        and all(initial_ai[key] == initial_rule[key] for key in ("effective_from", "created_at", "created_by"))
    ):
        delete_blockers.append("INITIAL_AI_POLICY_REQUIRED")
    if device["status"] != "normal" or device["trust_score"] != 100 or device["last_seen_at"] is not None:
        delete_blockers.append("DEVICE_ACTIVITY")
    if device["hidden_at"] is not None:
        delete_blockers.append("ALREADY_HIDDEN")
    delete_blockers.extend("HISTORY_" + row[0] for row in connection.execute(
        "SELECT source FROM device_management_history WHERE device_id = ? ORDER BY source", (device_id,),
    ))
    if "HISTORY_MQTT_LOGS" not in delete_blockers and has_non_sqlite_json_device_history(connection, device_id):
        delete_blockers.append("HISTORY_MQTT_LOGS")
    latest_operation = connection.execute(
        "SELECT operation_id FROM device_management_audits WHERE device_id = ? ORDER BY rowid DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    hide_blockers = []
    if rule.current is None or rule.current.registration_state != "DISABLED":
        hide_blockers.append("NOT_DISABLED")
    if rule.pending is not None:
        hide_blockers.append("PENDING_POLICY")
    if ai.pending is not None:
        hide_blockers.append("PENDING_AI_POLICY")
    if device["hidden_at"] is not None:
        hide_blockers.append("ALREADY_HIDDEN")
    if not hide_blockers and check_runtime:
        try:
            policy_service._state_change_guard(connection, device_id, "DISABLED", "DISABLED")
        except StateTransitionBlockedError:
            hide_blockers.append("FIREWALL_NOT_RELEASED")
    return {
        "device_id": device_id, "expected_revision": rule.latest_revision,
        "expected_ai_revision": ai.latest_revision, "hidden_at": device["hidden_at"],
        "expected_instance_id": device["registration_instance_id"],
        "expected_management_operation_id": latest_operation[0] if latest_operation else None,
        "can_delete": not delete_blockers, "can_hide": not hide_blockers,
        "can_restore": device["hidden_at"] is not None,
        "delete_blockers": delete_blockers, "hide_blockers": hide_blockers,
    }, device, rules, ais


def get_device_management(db, device_id):
    with policy_service._connection(db, read=True) as connection:
        return _state(connection, device_id, policy_service.utc_now())[0]


def manage_device(db, device_id, request, admin):
    actor = validate_actor(admin.principal)
    with policy_service._command_connection(db) as connection:
        with write_transaction(connection):
            now = policy_service.utc_now()
            state, device, rules, ais = _state(
                connection, device_id, now, check_runtime=request.action == "HIDE",
            )
            if (request.expected_revision != state["expected_revision"]
                or request.expected_ai_revision != state["expected_ai_revision"]
                or request.expected_instance_id != state["expected_instance_id"]
                or request.expected_management_operation_id != state["expected_management_operation_id"]
                or request.expected_hidden_at != state["hidden_at"]):
                raise ManagementConflict("Device management state changed; refresh before retrying")
            permitted = {"DELETE_UNUSED": "can_delete", "HIDE": "can_hide", "RESTORE": "can_restore"}
            if not state[permitted[request.action]]:
                blockers = (state["delete_blockers"] if request.action == "DELETE_UNUSED"
                            else state["hide_blockers"] if request.action == "HIDE" else ["NOT_HIDDEN"])
                raise ManagementActionBlocked("Action is unavailable: " + ", ".join(blockers))
            operation_id = str(uuid4())
            timestamp = format_utc_millis(now)
            if request.action == "DELETE_UNUSED" and device["registration_instance_id"] is None:
                instance_id = str(uuid4())
                connection.execute("UPDATE devices SET registration_instance_id = ? WHERE device_id = ?", (instance_id, device_id))
                device["registration_instance_id"] = instance_id
            hidden_at = timestamp if request.action == "HIDE" else None
            if request.action == "HIDE":
                previous_hidden = connection.execute(
                    "SELECT MAX(json_extract(payload_json, '$.after_hidden_at')) "
                    "FROM device_management_audits WHERE device_id = ? AND action = 'HIDE'", (device_id,),
                ).fetchone()[0]
                # Distinct visibility tokens prevent an old RESTORE from
                # matching a later HIDE, including within one clock tick.
                if previous_hidden is not None and hidden_at <= previous_hidden:
                    hidden_at = format_utc_millis(
                        datetime.fromisoformat(previous_hidden.replace("Z", "+00:00")) + timedelta(milliseconds=1)
                    )
            payload = {
                "before_device": device, "rule_revision": rules[0], "ai_revision": ais[0],
                "rule_revisions": rules, "ai_revisions": ais,
                "after_hidden_at": hidden_at, "deleted": request.action == "DELETE_UNUSED",
                "previous_operation_id": state["expected_management_operation_id"],
                "reason_provided": request.reason is not None,
            }
            connection.execute(
                "INSERT INTO device_management_audits "
                "(operation_id,device_id,action,requested_at,requested_by,reason,payload_json) "
                "VALUES (?,?,?,?,?,?,?)",
                (operation_id, device_id, request.action, timestamp, actor, request.reason or "사유 미입력",
                 json.dumps(payload, ensure_ascii=False, separators=(",", ":"))),
            )
            if request.action == "DELETE_UNUSED":
                connection.execute("DELETE FROM device_ai_policy_revisions WHERE device_id = ?", (device_id,))
                connection.execute("DELETE FROM device_policy_revisions WHERE device_id = ?", (device_id,))
                connection.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            else:
                connection.execute("UPDATE devices SET hidden_at = ? WHERE device_id = ?", (hidden_at, device_id))
            result = {
                "device_id": device_id, "action": request.action, "operation_id": operation_id,
                "hidden_at": hidden_at, "deleted": request.action == "DELETE_UNUSED",
            }
        return result
