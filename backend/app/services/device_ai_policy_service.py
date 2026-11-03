"""Expose stored AI settings; never activate a Stage, load a model or move its CP."""

from datetime import datetime
import sqlite3

from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.schemas.device_ai_policy_schema import AiPolicyRevisionRequest
from backend.app.security import RecoveryAdminContext
from backend.app.services.device_policy_service import (
    _command_connection, _connection, _device_row, _require_schema,
)
from edge.policy.device_ai_policy import AiPolicyUnavailableError
from edge.policy.device_ai_policy_repository import append_ai_policy_revision, get_ai_policy_snapshot
from edge.policy.device_policy import DeviceNotFoundError, utc_now
from edge.policy.device_policy_repository import get_registration_instance


def _require_ai_schema(connection: sqlite3.Connection) -> None:
    _require_schema(connection)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(device_ai_policy_revisions)")}
    if not {"device_id", "revision", "mode", "effective_from", "created_at", "created_by", "reason"} <= columns:
        raise AiPolicyUnavailableError("Device AI policy migration must be completed")


def get_device_ai_policy(db: Session, device_id: str) -> dict:
    with _connection(db, read=True) as connection:
        if _device_row(connection, device_id) is None:
            raise DeviceNotFoundError(f"Device {device_id!r} is not registered")
        _require_ai_schema(connection)
        return {**get_ai_policy_snapshot(connection, device_id, server_time=utc_now()).as_dict(),
                "expected_instance_id": get_registration_instance(connection, device_id)}


def revise_device_ai_policy(
    db: Session, device_id: str, request: AiPolicyRevisionRequest, admin: RecoveryAdminContext,
) -> dict:
    if request.mode == "OBSERVE" and settings.trust_ai_mode != "observe":
        raise AiPolicyUnavailableError("TRUST_AI_MODE=observe is required to select OBSERVE")
    with _command_connection(db) as connection:
        _require_ai_schema(connection)
        created = append_ai_policy_revision(
            connection, device_id=device_id, **request.model_dump(), created_by=admin.principal,
            clock=utc_now,
        )
        # The repository has committed. Read the response in one snapshot while
        # retaining the shared command lock, as for existing Rule-policy writes.
        connection.execute("BEGIN")
        now = datetime.fromisoformat(created.created_at.replace("Z", "+00:00"))
        return {**get_ai_policy_snapshot(connection, device_id, server_time=now).as_dict(),
                "expected_instance_id": get_registration_instance(connection, device_id)}
