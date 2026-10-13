"""Approve one new wide PENDING rule; no OS commands or source-row mutation."""

from contextlib import contextmanager
from datetime import datetime, timezone
import math

from sqlalchemy.exc import IntegrityError, OperationalError

from backend.app.config import settings
from backend.app.security import RecoveryAdminContext
from backend.app.services.firewall_rule_query_service import _firewall_item
from edge.policy.device_policy import DevicePolicyError
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.trust import firewall_repository
from edge.trust.firewall_scope import PI_INPUT_IPV4_ALL
from edge.trust.run_firewall_worker import firewall_lock_path


class FirewallScopeExtensionError(RuntimeError):
    def __init__(self, status_code, failure_code):
        self.status_code = status_code
        self.detail = {"result": "DENIED", "failure_code": failure_code, "failure_reason": failure_code}
        super().__init__(failure_code)


@contextmanager
def firewall_command_transaction(db):
    """Same ordering as Worker and policy API: file lock, then SQLite writer."""
    if db.get_bind().dialect.name != "sqlite":
        raise FirewallScopeExtensionError(503, "FIREWALL_DATABASE_UNAVAILABLE")
    wait = settings.firewall_lock_wait_seconds
    if not math.isfinite(wait) or wait < 0:
        raise FirewallScopeExtensionError(503, "FIREWALL_LOCK_UNAVAILABLE")
    lock_settings = settings.model_copy(update={"database_url": str(db.get_bind().url)})
    try:
        with single_instance_lock(firewall_lock_path(lock_settings), wait_seconds=wait):
            # A caller's existing write must never be discarded to authorize a command.
            firewall_repository._begin_authorization_transaction(db, write=True)
            try:
                yield
                db.commit()
            except BaseException:
                db.rollback()
                raise
    except RuntimeLockError:
        raise FirewallScopeExtensionError(409, "FIREWALL_OPERATION_IN_PROGRESS") from None
    except OSError:
        raise FirewallScopeExtensionError(503, "FIREWALL_LOCK_UNAVAILABLE") from None
    except OperationalError:
        raise FirewallScopeExtensionError(409, "FIREWALL_DATABASE_BUSY") from None


def scope_extension_confirmation(source_rule_id, source_ip, approved_policy_revision):
    return f"EXTEND-PI-INPUT-{source_rule_id}-{source_ip}-REV-{approved_policy_revision}"


def _now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0)


def create_firewall_scope_extension(db, *, source_rule_id: int, device_id: str, source_ip: str,
                                    approved_policy_revision: int, scope: str, reason: str,
                                    request_id: str, confirm: str, admin: RecoveryAdminContext):
    expected = scope_extension_confirmation(source_rule_id, source_ip, approved_policy_revision)
    if confirm != expected:
        raise FirewallScopeExtensionError(409, "SCOPE_EXTENSION_CONFIRMATION_MISMATCH")
    if scope != PI_INPUT_IPV4_ALL:
        raise FirewallScopeExtensionError(422, "UNSUPPORTED_EXTENSION_SCOPE")
    try:
        with firewall_command_transaction(db):
            row, created = firewall_repository.create_pending_scope_extension(
                db, source_rule_id=source_rule_id, device_id=device_id, source_ip=source_ip,
                approved_policy_revision=approved_policy_revision, scope=scope, reason=reason,
                request_id=request_id, requested_by=admin.principal, now=_now_utc(),
            )
    except firewall_repository.AutomaticResponseBlockedError as error:
        code = str(error)
        status = 503 if code in ("MIGRATION_011_REQUIRED", "FIREWALL_SCOPE_SCHEMA_UNAVAILABLE", "POLICY_UNAVAILABLE") else 404 if code == "SOURCE_RULE_NOT_FOUND" else 409
        raise FirewallScopeExtensionError(status, code) from None
    except DevicePolicyError:
        raise FirewallScopeExtensionError(422, "INVALID_SCOPE_EXTENSION_REQUEST") from None
    except IntegrityError:
        raise FirewallScopeExtensionError(409, "SCOPE_EXTENSION_CONFLICT") from None
    return {"item": _firewall_item(row), "created": created, "replayed": not created, "runtime_verified": False}
