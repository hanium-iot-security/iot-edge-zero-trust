"""Backend security dependencies for management-only API surfaces."""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from fastapi import Header, HTTPException

from backend.app.config import settings


@dataclass(frozen=True)
class RecoveryAdminContext:
    principal: str


def require_recovery_admin(
    x_recovery_admin_key: str | None = Header(default=None),
) -> RecoveryAdminContext:
    configured_key = settings.recovery_admin_api_key.strip()
    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="RECOVERY_ADMIN_NOT_CONFIGURED",
        )
    if x_recovery_admin_key is None or not secrets.compare_digest(
        x_recovery_admin_key,
        configured_key,
    ):
        raise HTTPException(status_code=401, detail="RECOVERY_ADMIN_UNAUTHORIZED")

    principal = settings.recovery_admin_principal.strip() or "recovery-admin"
    return RecoveryAdminContext(principal=principal)
