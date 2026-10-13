"""Public read-only DB/runtime consistency evidence; no privileged commands."""
from fastapi import APIRouter

from backend.app.config import settings
from edge.trust.firewall_consistency import read_firewall_runtime_status


router = APIRouter(tags=["firewall-runtime"])


@router.get("/firewall-runtime-status")
def firewall_runtime_status() -> dict:
    return read_firewall_runtime_status(
        snapshot_path=settings.firewall_runtime_snapshot_path,
        database_url=settings.database_url,
        max_age_seconds=settings.firewall_runtime_snapshot_max_age_seconds,
    )
