"""One-shot read-only runtime firewall observer.

Designed for a short-interval systemd timer on Raspberry Pi. The process uses
the same narrow root-owned firewall wrapper as Firewall Worker, but only invokes
its ``list`` operation. The resulting snapshot is consumed by Recovery
Preflight; no firewall mutation is performed here.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from backend.app.config import settings
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.trust.firewall_runtime_snapshot import observe_firewall_runtime, _write_json_atomically
from edge.trust.firewall_consistency import (
    FirewallConsistencyError, build_consistency, current_boot_id,
    read_firewall_state, read_snapshot, unknown,
)
from edge.trust.firewall_worker import FirewallPolicy, WrapperIptablesRunner
from edge.trust.run_firewall_worker import firewall_lock_path


logger = logging.getLogger(__name__)


def load_snapshot_policy() -> FirewallPolicy:
    return FirewallPolicy(
        wrapper_path=settings.firewall_wrapper_path,
        sudo_path=settings.firewall_sudo_path,
        command_timeout_seconds=settings.firewall_command_timeout_seconds,
        retry_delay_seconds=settings.firewall_retry_delay_seconds,
        batch_size=settings.firewall_worker_batch_size,
    )


def run_once() -> bool:
    runner = WrapperIptablesRunner(load_snapshot_policy())
    path = Path(settings.firewall_runtime_snapshot_path)
    previous = None
    try:
        # The same lock covers observation + DB read, never an automatic repair.
        with single_instance_lock(firewall_lock_path(), wait_seconds=settings.firewall_lock_wait_seconds):
            previous = read_snapshot(path)
            payload = observe_firewall_runtime(runner)
            payload["boot_id"] = current_boot_id()
            try:
                state = read_firewall_state(
                    settings.database_url, [row["rule_id"] for row in payload["managed_rules"]],
                ) if payload["available"] else None
                payload["consistency"] = build_consistency(
                    payload, state, previous=previous, now=datetime.now(timezone.utc),
                    boot_id=payload["boot_id"],
                    max_age_seconds=settings.firewall_runtime_snapshot_max_age_seconds,
                )
            except FirewallConsistencyError as exc:
                payload["consistency"] = unknown(str(exc), observed_at=payload["observed_at"])
            # The mode=ro DB connection has closed before the single JSON publish.
            _write_json_atomically(path, payload)
    except (RuntimeLockError, OSError) as exc:
        logger.error("Firewall runtime snapshot unavailable: %s", exc)
        return False

    consistency = payload["consistency"]
    if consistency["status"] == "UNKNOWN":
        logger.error("Firewall consistency unavailable: %s", consistency["reason_code"])
        return False
    old = previous.get("consistency", {}) if isinstance(previous, dict) else {}
    old_warnings = old.get("warnings") if isinstance(old, dict) else None
    old_episodes = {(row["key"], row["first_seen_at"]) for row in old_warnings
                    if isinstance(row, dict) and isinstance(row.get("key"), str)
                    and isinstance(row.get("first_seen_at"), str)} if isinstance(old_warnings, list) else set()
    episodes = {(row["key"], row["first_seen_at"]) for row in consistency["warnings"]}
    if episodes - old_episodes:
        logger.warning("Firewall DB/runtime mismatch observed: %s",
                       [(row["kind"], row["rule_id"]) for row in consistency["warnings"]])
    elif old_episodes and consistency["status"] == "MATCH":
        logger.info("Previously observed firewall DB/runtime mismatches are resolved")
    logger.info("Firewall runtime snapshot updated (managed_rules=%s, consistency=%s, observed_at=%s)",
                len(payload["managed_rules"]), consistency["status"], payload["observed_at"])
    return True


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return 0 if run_once() else 1


if __name__ == "__main__":
    raise SystemExit(main())
