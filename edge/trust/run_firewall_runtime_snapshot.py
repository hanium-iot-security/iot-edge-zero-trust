"""One-shot read-only runtime firewall observer.

Designed for a short-interval systemd timer on Raspberry Pi. The process uses
the same narrow root-owned firewall wrapper as Firewall Worker, but only invokes
its ``list`` operation. The resulting snapshot is consumed by Recovery
Preflight; no firewall mutation is performed here.
"""

from __future__ import annotations

import logging

from backend.app.config import settings
from edge.runtime_lock import RuntimeLockError, single_instance_lock
from edge.trust.firewall_runtime_snapshot import capture_firewall_runtime_snapshot
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
    try:
        # Do not publish an intermediate Worker state (e.g. delete succeeded
        # while DB commit is still pending). No SQLite write lock is held here.
        with single_instance_lock(firewall_lock_path(), wait_seconds=settings.firewall_lock_wait_seconds):
            payload = capture_firewall_runtime_snapshot(
                runner, snapshot_path=settings.firewall_runtime_snapshot_path,
            )
    except (RuntimeLockError, OSError) as exc:
        logger.error("Firewall runtime snapshot unavailable: %s", exc)
        return False
    if payload["available"]:
        logger.info(
            "Firewall runtime snapshot updated (managed_rules=%s, observed_at=%s)",
            len(payload["managed_rules"]),
            payload["observed_at"],
        )
        return True

    logger.error(
        "Firewall runtime snapshot observation unavailable: %s",
        payload.get("error"),
    )
    return False


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return 0 if run_once() else 1


if __name__ == "__main__":
    raise SystemExit(main())
