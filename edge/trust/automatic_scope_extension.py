"""Opt-in, once-per-source automatic Pi INPUT IPv4 scope extensions.

The caller holds the shared Worker/API lock. A fresh SQLite writer covers
selection and repository authorization; no OS operation happens in this module.
"""

from datetime import datetime
import logging
from uuid import uuid4

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from edge.detection.phase4_time import format_db_utc, require_utc_whole_second
from edge.trust import firewall_repository
from edge.trust.firewall_scope import MQTT_IPV4_TCP_1883, PI_INPUT_IPV4_ALL
from edge.trust.firewall_worker import FirewallPolicy, FirewallValidationError, validate_rule_row

logger = logging.getLogger(__name__)

AUTOMATIC_ACTOR = "system:firewall-worker"
AUTOMATIC_REASON = (
    "Automatic scope extension under operator setting "
    "FIREWALL_AUTO_SCOPE=PI_INPUT_IPV4_ALL; original MQTT rule retained"
)


def require_automatic_scope_schema(db: Session, *, policy: FirewallPolicy) -> None:
    """An explicit wide rollout must never silently fall back to legacy scope."""
    if policy.auto_scope == PI_INPUT_IPV4_ALL and not firewall_repository.has_scope_schema(db):
        raise firewall_repository.AutomaticResponseBlockedError("MIGRATION_011_REQUIRED")


def queue_automatic_scope_extensions(
    db: Session, *, policy: FirewallPolicy, now: datetime, limit: int | None = None,
) -> list[int]:
    """Queue a bounded batch; any prior wide row permanently consumes its source.

    Manual exact release and later manual reextension remain available. Failed
    rows use only the existing Worker retry policy, never replacement rows.
    """
    if policy.auto_scope != PI_INPUT_IPV4_ALL:
        return []
    batch_size = policy.batch_size if limit is None else min(limit, policy.batch_size)
    if batch_size <= 0:
        return []
    now = require_utc_whole_second(now, "now")
    firewall_repository._begin_authorization_transaction(db, write=True)
    queued = []
    try:
        require_automatic_scope_schema(db, policy=policy)
        # Cheap eligibility filters precede LIMIT so known disabled/protected
        # sources cannot monopolize the batch. The repository still performs
        # full policy, source/IP, release and prior-wide audit validation.
        candidates = db.execute(
            text("""
                SELECT source.*, current.revision AS current_policy_revision
                FROM firewall_rules AS source
                JOIN devices AS device ON device.device_id=source.device_id
                    AND device.ip_address=source.source_ip AND device.status='isolated'
                JOIN device_policy_revisions AS current ON current.device_id=source.device_id
                    AND current.revision=(
                        SELECT max(revision) FROM device_policy_revisions
                        WHERE device_id=source.device_id AND effective_from<=:now
                    )
                WHERE source.status='APPLIED' AND source.scope=:mqtt_scope
                    AND current.registration_state='ACTIVE'
                    AND source.source_ip NOT IN :protected_ips
                    AND NOT EXISTS (
                        SELECT 1 FROM device_policy_revisions AS pending
                        WHERE pending.device_id=source.device_id
                            AND pending.effective_from>:now AND pending.registration_state='DISABLED'
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM firewall_release_requests AS release
                        WHERE release.firewall_rule_id=source.id AND release.status='PENDING'
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM firewall_rules AS wide
                        WHERE wide.source_rule_id=source.id AND wide.scope=:wide_scope
                    )
                ORDER BY source.id LIMIT :limit
            """).bindparams(bindparam("protected_ips", expanding=True)),
            {"now": format_db_utc(now), "mqtt_scope": MQTT_IPV4_TCP_1883,
             "wide_scope": PI_INPUT_IPV4_ALL, "protected_ips": sorted(policy.protected_ips),
             "limit": batch_size},
        ).mappings().all()
        for source in candidates:
            try:
                validate_rule_row(source, policy)
                row, created = firewall_repository.create_pending_scope_extension(
                    db, source_rule_id=source["id"], device_id=source["device_id"],
                    source_ip=source["source_ip"],
                    approved_policy_revision=source["current_policy_revision"],
                    requested_by=AUTOMATIC_ACTOR, reason=AUTOMATIC_REASON,
                    request_id=str(uuid4()), scope=PI_INPUT_IPV4_ALL, now=now,
                )
            except (firewall_repository.AutomaticResponseBlockedError, FirewallValidationError) as error:
                logger.warning("Automatic scope extension refused (source_rule_id=%s): %s",
                               source["id"], error)
                continue
            if created:
                queued.append(row["id"])
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return queued
