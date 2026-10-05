"""Linux administrator CLI for audited, drained shutdown and one-use restart.

This command never powers off the host or changes Firewall/Trust policy. Online
backup and integrity checks finish before the short checkpoint write transaction.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import stat
import signal
import time
from typing import Sequence
import uuid

from backend.app.config import Settings
from dotenv import dotenv_values
from edge.detection import packet_checkpoint_recovery as safety
from edge.runtime_lock import single_instance_lock
from edge.orchestration.stage_registry import load_stage_registry
from edge.packet.capture_policy import CapturePolicy
from edge.detection.phase4_time import parse_db_utc
from edge.trust.run_firewall_worker import firewall_lock_path

CAPTURE = "packet-capture.service"
SUBSCRIBER = "mqtt-subscriber.service"
DRAIN_SERVICES = ("mqtt-feature-builder.service", "detection-orchestrator.service",
                  "packet-feature-extractor.timer", "firewall-worker.service")
STOP_AFTER_DRAIN = ("detection-orchestrator.service", "mqtt-feature-builder.service",
                    "packet-feature-extractor.timer", "packet-feature-extractor.service",
                    "firewall-runtime-snapshot.timer", "firewall-runtime-snapshot.service",
                    "firewall-worker.service")
MANAGED_SERVICES = (CAPTURE, SUBSCRIBER, *STOP_AFTER_DRAIN)


class MaintenanceHold(RuntimeError):
    """No approval is consumed on a failed precondition."""


class ConsumedApprovalHold(MaintenanceHold):
    """A used approval can never authorize a different reboot."""


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


class SystemOperations:
    """Bounded, shell-free OS operations; replace with a fake in unit tests."""

    def require_admin(self):
        if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise MaintenanceHold("execution requires an authenticated Linux root administrator")

    def boot_id(self):
        return str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))

    def command(self, *argv, timeout=35):
        completed = subprocess.run(argv, check=False, capture_output=True, text=True,
                                   timeout=timeout)
        if completed.returncode:
            raise MaintenanceHold(f"OS command failed ({completed.returncode}): {' '.join(argv)}")
        return completed.stdout.strip()

    def active(self, unit):
        result = subprocess.run(("systemctl", "is-active", unit), check=False,
                                capture_output=True, text=True, timeout=10)
        if result.returncode not in (0, 3):
            raise MaintenanceHold(f"cannot determine service state: {unit}")
        return result.stdout.strip() in ("active", "activating")

    def stop(self, unit):
        self.command("systemctl", "stop", unit)
        if self.active(unit):
            raise MaintenanceHold(f"service still active after stop: {unit}")
        if unit in (CAPTURE, SUBSCRIBER, "detection-orchestrator.service"):
            properties = self.command("systemctl", "show", unit, "--property=Result",
                                      "--property=ExecMainStatus")
            values = dict(line.split("=", 1) for line in properties.splitlines() if "=" in line)
            if values.get("Result") != "success" or values.get("ExecMainStatus") != "0":
                raise MaintenanceHold(f"unclean writer shutdown: {unit}")

    def start(self, unit):
        self.command("systemctl", "start", unit)

    def synchronized(self):
        return self.command("timedatectl", "show", "--property=NTPSynchronized", "--value",
                            timeout=10) == "yes"

    monotonic = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)


@contextmanager
def connection(database, *, readonly=False):
    conn = sqlite3.connect(database.as_uri() + "?mode=ro" if readonly else str(database),
                          uri=readonly, isolation_level=None, timeout=5)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        if readonly:
            conn.execute("PRAGMA query_only=ON")
        yield conn
    finally:
        conn.close()


def online_backup(database, artifact_root, *, timeout=120):
    """Bounded SQLite snapshot, hash and integrity checks outside a write lock."""
    root = artifact_root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    folder = root / str(uuid.uuid4())
    folder.mkdir(mode=0o700)
    backup = folder / "database.backup.db"
    # Exclusive creation prevents replacing an existing artifact or symlink.
    with backup.open("xb"):
        pass
    os.chmod(backup, 0o600)
    deadline = time.monotonic() + timeout

    def remaining(*_):
        if time.monotonic() >= deadline:
            raise MaintenanceHold("online backup or verification timed out")
        return 0

    with connection(database, readonly=True) as source, sqlite3.connect(backup) as target:
        source.backup(target, pages=256, progress=remaining, sleep=0.05)
        target.set_progress_handler(remaining, 10000)
        if target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise MaintenanceHold("backup failed integrity check")
        if target.execute("PRAGMA foreign_key_check").fetchall():
            raise MaintenanceHold("backup failed foreign-key check")
    digest = hashlib.sha256()
    with backup.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            remaining()
            digest.update(chunk)
    sha = digest.hexdigest()
    with backup.with_suffix(".db.sha256").open("x", encoding="ascii") as stream:
        os.chmod(backup.with_suffix(".db.sha256"), 0o600)
        stream.write(f"{sha}  {backup.name}\n")
    return {"backup_path": str(backup), "backup_sha256": sha}


class MaintenanceRunner:
    def __init__(self, database, repository_root, *, system=None, core=None,
                 locks=None, backup=online_backup, now=utc_now):
        self.database = Path(database).resolve(strict=True)
        self.root = Path(repository_root).resolve(strict=True)
        self.system = system or SystemOperations()
        if core is None:
            from edge.maintenance import planned as core
        self.core, self.backup, self.now = core, backup, now
        configured = Settings(_env_file=self.root / ".env")
        self.settings = configured
        self.capture_policy = CapturePolicy(
            max_start_delay_seconds=configured.pcap_max_start_delay_seconds,
            minimum_duration_seconds=configured.packet_min_capture_duration_seconds,
            epsilon_seconds=configured.capture_time_epsilon_seconds,
            version=configured.capture_policy_version)
        recovery_locks = safety.resolve_recovery_locks(
            repository_root=self.root, database_url=f"sqlite:///{self.database.as_posix()}",
            orchestrator_lock_path=Path(configured.orchestrator_lock_path)
            if configured.orchestrator_lock_path.strip() else None,
            manual_lock_path=None, extractor_lock_path=None)
        lock_settings = configured.model_copy(update={"database_url": f"sqlite:///{self.database.as_posix()}"})
        ordered = tuple(item.path for item in recovery_locks)
        firewall = firewall_lock_path(lock_settings)
        # Orchestrator owns its lock before requesting the Firewall lock. Keep
        # that order even when a custom path sorts before orchestrator lexically.
        self.locks = locks or (*[path for path in ordered if path != firewall], firewall)
        self.command_lock = self.database.with_name(self.database.name + ".planned-maintenance.lock")

    def require_deployment(self):
        if not isinstance(self.system, SystemOperations):
            return  # injectable fake owns its test service namespace
        if self.root != Path(__file__).resolve().parents[2]:
            raise MaintenanceHold("execution must use the running implementation checkout")
        values = dotenv_values(self.root / ".env")
        for name in ("DATABASE_URL", "ORCHESTRATOR_LOCK_PATH", "FIREWALL_LOCK_PATH",
                     "ORCHESTRATOR_ENABLED_STAGES", "ORCHESTRATOR_REQUIRED_STAGES",
                     "PCAP_WINDOW_SECONDS", "FEATURE_WINDOW_SECONDS",
                     "PCAP_MAX_START_DELAY_SECONDS", "PACKET_MIN_CAPTURE_DURATION_SECONDS",
                     "CAPTURE_TIME_EPSILON_SECONDS", "CAPTURE_POLICY_VERSION"):
            if name in os.environ and os.environ[name].strip() != (values.get(name) or "").strip():
                raise MaintenanceHold(f"shell {name} override differs from deployment .env")
        configured = self.settings.database_url
        if not configured.startswith("sqlite:///"):
            raise MaintenanceHold("planned maintenance supports the deployed SQLite database only")
        candidate = Path(configured.removeprefix("sqlite:///"))
        deployed = (candidate if candidate.is_absolute() else self.root / candidate).resolve()
        if deployed != self.database:
            raise MaintenanceHold("database path differs from deployment configuration")
        paths = (self.database, *[Path(str(self.database) + suffix) for suffix in ("-wal", "-shm", "-journal")],
                 self.command_lock, *self.locks)
        for index, first in enumerate(paths):
            for second in paths[index + 1:]:
                if first.resolve() == second.resolve() or (first.exists() and second.exists() and os.path.samefile(first, second)):
                    raise MaintenanceHold("database and lock paths must be distinct")
        for lock in (self.command_lock, *self.locks):
            if lock.is_symlink() or (lock.exists() and not lock.is_file()):
                raise MaintenanceHold(f"lock path must be a regular file: {lock}")
        safety.validate_generated_paths(repository_root=self.root, lock_paths=(self.command_lock, *self.locks))

    def required_checkpoints(self):
        registry = load_stage_registry(self.settings)
        required = {(item.stage.detector_name, item.stage.source_table)
                    for item in registry.required_stages}
        required.update((("mqtt_feature_builder", "mqtt_logs"),
                         ("trust_score_v2", "detection_events")))
        canonical = set(self.core.REQUIRED_CHECKPOINTS)
        if required not in (canonical, canonical | {("mqtt_if", "feature_logs")}):
            raise MaintenanceHold("configured required stages do not match supported shutdown barriers")
        return tuple(sorted(required))

    @contextmanager
    def protected(self):
        with ExitStack() as stack:
            for lock in self.locks:
                self.prepare_lock_file(lock)
                stack.enter_context(single_instance_lock(lock, wait_seconds=15))
            yield

    def prepare_lock_file(self, path):
        if not isinstance(self.system, SystemOperations) or os.name != "posix":
            return
        if not path.parent.is_dir():
            raise MaintenanceHold(f"runtime lock parent must already exist for the service user: {path.parent}")
        owner = self.database.stat()
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            existing = path.lstat()
            if not stat.S_ISREG(existing.st_mode) or existing.st_uid != owner.st_uid:
                raise MaintenanceHold(f"runtime lock has unsafe type/owner: {path}")
        else:
            try:
                os.fchown(descriptor, owner.st_uid, owner.st_gid)
            finally:
                os.close(descriptor)

    def running_session(self, conn):
        rows = conn.execute("SELECT session_id FROM packet_capture_sessions WHERE status='RUNNING'").fetchall()
        if len(rows) != 1:
            raise MaintenanceHold("exactly one RUNNING capture session is required")
        return rows[0][0]

    def latest(self, conn, operation_id=None):
        if operation_id is None:
            row = conn.execute("SELECT operation_id FROM planned_maintenance_operations "
                               "ORDER BY requested_at DESC, operation_id DESC LIMIT 1").fetchone()
            if not row:
                return None
            operation_id = row[0]
        return self.core.get_operation(conn, operation_id)

    def status(self, operation_id=None):
        with connection(self.database, readonly=True) as conn:
            conn.execute("BEGIN")
            record = self.latest(conn, operation_id)
            return {"result": "STATUS", "operation": record}

    def cancel(self, operation_id, *, reason):
        self.system.require_admin()
        self.require_deployment()
        with single_instance_lock(self.command_lock, wait_seconds=0), connection(self.database) as conn:
            conn.execute("BEGIN IMMEDIATE")
            record = self.core.cancel_stop(conn, operation_id, reason=reason, now=self.now())
            conn.commit()
            return {"result": "CANCELLED", "operation": record}

    def dry_run(self, operation_id=None):
        with connection(self.database, readonly=True) as conn:
            conn.execute("BEGIN")
            record = self.latest(conn, operation_id)
            if not record:
                return {"result": "WAIT", "reason": "no planned shutdown approval"}
            if record["status"] == "RESUMED":
                if (self.system.boot_id() != record["target_boot_id"] or
                    self.running_session(conn) != record["target_session_id"]):
                    return {"result": "HOLD", "reason": "consumed approval belongs to another boot or Session; strict recovery required"}
                audit = self.core.get_resume_audit(conn, record["operation_id"])
                return {"result": "ALREADY_RESUMED", "operation": record, "audit": audit,
                        "verification": "read-only preview; live progress is not checked"}
            return self.core.inspect_resume(
                conn, record["operation_id"], target_session_id=self.running_session(conn),
                current_boot_id=self.system.boot_id(), time_synchronized=self.system.synchronized(),
                now=self.now())

    def prepare_stop(self, *, approved_by, reason, timeout=180):
        self.system.require_admin()
        self.require_deployment()
        required = self.required_checkpoints()  # reject bad profile before stopping writers
        original = {unit: self.system.active(unit) for unit in MANAGED_SERVICES}
        if not all(original[unit] for unit in (CAPTURE, SUBSCRIBER, *DRAIN_SERVICES)):
            raise MaintenanceHold("capture, subscriber and all drain services must be active")
        operation_id, stopped = None, []
        with single_instance_lock(self.command_lock, wait_seconds=0):
            try:
                with connection(self.database) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    record = self.core.request_stop(
                        conn, approved_by=f"root/uid=0; declared={approved_by}", reason=reason,
                        source_session_id=self.running_session(conn),
                        source_boot_id=self.system.boot_id(), required_checkpoints=required,
                        now=self.now())
                    conn.commit()
                    operation_id = record["operation_id"]
                # SIGTERM is handled by Capture: finish the current window. The
                # subscriber's graceful stop flushes its already accepted buffer.
                for unit in (CAPTURE, SUBSCRIBER):
                    stopped.append(unit)
                    self.system.stop(unit)
                deadline, last_reason = self.system.monotonic() + timeout, "drain pending"
                while self.system.monotonic() <= deadline:
                    try:
                        with connection(self.database) as conn:
                            conn.execute("BEGIN IMMEDIATE")
                            self.core.finalize_stop(conn, operation_id, now=self.now(),
                                                    capture_policy=self.capture_policy)
                            conn.rollback()  # readiness probe is never the READY commit
                        break
                    except self.core.PlannedMaintenanceError as exc:
                        last_reason = str(exc)
                        self.system.sleep(1)
                else:
                    raise MaintenanceHold(f"shutdown drain timed out: {last_reason}")
                for unit in STOP_AFTER_DRAIN:
                    # Stop timer and oneshot even when it was initially idle.
                    stopped.append(unit)
                    self.system.stop(unit)
                with self.protected(), connection(self.database) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    record = self.core.finalize_stop(conn, operation_id, now=self.now(),
                                                    capture_policy=self.capture_policy)
                    conn.commit()
                return {"result": "READY", "operation": record,
                        "message": "drained and sealed; administrator may now shut down the OS"}
            except BaseException as exc:
                failures = []
                cancellation_reason = str(exc).strip() or f"{type(exc).__name__} interrupted planned shutdown"
                if operation_id:
                    try:
                        with connection(self.database) as conn:
                            conn.execute("BEGIN IMMEDIATE")
                            self.core.cancel_stop(conn, operation_id, reason=cancellation_reason, now=self.now())
                            conn.commit()
                    except Exception as cancel_error:
                        failures.append(f"approval cancellation failed: {cancel_error}")
                # Cancel before restarting Capture so its new Session can never
                # silently reuse a partially prepared approval.
                for unit in reversed(stopped):
                    if original[unit]:
                        try:
                            self.system.start(unit)
                        except Exception as restore_error:
                            failures.append(f"service restoration failed ({unit}): {restore_error}")
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise MaintenanceHold(f"{exc}; {'; '.join(failures) or 'original active services restored'}") from exc

    def progress_snapshot(self, target_session_id, required):
        with connection(self.database, readonly=True) as conn:
            conn.execute("BEGIN")
            if self.running_session(conn) != target_session_id:
                raise MaintenanceHold("capture session changed during post-resume verification")
            failed = conn.execute(
                "SELECT COUNT(*) FROM packet_capture_segments seg JOIN packet_capture_sessions ses "
                "ON ses.id=seg.capture_session_id WHERE ses.session_id=? AND seg.status='FAILED'",
                (target_session_id,)).fetchone()[0]
            if failed:
                raise MaintenanceHold("new failed capture segment requires incident recovery")
            snapshot = {}
            for name, source in required:
                row = conn.execute("SELECT last_processed_id,last_completed_window_end FROM detector_checkpoints "
                                   "WHERE detector_name=? AND source_table=?", (name, source)).fetchone()
                if not row or not row[1]:
                    raise MaintenanceHold(f"checkpoint is not initialized: {name}+{source}")
                snapshot[name + "+" + source] = {"id": row[0], "boundary": row[1]}
            return snapshot

    def verify_progress(self, target_session_id, required, *, timeout=120):
        before = self.progress_snapshot(target_session_id, required)
        evidence, deadline = [], self.system.monotonic() + timeout
        while self.system.monotonic() <= deadline:
            if not all(self.system.active(unit) for unit in (CAPTURE, SUBSCRIBER, *DRAIN_SERVICES)):
                raise MaintenanceHold("required runtime service stopped during post-resume verification")
            after = self.progress_snapshot(target_session_id, required)
            advanced = all(after[key]["boundary"] > prior["boundary"] and
                           (prior["id"] is None or
                            (after[key]["id"] is not None and after[key]["id"] >= prior["id"]))
                           for key, prior in before.items())
            fresh = all(0 <= (self.now() - parse_db_utc(row["boundary"])).total_seconds() <= 45
                        for row in after.values())
            if advanced and fresh:
                evidence.append(after)
                before = after
                if len(evidence) == 2:
                    return {"result": "PASS", "snapshots": evidence}
            self.system.sleep(1)
        return {"result": "WAIT", "reason": "required checkpoints have not advanced twice",
                "snapshots": evidence}

    def resume(self, *, operation_id=None, artifact_dir, timeout=120, verify_timeout=120):
        self.system.require_admin()
        self.require_deployment()
        required = self.required_checkpoints()
        with single_instance_lock(self.command_lock, wait_seconds=0):
            deadline, last_reason, prior = self.system.monotonic() + timeout, "preparing", False
            while True:
                try:
                    with connection(self.database, readonly=True) as conn:
                        conn.execute("BEGIN")
                        record = self.latest(conn, operation_id)
                        if not record:
                            return {"result": "WAIT", "reason": "no planned shutdown approval"}
                        operation_id = record["operation_id"]
                        if record["status"] in ("READY", "RESUMED"):
                            stored = json.loads(record["checkpoint_snapshot_json"])
                            if {(name, row["source_table"]) for name, row in stored.items()} != set(required):
                                raise ConsumedApprovalHold("required stage profile changed since shutdown approval")
                        if record["status"] == "RESUMED":
                            if (self.system.boot_id() != record["target_boot_id"] or
                                self.running_session(conn) != record["target_session_id"]):
                                raise ConsumedApprovalHold("consumed approval belongs to another boot or Session; strict recovery required")
                            audit = self.core.get_resume_audit(conn, operation_id)
                            prior_target = record["target_session_id"]
                            prior = True
                            break
                        plan = self.core.inspect_resume(
                            conn, operation_id, target_session_id=self.running_session(conn),
                            current_boot_id=self.system.boot_id(),
                            time_synchronized=self.system.synchronized(), now=self.now())
                    break
                except ConsumedApprovalHold as exc:
                    return {"result": "HOLD", "operation_id": operation_id, "reason": str(exc)}
                except (MaintenanceHold, self.core.PlannedMaintenanceError) as exc:
                    last_reason = str(exc)
                    if self.system.monotonic() >= deadline:
                        return {"result": "WAIT", "operation_id": operation_id, "reason": last_reason}
                    self.system.sleep(1)
            if prior:
                try:
                    progress = self.verify_progress(prior_target, required, timeout=verify_timeout)
                except Exception as exc:
                    progress = {"result": "HOLD", "reason": str(exc)}
                return {"result": "ALREADY_RESUMED" if progress["result"] == "PASS" else "COMMITTED_HOLD",
                        "operation_id": operation_id, "audit": audit, "verification": progress}
            # No subscriber/Capture stop, no BEGIN IMMEDIATE during this work.
            if isinstance(self.system, SystemOperations):
                artifact_dir = safety.validate_generated_path(self.root, artifact_dir, field_name="artifact_dir")
            evidence = self.backup(self.database, Path(artifact_dir))
            with connection(Path(evidence["backup_path"]), readonly=True) as saved:
                saved.execute("BEGIN")
                saved_plan = self.core.inspect_resume(
                    saved, operation_id, target_session_id=plan["target_session_id"],
                    current_boot_id=plan["target_boot_id"], time_synchronized=True, now=self.now())
                if saved_plan["plan_sha256"] != plan["plan_sha256"]:
                    raise MaintenanceHold("backup does not match the bound resume plan")
            orchestrator_active, committed = self.system.active("detection-orchestrator.service"), False
            apply_error, restore_error = None, None
            try:
                # Its --loop owns the lock for the service lifetime. Release it
                # gracefully; subscriber and Capture continue throughout resume.
                if orchestrator_active:
                    self.system.stop("detection-orchestrator.service")
                with self.protected():
                    if self.system.boot_id() != plan["target_boot_id"] or not self.system.synchronized():
                        raise MaintenanceHold("boot identity or time synchronization changed before apply")
                    with connection(self.database) as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        result = self.core.apply_resume(conn, plan, now=self.now(), **evidence)
                        conn.commit()
                        committed = True
            except BaseException as exc:
                apply_error = exc
            finally:
                if orchestrator_active:
                    try:
                        self.system.start("detection-orchestrator.service")
                    except Exception as exc:
                        restore_error = exc
            if restore_error and committed:
                return {"result": "COMMITTED_HOLD", "operation_id": operation_id,
                        "audit": result, "reason": f"orchestrator restoration failed: {restore_error}"}
            if apply_error:
                # A lost response after commit is ambiguous until the persisted
                # approval and audit are inspected. Never rerun the transition.
                with connection(self.database, readonly=True) as inspected:
                    record = self.core.get_operation(inspected, operation_id)
                    if record["status"] == "RESUMED":
                        return {"result": "COMMITTED_HOLD", "operation_id": operation_id,
                                "audit": self.core.get_resume_audit(inspected, operation_id),
                                "reason": f"apply response failed: {apply_error}; restore error: {restore_error}"}
                if restore_error:
                    raise MaintenanceHold(f"{apply_error}; orchestrator restoration failed: {restore_error}") from apply_error
                raise apply_error
            # A verification HOLD after commit must never cancel/reapply the pair.
            try:
                progress = self.verify_progress(plan["target_session_id"], required,
                                                timeout=verify_timeout)
            except Exception as exc:
                progress = {"result": "HOLD", "reason": str(exc)}
            return {"result": "RESUMED" if progress["result"] == "PASS" else "COMMITTED_HOLD",
                    "operation_id": operation_id, "audit": result, "verification": progress}


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, default=Path("backend/data/iot_security.db"))
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[2])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "dry-run", "resume"):
        child = commands.add_parser(name)
        child.add_argument("--operation-id")
        if name == "resume":
            child.add_argument("--artifact-dir", type=Path, default=Path("data/recovery/planned"))
            child.add_argument("--timeout", type=float, default=120)
            child.add_argument("--verify-timeout", type=float, default=120)
    prepare = commands.add_parser("prepare-stop")
    prepare.add_argument("--approved-by", required=True)
    prepare.add_argument("--reason", required=True)
    prepare.add_argument("--timeout", type=float, default=180)
    cancel = commands.add_parser("cancel")
    cancel.add_argument("--operation-id", required=True)
    cancel.add_argument("--reason", required=True)
    return parser


def main(argv: Sequence[str] | None = None):
    args = build_parser().parse_args(argv)
    if args.command in ("prepare-stop", "resume", "cancel") and os.name == "posix":
        def interrupted(_signal, _frame):
            raise KeyboardInterrupt("maintenance command interrupted; inspect approval and audit")
        signal.signal(signal.SIGTERM, interrupted)
    try:
        if hasattr(args, "timeout") and not 0 <= args.timeout <= 600:
            raise MaintenanceHold("timeout must be between 0 and 600 seconds")
        if hasattr(args, "verify_timeout") and not 0 <= args.verify_timeout <= 600:
            raise MaintenanceHold("verify timeout must be between 0 and 600 seconds")
        runner = MaintenanceRunner(args.db_path, args.repository_root)
        if args.command == "prepare-stop":
            result = runner.prepare_stop(approved_by=args.approved_by, reason=args.reason, timeout=args.timeout)
        elif args.command == "resume":
            result = runner.resume(operation_id=args.operation_id, artifact_dir=args.artifact_dir,
                                   timeout=args.timeout, verify_timeout=args.verify_timeout)
        elif args.command == "dry-run":
            result = runner.dry_run(args.operation_id)
        elif args.command == "cancel":
            result = runner.cancel(args.operation_id, reason=args.reason)
        else:
            result = runner.status(args.operation_id)
    except Exception as exc:
        result = {"result": "HOLD", "reason": str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if result.get("result") not in ("WAIT", "HOLD", "COMMITTED_HOLD") else 2


if __name__ == "__main__":
    raise SystemExit(main())
