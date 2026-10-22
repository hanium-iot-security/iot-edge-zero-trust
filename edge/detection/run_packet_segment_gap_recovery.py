"""Explicit, audited recovery of one lost Packet capture window (POSIX execute)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
from typing import Sequence
import uuid
from dataclasses import asdict

from dotenv import dotenv_values

from backend.app.config import Settings
from edge.detection import packet_checkpoint_recovery as safety
from edge.detection import segment_gap_source_scope as source_scope
from edge.packet import segment_gap_recovery as recovery
from edge.runtime_lock import RuntimeLockError

CONFIRMATION = "APPLY-PACKET-SEGMENT-GAP"


class CommittedRecoveryError(RuntimeError):
    """The recovery committed; stop and inspect instead of restoring automatically."""


def _implementation_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _regular_hash(path: Path) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("evidence must be a regular file, not a symlink")
    return safety._sha256_open_regular_file(path, before)


def _read_plan(path: Path) -> tuple[dict, tuple]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("plan must be a regular file, not a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("plan file changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("plan is too large")
        plan = json.loads(content)
        if not isinstance(plan, dict):
            raise ValueError("plan must be an object")
        return plan, (opened.st_dev, opened.st_ino, hashlib.sha256(content).hexdigest())
    finally:
        os.close(descriptor)


def _require_distinct_paths(paths: list[Path]) -> None:
    # Runtime locks truncate their file after acquisition; aliases must be
    # rejected before touching locks or any reviewed evidence.
    for index, first in enumerate(paths):
        for second in paths[index + 1:]:
            if first.resolve() == second.resolve() or (
                first.exists() and second.exists() and os.path.samefile(first, second)
            ):
                raise ValueError(f"recovery paths must be distinct: {first} and {second}")


def _operation_paths(database: Path, plan: Path, backup: Path, locks, evidence: list[dict]) -> list[Path]:
    return [database, Path(str(database) + "-wal"), Path(str(database) + "-shm"),
            Path(str(database) + "-journal"), plan, backup,
            backup.with_suffix(backup.suffix + ".sha256"), backup.parent / "result.json",
            *[lock.path for lock in locks],
            *[Path(item[key]) for item in evidence for key in ("source", "preserved")]]


def _private_json(path: Path, payload: dict) -> None:
    # Do not overwrite a reviewed plan or an earlier result.
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro" if readonly else str(path), uri=readonly,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _resolved_locks(root: Path, database: Path):
    # The orchestrator may have a non-default lock in the deployed .env.
    configured = dotenv_values(root / ".env").get("ORCHESTRATOR_LOCK_PATH") or ""
    if os.environ.get("ORCHESTRATOR_LOCK_PATH", configured).strip() != configured.strip():
        raise ValueError("shell lock override differs from the deployment .env")
    settings = Settings(_env_file=root / ".env", orchestrator_lock_path=configured)
    return safety.resolve_recovery_locks(
        repository_root=root,
        database_url=f"sqlite:///{database.as_posix()}",
        orchestrator_lock_path=(
            Path(settings.orchestrator_lock_path)
            if settings.orchestrator_lock_path.strip() else None
        ),
        manual_lock_path=None,
        extractor_lock_path=None,
    )


def _preserve(source: Path, destination: Path) -> str:
    digest = _regular_hash(source)
    # Hash through the already-open descriptor too; refuse changed evidence.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(source, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("evidence is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as incoming:
            with destination.open("xb") as outgoing:
                os.chmod(destination, 0o600)
                while chunk := incoming.read(1024 * 1024):
                    outgoing.write(chunk)
    finally:
        os.close(descriptor)
    if _regular_hash(destination) != digest or _regular_hash(source) != digest:
        raise ValueError("capture evidence changed while preserving it")
    return digest


def dry_run(args: argparse.Namespace) -> dict:
    return _dry_run(args, chain=False)


def dry_run_chain(args: argparse.Namespace) -> dict:
    return _dry_run(args, chain=True)


def _dry_run(args: argparse.Namespace, *, chain: bool) -> dict:
    root = Path(args.repository_root).resolve(strict=True)
    if root != _implementation_root():
        raise ValueError("repository_root must be the executing implementation checkout")
    database = safety.resolve_database_path(args.db_path)
    repository = safety.inspect_repository_state(root)
    plan_output = safety.validate_generated_path(root, args.plan_output, field_name="plan_output")
    safety.require_existing_parent(plan_output, field_name="plan_output")
    if plan_output.exists():
        raise ValueError("plan output already exists")
    artifacts = safety.validate_generated_path(root, args.artifact_dir, field_name="artifact_dir")
    safety.require_existing_directory(artifacts, field_name="artifact_dir")
    ids = args.failed_segment_ids if chain else [args.failed_segment_id]
    paths = args.pcap_paths if chain else [args.pcap_path]
    if chain and (not 2 <= len(ids) <= 3 or len(paths) != len(ids) or len(set(ids)) != len(ids)):
        raise ValueError("an exact two- or three-Window ID/PCAP list is required")
    sources = [Path(path).absolute() for path in paths]
    operation_dir = artifacts / str(uuid.uuid4())
    locks = _resolved_locks(root, database)
    safety.validate_generated_paths(repository_root=root, lock_paths=[lock.path for lock in locks])
    # Read-only transaction gives the plan one DB snapshot. Dry-run changes only
    # private evidence/plan files, never capture status or checkpoints.
    with _connect(database, readonly=True) as connection:
        connection.execute("BEGIN")
        for segment_id, source in zip(ids, sources):
            segment = connection.execute(
                "SELECT file_name FROM packet_capture_segments WHERE id=?", (segment_id,)
            ).fetchone()
            if segment is None or source.name != segment["file_name"]:
                raise ValueError("PCAP filename does not match the failed segment")
        operation_dir.mkdir(mode=0o700)
        evidence, pcaps = [], []
        for source in sources:
            preserved = operation_dir / source.name
            digest = _preserve(source, preserved)
            evidence.append({"source": str(source), "preserved": str(preserved), "sha256": digest})
            pcaps.append({"path": str(preserved), "sha256": digest})
            sidecar = source.with_suffix(source.suffix + ".capture.json")
            if sidecar.exists() or sidecar.is_symlink():
                saved_sidecar = operation_dir / sidecar.name
                evidence.append({"source": str(sidecar), "preserved": str(saved_sidecar),
                                 "sha256": _preserve(sidecar, saved_sidecar)})
        _require_distinct_paths(_operation_paths(database, plan_output, operation_dir / "database.backup.db", locks, evidence))
        selection = ({"failed_segment_ids": ids, "preserved_pcaps": pcaps} if chain else {
            "failed_segment_id": ids[0], "preserved_pcap_path": pcaps[0]["path"], "pcap_sha256": pcaps[0]["sha256"],
        })
        builder = recovery.build_segment_gap_chain_plan if chain else recovery.build_segment_gap_plan
        plan = builder(
            connection, capture_session_id=args.capture_session_id, **selection, approved_by=args.approved_by,
            reason=args.reason, repository_commit=repository["repository_commit"],
            database_path=str(database), backup_path=str(operation_dir / "database.backup.db"),
        )
        if chain and args.allow_source_appends:
            deployment = _deployment_binding(root)
            from edge.packet.capture_policy import CapturePolicy
            plan.update(execution_mode=source_scope.EXECUTION_MODE,
                        source_scope=source_scope.build_source_scope(
                            connection, plan, capture_policy=CapturePolicy(**deployment["capture_policy"])),
                        deployment_binding=deployment)
    plan.update(repository_root=str(root), repository_state=repository,
                locks=list(safety.serialize_resolved_locks(locks)), evidence=evidence)
    plan["plan_sha256"] = recovery.calculate_plan_sha256(plan)
    _private_json(plan_output, plan)
    return {"ok": True, "database_committed": False, "plan_file": str(plan_output),
            "plan_sha256": plan["plan_sha256"], **({"failed_segment_ids": ids} if chain else {"failed_segment_id": ids[0]}),
            "window_start": plan["window_start"], "window_end": plan["window_end"]}


def _verify_evidence(plan: dict) -> None:
    evidence = plan.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("plan has no retained capture evidence")
    for binding in _pcap_bindings(plan):
        matches = [item for item in evidence if item.get("preserved") == binding["preserved_pcap_path"]
                   and item.get("sha256") == binding["pcap_sha256"]]
        if len(matches) != 1:
            raise ValueError("PCAP evidence does not match the plan")
    for item in evidence:
        for key in ("source", "preserved"):
            if _regular_hash(Path(item[key])) != item["sha256"]:
                raise ValueError("capture evidence changed since plan approval")


def _validate_envelope(plan: dict) -> None:
    recovery.verify_segment_gap_plan(plan)
    if not isinstance(plan.get("repository_root"), str) or not Path(plan["repository_root"]).is_absolute():
        raise ValueError("repository_root must be absolute")
    state = plan.get("repository_state")
    if not isinstance(state, dict) or state.get("repository_root") != plan["repository_root"] or state.get("repository_commit") != plan["repository_commit"]:
        raise ValueError("repository evidence does not match the plan")
    if not isinstance(plan.get("locks"), list):
        raise ValueError("runtime lock evidence is required")
    if any(key in plan for key in ("execution_mode", "source_scope", "deployment_binding")):
        if plan["schema_version"] != recovery.CHAIN_PLAN_SCHEMA_VERSION or plan.get("execution_mode") != source_scope.EXECUTION_MODE:
            raise ValueError("source append execution is only supported for an explicit chain")
        source_scope.validate_source_scope_envelope(plan.get("source_scope"))
        if not isinstance(plan.get("deployment_binding"), dict):
            raise ValueError("source append deployment binding is required")
        if plan["deployment_binding"].get("capture_policy") != plan["source_scope"]["capture_policy"]:
            raise ValueError("source scope Capture policy differs from its deployment")
        if plan["source_scope"]["capture_session_pk"] != plan["failed_segments"][0]["failed_segment"]["capture_session_id"]:
            raise ValueError("source scope differs from the approved capture")
        if (plan["source_scope"]["recovery_input_start"] != plan["window_start"]
                or plan["source_scope"]["recovery_input_end"] != plan["window_end"]
                or plan["source_scope"]["tail_start"] < plan["window_end"]):
            raise ValueError("source scope differs from the approved recovery window")
    evidence = plan.get("evidence")
    bindings = _pcap_bindings(plan)
    if not isinstance(evidence, list) or not len(bindings) <= len(evidence) <= 2 * len(bindings):
        raise ValueError("PCAP and optional sidecar evidence envelope is required")
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"source", "preserved", "sha256"}:
            raise ValueError("capture evidence envelope is invalid")
        for key in ("source", "preserved"):
            if not isinstance(item[key], str) or not Path(item[key]).is_absolute():
                raise ValueError("capture evidence paths must be absolute")
        digest = item["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("capture evidence SHA256 is invalid")
    if plan["schema_version"] == recovery.CHAIN_PLAN_SCHEMA_VERSION:
        remaining = list(evidence)
        for binding in bindings:
            if not remaining:
                raise ValueError("PCAP evidence does not match the chain")
            pcap = remaining.pop(0)
            if pcap["preserved"] != binding["preserved_pcap_path"] or pcap["sha256"] != binding["pcap_sha256"]:
                raise ValueError("PCAP evidence does not match the chain")
            if remaining and remaining[0]["source"] == pcap["source"] + ".capture.json":
                sidecar = remaining.pop(0)
                if sidecar["preserved"] != pcap["preserved"] + ".capture.json":
                    raise ValueError("sidecar evidence does not match its PCAP")
        if remaining:
            raise ValueError("chain contains unbound capture evidence")


def _pcap_bindings(plan: dict) -> list[dict]:
    return plan["failed_segments"] if plan["schema_version"] == recovery.CHAIN_PLAN_SCHEMA_VERSION else [plan]


def _deployment_binding(root: Path) -> dict:
    # Store digests only: .env and resolved Settings contain credentials. The
    # selected model bytes are bound even when they are untracked in Git.
    settings = Settings(_env_file=root / ".env")
    env_file = root / ".env"
    env_sha256 = _regular_hash(env_file) if env_file.exists() or env_file.is_symlink() else None
    resolved = settings.model_dump(mode="json")
    for field in ("mqtt_subscriber_password", "mqtt_test_tool_password", "recovery_admin_api_key"):
        resolved.pop(field, None)
    resolved_sha256 = hashlib.sha256(json.dumps(resolved, sort_keys=True,
                                               separators=(",", ":")).encode()).hexdigest()
    from edge.packet.capture_policy import CapturePolicy
    capture_policy = CapturePolicy(
        max_start_delay_seconds=settings.pcap_max_start_delay_seconds,
        minimum_duration_seconds=settings.packet_min_capture_duration_seconds,
        epsilon_seconds=settings.capture_time_epsilon_seconds, version=settings.capture_policy_version,
    )
    artifacts = {}
    if settings.packet_if_artifact_dir.strip():
        directory = Path(settings.packet_if_artifact_dir)
        if not directory.is_absolute():
            directory = root / directory
        from ai.packet_if_contract import (
            PACKET_IF_METADATA_FILENAME, PACKET_IF_MODEL_FILENAME, PACKET_IF_TRAINING_REPORT_FILENAME,
        )
        for name in (PACKET_IF_METADATA_FILENAME, PACKET_IF_MODEL_FILENAME, PACKET_IF_TRAINING_REPORT_FILENAME):
            path = directory / name
            artifacts[str(path.absolute())] = _regular_hash(path)
    return {"env_sha256": env_sha256, "resolved_settings_sha256": resolved_sha256,
            "capture_policy": asdict(capture_policy), "packet_if_artifacts": artifacts}


def _execute(args: argparse.Namespace, commit_state: list[bool]) -> dict:
    safety.require_execute_platform(os.name)
    if args.confirm != CONFIRMATION:
        raise ValueError(f"execute requires --confirm {CONFIRMATION}")
    plan_path = Path(args.plan_file).absolute()
    plan, plan_identity = _read_plan(plan_path)
    if not isinstance(plan, dict) or recovery.calculate_plan_sha256(plan) != plan.get("plan_sha256"):
        raise ValueError("plan SHA256 mismatch")
    _validate_envelope(plan)
    database = safety.require_plan_database_path(plan, args.db_path)
    root = Path(plan["repository_root"]).resolve(strict=True)
    if root != _implementation_root():
        raise ValueError("approved repository differs from the executing implementation")
    locks = _resolved_locks(root, database)
    if list(safety.serialize_resolved_locks(locks)) != plan["locks"]:
        raise ValueError("runtime lock configuration changed since approval")
    backup = Path(plan["backup_path"])
    result_path = backup.parent / "result.json"
    safety.validate_generated_paths(repository_root=root, artifact_dir=backup.parent,
                                    backup_path=backup, result_path=result_path,
                                    lock_paths=[lock.path for lock in locks])
    if result_path.exists():
        raise ValueError("result output already exists")
    _require_distinct_paths(_operation_paths(database, plan_path, backup, locks, plan["evidence"]))
    with safety.acquire_recovery_locks(locks):
        if safety.inspect_repository_state(root) != plan["repository_state"]:
            raise ValueError("repository changed since plan approval")
        _verify_evidence(plan)
        online = plan.get("execution_mode") == source_scope.EXECUTION_MODE
        if online and _deployment_binding(root) != plan["deployment_binding"]:
            raise ValueError("deployment settings/model changed since approval")
        with _connect(database) as connection:
            version = connection.execute("PRAGMA data_version").fetchone()[0]
            if online:
                connection.execute("BEGIN")
                source_scope.verify_source_scope(connection, plan["source_scope"])
                connection.rollback()
            artifact = safety.create_sqlite_backup(database, backup)
            os.chmod(backup, 0o600)
            os.chmod(artifact.sha256_path, 0o600)
            if artifact.integrity_check != "ok" or artifact.foreign_key_violations:
                raise ValueError("backup integrity/foreign-key check failed")
            if online:
                with _connect(backup, readonly=True) as retained:
                    retained.execute("BEGIN")
                    source_scope.verify_source_scope(retained, plan["source_scope"])
            connection.execute("BEGIN IMMEDIATE")
            if online:
                source_scope.verify_source_scope(connection, plan["source_scope"])
            elif connection.execute("PRAGMA data_version").fetchone()[0] != version:
                raise ValueError("database changed during backup; create a new plan")
            # Approval is checked again after backup and DB write-lock acquisition.
            if _read_plan(plan_path)[1] != plan_identity:
                raise ValueError("plan file changed during execution")
            _verify_evidence(plan)
            if safety.inspect_repository_state(root) != plan["repository_state"]:
                raise ValueError("repository changed during backup")
            if online and _deployment_binding(root) != plan["deployment_binding"]:
                raise ValueError("deployment settings/model changed during backup")
            audit = recovery.apply_segment_gap_plan(connection, plan, backup_sha256=artifact.sha256)
            connection.commit()
            commit_state[0] = True
        try:
            check = safety.verify_database(database)
            if check.integrity_check != "ok" or check.foreign_key_violations:
                raise ValueError("post-commit database check failed")
            result = {"ok": True, "database_committed": True,
                      "operation_id": audit["operation_id"],
                      **({"failed_segment_ids": [entry["failed_segment_id"] for entry in plan["failed_segments"]],
                          "audit_ids": [entry["id"] for entry in audit["audits"]], "coverage": plan["coverage"]}
                         if plan["schema_version"] == recovery.CHAIN_PLAN_SCHEMA_VERSION
                         else {"failed_segment_id": plan["failed_segment_id"]}),
                      "window_start": plan["window_start"], "window_end": plan["window_end"],
                      "plan_sha256": plan["plan_sha256"], "backup_sha256": artifact.sha256,
                      "backup_path": str(backup), "failed_segment_preserved": True}
            _private_json(result_path, result)
            return result
        except Exception as exc:
            raise CommittedRecoveryError(
                f"database committed; HOLD, inspect operation {plan['operation_id']} and backup {backup}; no automatic restore"
            ) from exc


def execute(args: argparse.Namespace) -> dict:
    commit_state = [False]
    try:
        return _execute(args, commit_state)
    except Exception as exc:
        if commit_state[0]:
            raise CommittedRecoveryError(
                f"database committed; HOLD and inspect plan {args.plan_file}, its Audit and backup; no automatic restore"
            ) from exc
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("dry-run", "dry-run-chain"):
        inspect = commands.add_parser(command)
        for name in ("db-path", "repository-root", "capture-session-id", "approved-by", "reason", "plan-output", "artifact-dir"):
            inspect.add_argument(f"--{name}", required=True)
        if command == "dry-run-chain":
            inspect.add_argument("--failed-segment-ids", type=int, nargs="+", required=True)
            inspect.add_argument("--pcap-paths", nargs="+", required=True)
            inspect.add_argument("--allow-source-appends", action="store_true",
                                 help="Bind frozen recovery inputs and permit only explicit live producer appends")
        else:
            inspect.add_argument("--failed-segment-id", type=int, required=True)
            inspect.add_argument("--pcap-path", required=True)
    apply = commands.add_parser("execute")
    for name in ("db-path", "plan-file", "confirm"):
        apply.add_argument(f"--{name}", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = {"dry-run": dry_run, "dry-run-chain": dry_run_chain, "execute": execute}[args.command](args)
    except CommittedRecoveryError as exc:
        print(json.dumps({"ok": False, "database_committed": True, "hold_required": True, "error": str(exc)}))
        return 3
    except (ValueError, RuntimeError, OSError, sqlite3.DatabaseError,
            subprocess.CalledProcessError, safety.PacketCheckpointRecoveryError, RuntimeLockError) as exc:
        print(json.dumps({"ok": False, "database_committed": False, "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
