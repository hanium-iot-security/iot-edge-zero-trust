import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from db.migration_runner import apply_migrations
from edge.maintenance.storage_inventory import inventory, main
from edge.maintenance import storage_inventory


SESSION = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def source(tmp_path):
    db = tmp_path / "source.db"
    apply_migrations(db)
    with sqlite3.connect(db) as conn:
        conn.execute("""INSERT INTO packet_capture_sessions
            (session_id,capture_interface,started_at,status) VALUES (?,'eth0','2026-10-13T00:00:00Z','RUNNING')""", (SESSION,))
        conn.execute("""INSERT INTO packet_capture_segments
            (capture_session_id,file_name,capture_interface,window_start,window_end,status)
            VALUES (1,'capture.pcap','eth0','2026-10-13T00:00:00Z','2026-10-13T00:00:10Z','PROCESSED')""")
    processed = tmp_path / "data/pcap/processed/capture.pcap"
    processed.parent.mkdir(parents=True)
    processed.write_bytes(b"test capture")
    sidecar = tmp_path / "data/pcap/ready/capture.pcap.capture.json"
    sidecar.parent.mkdir()
    sidecar.write_text(json.dumps({"session_id": SESSION}), encoding="utf-8")
    return tmp_path, db, processed, sidecar


def by_path(report, path):
    return next(row for row in report["items"] if row["path"] == str(path))


def test_links_processed_pcap_to_ready_sidecar_and_preserves_originals(source):
    root, db, pcap, sidecar = source
    before = {path: path.read_bytes() for path in (db, pcap, sidecar)}
    result = inventory(root, db)
    row = by_path(result, pcap)
    assert row["paired_paths"] == [str(sidecar)]
    assert row["session_id"] == SESSION
    assert row["window_start"] == "2026-10-13T00:00:00Z"
    assert "SESSION_NOT_COMPLETED" in row["retention_reasons"]
    assert by_path(result, sidecar)["category"] == "sidecar"
    assert result["scan_complete"]
    assert result["cleanup_status"] == "HOLD" and not result["deletion_supported"]
    assert result["capacity"]["status"] == "UNKNOWN"
    assert result["totals_bytes"]["database"] == db.stat().st_size
    assert {path: path.read_bytes() for path in before} == before


def test_manifest_references_and_full_hash_copy_are_reported_but_not_deletable(source):
    root, db, pcap, _ = source
    refs, copies = root / "manifests", root / "backup"
    refs.mkdir()
    copies.mkdir()
    copied = copies / pcap.name
    copied.write_bytes(pcap.read_bytes())
    manifest = refs / "candidate.json"
    manifest.write_text(json.dumps({"training_approved": False,
        "capture_artifacts": [{"pcap_path": "../data/pcap/processed/capture.pcap"}],
        "source_capture_group_id": SESSION}), encoding="utf-8")
    result = inventory(root, db, reference_roots=[refs], backup_roots=[copies])
    row = by_path(result, pcap)
    assert str(manifest) in row["references"]
    assert row["sha256"] == hashlib.sha256(pcap.read_bytes()).hexdigest()
    assert row["verified_copy_paths"] == [str(copied)]
    assert row["cleanup_status"] == "HOLD"
    assert not result["reference_protection_complete"]


def test_completed_and_unreferenced_files_still_hold(source):
    root, db, pcap, _ = source
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE packet_capture_sessions SET status='COMPLETED'")
    unknown = pcap.parent / "unknown.pcap"
    unknown.write_bytes(b"unknown")
    result = inventory(root, db)
    assert by_path(result, pcap)["session_status"] == "COMPLETED"
    assert "SESSION_UNKNOWN" in by_path(result, unknown)["retention_reasons"]
    assert all(row["cleanup_status"] == "HOLD" for row in result["items"])


def test_incoming_and_temporary_files_not_hashed(source):
    root, db, _, _ = source
    incoming = root / "data/pcap/incoming/live.pcap.tmp"
    incoming.parent.mkdir()
    incoming.write_bytes(b"still writing")
    row = by_path(inventory(root, db), incoming)
    assert row["sha256"] is None
    assert "LIVE_FILE_HASH_NOT_TAKEN" in row["retention_reasons"]


@pytest.mark.parametrize("content", ["not json", "{}"])
def test_unreadable_or_unsupported_references_are_not_complete(source, content):
    root, db, _, _ = source
    refs = root / "references"
    refs.mkdir()
    (refs / ("invalid.json" if content == "not json" else "unsupported.yaml")).write_text(content)
    result = inventory(root, db, reference_roots=[refs])
    assert not result["scan_complete"]
    assert result["errors"][0]["reason"] == "REFERENCE_CHECK_FAILED"


def test_missing_database_is_not_created(source):
    root, _, _, _ = source
    missing = root / "missing.db"
    report = inventory(root, missing)
    assert not missing.exists()
    assert not report["scan_complete"]
    assert any(row["reason"] == "DATABASE_REFERENCE_CHECK_FAILED" for row in report["errors"])


def test_only_default_snapshot_root_is_optional(source, capsys):
    root, db, _, _ = source
    assert not (root / "data/runtime").exists()
    assert inventory(root, db)["scan_complete"]
    missing = root / "operator-snapshots"
    report = inventory(root, db, snapshot_roots=[missing])
    assert not report["scan_complete"]
    assert {"path": str(missing), "reason": "PATH_NOT_FOUND"} in report["errors"]
    assert report["cleanup_status"] == "HOLD"
    assert main(["inventory", "--project-root", str(root), "--database", str(db),
                 "--snapshot-root", str(missing)]) == 2
    assert not json.loads(capsys.readouterr().out)["scan_complete"]


def test_maintenance_session_and_backup_references_are_included(source):
    root, db, pcap, _ = source
    with sqlite3.connect(db) as conn:
        conn.execute("""INSERT INTO planned_maintenance_operations
            (operation_id,status,approved_by,reason,source_session_id,source_boot_id,
             required_checkpoints_json,requested_at)
            VALUES ('test','REQUESTED','operator','test',?,'boot','[]','2026-10-13T00:00:20Z')""", (SESSION,))
        conn.execute("""INSERT INTO planned_maintenance_resumes
            (operation_id,target_session_id,target_boot_id,plan_sha256,plan_json,
             backup_path,backup_sha256,resumed_at)
            VALUES ('test',?,'boot',?,'{}',?,?,'2026-10-13T00:00:30Z')""",
            (SESSION, "a" * 64, str(pcap), "b" * 64))
    refs = by_path(inventory(root, db), pcap)["references"]
    assert "db:planned_maintenance_operations.source_session_id" in refs
    assert "db:planned_maintenance_resumes.backup_path" in refs


def test_reference_non_json_is_not_read_or_hashed(source, monkeypatch):
    root, db, _, _ = source
    refs = root / "references"
    refs.mkdir()
    csv = refs / "large.csv"
    csv.write_bytes(b"skip content")
    original_hash = storage_inventory._hash
    def checked_hash(path):
        assert path != csv
        return original_hash(path)
    monkeypatch.setattr(storage_inventory, "_hash", checked_hash)
    row = by_path(inventory(root, db, reference_roots=[refs]), csv)
    assert row["sha256"] is None
    assert "UNSUPPORTED_REFERENCE_FORMAT" in row["retention_reasons"]


def test_wal_committed_metadata_visible_without_database_or_wal_mutation(source):
    root, db, pcap, _ = source
    writer = sqlite3.connect(db)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("UPDATE packet_capture_sessions SET status='COMPLETED'")
        writer.commit()
        wal = Path(str(db) + "-wal")
        before = (db.read_bytes(), wal.read_bytes())
        report = inventory(root, db)
        assert by_path(report, pcap)["session_status"] == "COMPLETED"
        assert by_path(report, wal)["sha256"] is None
        assert before == (db.read_bytes(), wal.read_bytes())
    finally:
        writer.close()


def test_limit_marks_partial_and_space_budget_holds(source):
    root, db, _, _ = source
    result = inventory(root, db, max_files=1, planned_bytes=10**30, snapshot_bytes=0, reserve_bytes=0)
    assert len(result["items"]) == 1
    assert not result["scan_complete"]
    assert result["capacity"]["status"] == "HOLD"


def test_file_limit_stops_directory_enumeration(source, monkeypatch):
    root, db, _, _ = source
    captures = root / "many-captures"
    captures.mkdir()
    for index in range(200):
        (captures / f"capture-{index}.pcap").write_bytes(b"capture")
    original_scandir = storage_inventory.os.scandir
    consumed = []

    @contextmanager
    def counted_scandir(path):
        with original_scandir(path) as entries:
            def counted_entries():
                for entry in entries:
                    if Path(path) == captures:
                        consumed.append(entry.name)
                    yield entry
            yield counted_entries()

    monkeypatch.setattr(storage_inventory.os, "scandir", counted_scandir)
    result = inventory(root, db, pcap_root=captures, max_files=1)
    assert 1 <= len(consumed) <= 2
    assert len(result["items"]) == 1
    assert not result["scan_complete"]
    assert {"path": str(captures), "reason": "FILE_LIMIT_REACHED"} in result["errors"]


def test_growth_only_for_same_complete_scan(source):
    root, db, pcap, _ = source
    now = datetime.now(timezone.utc)
    first = inventory(root, db, now=now)
    pcap.write_bytes(pcap.read_bytes() + b"123")
    second = inventory(root, db, previous=first, now=now + timedelta(seconds=5))
    assert second["growth_bytes"]["pcap"] == 3
    with pytest.raises(ValueError, match="same roots"):
        inventory(root, db, previous=first, reference_roots=[root / "missing"], now=now + timedelta(seconds=5))


def test_cli_only_previews_and_never_accepts_delete(source, capsys):
    root, db, _, _ = source
    assert main(["cleanup-dry-run", "--project-root", str(root), "--database", str(db)]) == 0
    assert json.loads(capsys.readouterr().out)["deletion_supported"] is False
    with pytest.raises(SystemExit):
        main(["cleanup", "--database", str(db)])


def test_symlink_is_not_followed(source):
    root, db, pcap, _ = source
    linked = pcap.parent / "linked.pcap"
    try:
        linked.symlink_to(pcap)
    except OSError:
        pytest.skip("Host does not allow symlinks")
    result = inventory(root, db)
    assert not result["scan_complete"]
    assert not any(row["path"] == str(linked) for row in result["items"])
    assert any(row["reason"] == "LINK_NOT_FOLLOWED" for row in result["errors"])
