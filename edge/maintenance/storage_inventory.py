"""Read-only storage inventory. A cleanup preview is never a deletion plan."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat


SCHEMA_VERSION = "storage-inventory-v1"
MAX_JSON_BYTES = 8 * 1024 * 1024


def _linked(path: Path) -> bool:
    # Windows junctions, including ancestors, must not expand the scan scope.
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            return True
    return False


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _hash(path: Path) -> str:
    if _linked(path):
        raise ValueError("LINK_NOT_FOLLOWED")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("NOT_REGULAR_FILE")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError("FILE_CHANGED")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError("FILE_CHANGED")
    if _linked(path) or _identity(path.stat()) != _identity(before):
        raise ValueError("FILE_CHANGED")
    return digest.hexdigest()


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _pcap_name(name):
    return name.removesuffix(".tmp").removesuffix(".capture.json")


def _read_database(path: Path, file_names):
    """Copy provenance for inventoried files; never read historical Feature data."""
    if _linked(path):
        raise ValueError("LINK_NOT_FOLLOWED")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        names = sorted(set(file_names))
        segments = []
        for offset in range(0, max(1, len(names)), 500):
            batch = names[offset:offset + 500]
            placeholders = ",".join("?" for _ in batch) or "NULL"
            segments.extend(dict(row) for row in db.execute(f"""
                SELECT g.file_name, g.status AS segment_status, g.id AS segment_id,
                       g.window_start, g.window_end,
                       s.session_id, s.status AS session_status, s.ended_at
                FROM packet_capture_segments g
                JOIN packet_capture_sessions s ON s.id = g.capture_session_id
                WHERE g.file_name IN ({placeholders})
            """, batch))
        references = []
        # Existing recovery audits contain paths and embedded plans. Never scan
        # raw MQTT payloads or load the large feature tables for this inventory.
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("trust_score_compensations", "packet_checkpoint_recoveries",
                      "packet_segment_gap_recoveries", "planned_maintenance_operations",
                      "planned_maintenance_resumes"):
            if table not in tables:
                continue
            columns = [row[1] for row in db.execute(f'PRAGMA table_info("{table}")')
                       if row[1].endswith(("_path", "_sha256", "_json", "_session_id"))]
            if not columns:
                continue
            fields = ", ".join('"' + name + '"' for name in columns)
            for row in db.execute(f'SELECT {fields} FROM "{table}"'):
                for name, value in zip(columns, row):
                    if not isinstance(value, str):
                        continue
                    values = _strings(json.loads(value)) if name.endswith("_json") else [value]
                    references.extend((item, f"db:{table}.{name}") for item in values)
        return segments, references


def inventory(project_root: Path, database: Path, *, pcap_root: Path | None = None,
              reference_roots=(), backup_roots=(), snapshot_roots=(), max_files=10000,
              planned_bytes=None, snapshot_bytes=None, reserve_bytes=None,
              previous=None, now=None):
    """Observe explicit roots without changing files, DB rows, or services.

    JSON string matching is deliberately conservative and cannot certify the
    absence of references in every manifest format. All deletion remains HOLD.
    """
    root = Path(os.path.abspath(project_root))
    database = Path(os.path.abspath(database))
    if type(max_files) is not int or max_files < 1:
        raise ValueError("max_files must be positive")
    budgets = (planned_bytes, snapshot_bytes, reserve_bytes)
    if any(value is not None and (type(value) is not int or value < 0) for value in budgets):
        raise ValueError("space budgets must be non-negative integers")
    observed = now or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        raise ValueError("now must include timezone")
    errors, records, seen = [], [], set()
    sources = [(pcap_root or root / "data/pcap", "pcap"),
               (database, "database"), (Path(str(database) + "-wal"), "wal"),
               (Path(str(database) + "-shm"), "wal")]
    sources += [(path, "reference") for path in reference_roots]
    sources += [(path, "backup") for path in backup_roots]
    sources += [(path, "snapshot") for path in (snapshot_roots or (root / "data/runtime",))]

    def visit(path, category):
        path = Path(os.path.abspath(path))
        if path in seen:
            return
        seen.add(path)
        try:
            info = path.lstat()
            if _linked(path):
                errors.append({"path": str(path), "reason": "LINK_NOT_FOLLOWED"})
                return
            if stat.S_ISDIR(info.st_mode):
                for child in sorted(path.iterdir()):
                    if len(records) >= max_files:
                        errors.append({"path": str(path), "reason": "FILE_LIMIT_REACHED"})
                        break
                    visit(child, category)
                return
            if not stat.S_ISREG(info.st_mode):
                errors.append({"path": str(path), "reason": "NOT_REGULAR_FILE"})
                return
            if len(records) >= max_files:
                errors.append({"path": str(path), "reason": "FILE_LIMIT_REACHED"})
                return
            kind = "sidecar" if category == "pcap" and ".capture.json" in path.name else category
            reasons = ["READ_ONLY_PREVIEW", "REFERENCE_PROTECTION_INCOMPLETE"]
            if category in ("database", "wal", "backup", "snapshot", "reference"):
                reasons.append("PRESERVE_" + category.upper())
            if category == "pcap":
                locations = set(path.relative_to(Path(os.path.abspath(pcap_root or root / "data/pcap"))).parts[:-1])
                reasons.extend("PRESERVE_" + value.upper() for value in sorted(locations & {"incoming", "ready", "failed", "samples"}))
            if path.name.endswith(".tmp"):
                reasons.append("IN_PROGRESS_FILE")
            digest = None
            if category == "reference" and (path.suffix != ".json" or info.st_size > MAX_JSON_BYTES):
                reasons.append("UNSUPPORTED_REFERENCE_FORMAT")
            elif category in ("database", "wal") or "IN_PROGRESS_FILE" in reasons or "PRESERVE_INCOMING" in reasons:
                reasons.append("LIVE_FILE_HASH_NOT_TAKEN")
            else:
                try:
                    digest = _hash(path)
                except (OSError, ValueError) as exc:
                    reasons.append(str(exc) if isinstance(exc, ValueError) else "FILE_READ_FAILED")
                    errors.append({"path": str(path), "reason": reasons[-1]})
            records.append({"path": str(path), "category": kind, "size_bytes": info.st_size,
                            "sha256": digest, "session_id": None, "session_status": None,
                            "segment_status": None, "retention_reasons": reasons,
                            "references": [], "verified_copy_paths": [],
                            "cleanup_status": "HOLD", "_identity": (info.st_dev, info.st_ino)})
        except FileNotFoundError:
            errors.append({"path": str(path), "reason": "PATH_NOT_FOUND"})
        except OSError:
            errors.append({"path": str(path), "reason": "PATH_READ_FAILED"})

    for path, category in sources:
        # WAL/SHM and the default runtime directory may legitimately not exist.
        if category in ("wal", "snapshot") and not Path(path).exists():
            continue
        visit(path, category)
    try:
        segments, reference_values = _read_database(database, [
            _pcap_name(Path(row["path"]).name) for row in records if row["category"] in ("pcap", "sidecar")])
    except (OSError, ValueError, RecursionError, sqlite3.Error):
        segments, reference_values = [], []
        errors.append({"path": str(database), "reason": "DATABASE_REFERENCE_CHECK_FAILED"})
    by_name = {row["file_name"]: row for row in segments}
    for record in records:
        if record["category"] == "reference":
            path = Path(record["path"])
            try:
                if path.suffix != ".json" or record["size_bytes"] > MAX_JSON_BYTES or not record["sha256"]:
                    raise ValueError("UNSUPPORTED_REFERENCE_FORMAT")
                payload = json.loads(path.read_text(encoding="utf-8"))
                if _hash(path) != record["sha256"]:
                    raise ValueError("REFERENCE_CHANGED")
                reference_values.extend((value, str(path)) for value in _strings(payload))
            except (OSError, ValueError, RecursionError):
                errors.append({"path": str(path), "reason": "REFERENCE_CHECK_FAILED"})
    references = defaultdict(set)
    for value, origin in reference_values:
        references[value].add(origin)
        references[value.replace("\\", "/").split("/")[-1]].add(origin)
    copies, pairs = defaultdict(list), defaultdict(list)
    for record in records:
        if record["category"] == "backup" and record["sha256"]:
            copies[record["sha256"]].append(record)
        if record["category"] in ("pcap", "sidecar"):
            pairs[_pcap_name(Path(record["path"]).name)].append(record["path"])
    for record in records:
        path = Path(record["path"])
        name = _pcap_name(path.name)
        segment = by_name.get(name) if record["category"] in ("pcap", "sidecar") else None
        if segment:
            record.update({key: segment[key] for key in ("session_id", "session_status", "segment_status", "window_start", "window_end")})
            record["references"].append(f"db:packet_capture_segments:{segment['segment_id']}")
            record["retention_reasons"].append("DATABASE_CAPTURE_REFERENCE")
            if segment["session_status"] != "COMPLETED":
                record["retention_reasons"].append("SESSION_NOT_COMPLETED")
            if segment["segment_status"] in ("READY", "FAILED"):
                record["retention_reasons"].append("PRESERVE_" + segment["segment_status"] + "_SEGMENT")
        elif record["category"] in ("pcap", "sidecar"):
            record["retention_reasons"].append("SESSION_UNKNOWN")
        for key in (str(path), path.name, name, record["sha256"], record["session_id"]):
            record["references"].extend(sorted(references.get(key, ())))
        record["references"] = sorted(set(record["references"]))
        if record["references"]:
            record["retention_reasons"].append("REFERENCED")
        record["verified_copy_paths"] = [copy["path"] for copy in copies[record["sha256"]]
                                         if copy["_identity"] != record["_identity"]]
        if not record["verified_copy_paths"]:
            record["retention_reasons"].append("NO_VERIFIED_COPY")
        record["paired_paths"] = [other for other in pairs[name] if other != str(path)] if record["category"] in ("pcap", "sidecar") else []
    for record in records:
        del record["_identity"]
    totals = Counter()
    for record in records:
        totals[record["category"]] += record["size_bytes"]
    required = sum(budgets) if all(value is not None for value in budgets) else None
    free = shutil.disk_usage(root).free
    growth = None
    scan_roots = [{"path": str(Path(os.path.abspath(path))), "category": category} for path, category in sources]
    if previous is not None:
        if (previous.get("schema_version") != SCHEMA_VERSION or previous.get("project_root") != str(root)
                or previous.get("scan_roots") != scan_roots
                or not previous.get("scan_complete") or errors
                or datetime.fromisoformat(previous["observed_at"]) >= observed):
            raise ValueError("growth requires earlier complete observations of the same roots")
        growth = {key: totals[key] - previous["totals_bytes"].get(key, 0)
                  for key in set(totals) | set(previous["totals_bytes"])}
    return {"schema_version": SCHEMA_VERSION, "observed_at": observed.isoformat(),
            "project_root": str(root), "read_only": True, "cleanup_status": "HOLD",
            "deletion_supported": False, "reference_protection_complete": False,
            "reference_scope": "DB capture/recovery metadata and explicit JSON roots; conservative matches only",
            "scan_roots": scan_roots, "scan_complete": not errors, "errors": errors, "totals_bytes": dict(totals),
            "growth_bytes": growth, "items": records,
            "capacity": {"volume_path": str(root), "free_bytes": free, "required_bytes": required,
                         "status": "UNKNOWN" if required is None else "PASS" if free >= required else "HOLD",
                         "scope": "project-root volume only; observation does not authorize capture"}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "cleanup-dry-run"))
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--pcap-root", type=Path)
    for name in ("reference", "backup", "snapshot"):
        parser.add_argument(f"--{name}-root", type=Path, action="append", default=[])
    parser.add_argument("--max-files", type=int, default=10000)
    for name in ("planned", "snapshot", "reserve"):
        parser.add_argument(f"--{name}-bytes", type=int)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args(argv)
    try:
        report = inventory(args.project_root, args.database, pcap_root=args.pcap_root,
                           reference_roots=args.reference_root, backup_roots=args.backup_root,
                           snapshot_roots=args.snapshot_root, max_files=args.max_files,
                           planned_bytes=args.planned_bytes, snapshot_bytes=args.snapshot_bytes,
                           reserve_bytes=args.reserve_bytes,
                           previous=json.loads(args.previous.read_text(encoding="utf-8")) if args.previous else None)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(2, f"Inventory unavailable: {type(exc).__name__}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["scan_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
