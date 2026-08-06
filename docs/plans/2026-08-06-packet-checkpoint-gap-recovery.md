# Packet Checkpoint Gap Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 운영자가 승인한 Packet Detector 하나의 Checkpoint 시간 경계를 지정한 COMPLETED Capture Session의 시작점으로 안전하게 전진시키고, 모든 사전조건·백업·변경·감사 결과를 결정적으로 증명하는 Dry-run/Execute CLI를 구현한다.

**Architecture:** `packet_checkpoint_recovery.py`가 Canonical Plan, Git/경로/Session/Lock Gate와 Execute 순서를 조정하고, `packet_checkpoint_recovery_repository.py`가 고정된 SQLite SELECT·조건부 UPDATE·Audit INSERT만 담당한다. Dry-run은 Windows와 POSIX에서 지원하지만, 상이한 Windows Lock 구현 사이의 상호배제를 증명할 수 없으므로 Execute는 POSIX에서만 허용한다. Migration 005는 별도 운영 단계로 적용하며, Execute는 검증된 Plan JSON을 같은 DB·Repository 상태에서 재생성한 뒤 Checkpoint 1건과 Audit 1건만 단일 Transaction으로 변경한다. 기존 Manual Packet Rule/IF Runner는 이미 존재하는 `run_until_for_capture_session()`에 `--session-id`를 전달하도록 최소 수정한다.

**Tech Stack:** Python 3.10, SQLite/sqlite3, SQLAlchemy Session, argparse, pathlib, hashlib, JSON, pytest, Git CLI, 기존 `edge.runtime_lock.single_instance_lock`, 기존 `edge.scripts.phase4_cutover_storage.create_sqlite_backup`.

## Global Constraints

- 구현 기준은 `origin/develop@65714579610afa077dbb486a8fee92b020634d1d`에서 생성된 `feat/packet-checkpoint-gap-recovery` Worktree다.
- Recovery 대상은 `packet_rule` 또는 `packet_if` 하나이며 Source Table은 항상 `packet_feature_logs`다.
- `last_processed_id`는 유지하고 `last_completed_window_end`와 `updated_at`만 Target Session의 `first_window_start`로 전진한다.
- Trust Checkpoint, 과거 Detection Event, Trust History, Device, Isolation, Firewall, MQTT/Feature/Packet 데이터와 PCAP 파일은 변경하지 않는다.
- Migration 005 적용과 Recovery Execute는 분리한다. CLI는 Migration을 자동 적용하지 않는다.
- Raspberry Pi, 운영 DB, systemd, iptables, Packet Capture, 공격 프로세스는 구현·테스트 단계에서 접근하거나 실행하지 않는다.
- 기존 Baseline Recovery와 Trust Compensation의 안전 패턴은 참고하되 private helper import나 광범위한 공통화는 하지 않는다.
- SQLite Authorizer는 v1 범위에서 제외한다. 고정 SQL, 조건부 UPDATE, Row 수, Snapshot 회귀 테스트로 변경 범위를 증명한다.
- 계획/백업/결과/Lock 생성 경로가 Repository 내부이면 파일 생성 전에 실제 Git ignore 대상인지 확인한다. `.gitignore`는 수정하지 않는다.
- Dry-run은 Windows와 POSIX에서 지원한다. Execute는 내부 `_current_platform_name()`이 반환한 실제 `os.name`이 `"posix"`일 때만 허용하고 Windows에서는 Lock·Backup·Artifact·DB 변경 전에 Exit 2로 거부한다. 공개 Execute API에는 플랫폼 Override 인자를 두지 않는다.
- `plan_output.parent`와 Execute의 최상위 `artifact_dir`는 CLI 실행 전에 이미 존재해야 한다. CLI는 Plan 상위 Directory를 만들지 않고, Execute는 기존 `artifact_dir` 아래 `operation_id` Directory만 생성한다.
- 모든 테스트는 독립 임시 SQLite DB와 임시 Git Repository를 사용한다.

## File Map

- Create: `db/migrations/005_packet_checkpoint_recovery.sql` — Audit Schema와 중복 실행 방지 Constraint.
- Create: `edge/detection/packet_checkpoint_recovery_repository.py` — Recovery 전용 고정 SELECT, 조건부 Checkpoint UPDATE, Audit INSERT.
- Create: `edge/detection/packet_checkpoint_recovery.py` — Canonical Plan, Git/경로/Session/Lock Gate, Dry-run과 Execute Workflow.
- Create: `edge/detection/run_packet_checkpoint_recovery.py` — `dry-run`/`execute` argparse CLI와 Exit Code 2/3 출력 계약.
- Create: `tests/test_packet_checkpoint_recovery.py` — Plan, Git, 경로, Session, Lock, Transaction, Artifact, 불변성 집중 테스트.
- Create: `docs/packet-checkpoint-gap-recovery-runbook.md` — Migration과 Recovery를 분리한 운영 절차.
- Modify: `tests/test_migrations.py` — Migration 005 Schema·Upgrade·Rollback 회귀.
- Modify: `edge/detection/run_packet_rule_detector.py` — Manual Rule 실행을 Session-bound Stage 호출로 변경.
- Modify: `tests/test_packet_rule_runner.py` — Rule Runner가 Session ID를 Stage에 전달하는 계약.
- Modify: `edge/detection/run_packet_ai_detector.py` — Manual Packet IF 실행을 Session-bound Stage 호출로 변경.
- Modify: `tests/test_run_packet_ai_detector.py` — Packet IF Runner Session binding 계약.
- Modify: `docs/db-schema.md` — Migration 005와 Audit Table 계약.
- Modify: `docs/phase4-detection-core.md` — Gap Recovery와 Manual Runner Session binding.

## 공통 테스트 Fixture 계약

아래 Test Support는 각 Task에서 처음 필요한 함수만 그 Task의 RED 테스트와 함께 정의한다. 앞 Task는 뒤 Task에서 추가할 Helper나 Production API를 호출하지 않는다.

```python
@dataclass(frozen=True)
class RecoveryFixture:
    db_path: Path
    repository_root: Path
    plan_output: Path
    artifact_dir: Path
    backup_path: Path
    result_path: Path
    pcap_dir: Path
    current_session_id: str
    target_session_id: str
    detector_name: str

def create_recovery_fixture(
    tmp_path: Path,
    *,
    detector_name: str = "packet_rule",
    intermediate_sessions: tuple[dict[str, object], ...] = (),
) -> RecoveryFixture:
    """Migration 001~005가 적용된 독립 DB와 깨끗한 임시 Git Repository를 만든다."""

def database_snapshot(database: Path, tables: tuple[str, ...]) -> dict[str, tuple[tuple[object, ...], ...]]:
    """각 Table의 `SELECT * ORDER BY rowid` 결과를 불변 tuple로 반환한다."""

def checkpoint_snapshot(database: Path) -> tuple[tuple[object, ...], ...]:
    """모든 detector_checkpoints Row를 Key 순으로 반환한다."""

def file_hash_snapshot(root: Path) -> dict[str, str]:
    """root 아래 일반 파일의 상대 POSIX 경로와 SHA256을 반환한다."""

def unchanged_checkpoint_rows(
    before: tuple[tuple[object, ...], ...],
    after: tuple[tuple[object, ...], ...],
    *,
    requested_key: tuple[str, str],
) -> bool:
    """요청 Key를 제외한 Checkpoint Row가 동일한지 반환한다."""

def valid_dry_run_kwargs(fixture: RecoveryFixture) -> dict[str, object]:
    """inspect_packet_checkpoint_recovery()의 완전한 성공 인자를 반환한다."""

def valid_execute_kwargs(fixture: RecoveryFixture, plan_file: Path) -> dict[str, object]:
    """독립 DB의 성공 Execute 입력을 반환하며 플랫폼·Lock Override는 포함하지 않는다."""
```

Fixture는 임시 Repository 내부 생성 경로를 `.gitignore`에 포함한 뒤 Initial Commit을 만들고, 제품 Repository나 실제 DB 경로를 참조하지 않는다. UUID는 `uuid.UUID(..., version=4)` 검증을 통과하는 고정 Test ID를 사용한다.

---

### Task 1: Migration 005와 Audit Schema

**Files:**
- Create: `db/migrations/005_packet_checkpoint_recovery.sql`
- Modify: `tests/test_migrations.py`

**Interfaces:**
- Consumes: `db.migration_runner.apply_migrations(db_path, migrations_dir)`와 기존 `schema_migrations(version, name, applied_at)` 계약.
- Produces: `packet_checkpoint_recoveries` base table and `(5, 'packet_checkpoint_recovery')` migration metadata. Task 2 owns every UNIQUE, CHECK, FOREIGN KEY, and index constraint.

- [ ] **Step 1: 신규 DB의 Migration 005 생성 실패 테스트 작성**

  `tests/test_migrations.py`에 다음 테스트를 추가한다.

  ```python
  def test_packet_checkpoint_recovery_base_schema(tmp_path: Path) -> None:
      db_path = tmp_path / "recovery.db"
      apply_migrations(db_path, MIGRATIONS_DIR)
      with connect_database(db_path) as connection:
          assert connection.execute(
              "SELECT version, name FROM schema_migrations WHERE version = 5"
          ).fetchone() == (5, "packet_checkpoint_recovery")
          assert _table_exists(connection, "packet_checkpoint_recoveries")
          columns = _column_names(connection, "packet_checkpoint_recoveries")
          assert {
              "operation_id", "detector_name", "source_table",
              "current_capture_session_id", "target_capture_session_id",
              "last_processed_id_before", "last_processed_id_after",
              "last_completed_window_end_before", "last_completed_window_end_after",
              "updated_at_before", "updated_at_after", "plan_sha256", "plan_json",
              "approved_by", "reason", "repository_commit", "database_path",
              "backup_path", "backup_sha256", "created_at",
          } <= columns
  ```

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_migrations.py::test_packet_checkpoint_recovery_base_schema -q`

  Expected: FAIL — Migration 005가 없어 `packet_checkpoint_recoveries`가 존재하지 않는다.

- [ ] **Step 3: Migration 005 최소 Schema 작성**

  `db/migrations/005_packet_checkpoint_recovery.sql`에 다음 계약을 실제 SQLite DDL로 작성한다.

  ```sql
  CREATE TABLE packet_checkpoint_recoveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT NOT NULL,
      detector_name TEXT NOT NULL,
      source_table TEXT NOT NULL,
      current_capture_session_id TEXT NOT NULL,
      target_capture_session_id TEXT NOT NULL,
      last_processed_id_before INTEGER,
      last_processed_id_after INTEGER,
      last_completed_window_end_before TEXT NOT NULL,
      last_completed_window_end_after TEXT NOT NULL,
      updated_at_before TEXT NOT NULL,
      updated_at_after TEXT NOT NULL,
      plan_sha256 TEXT NOT NULL,
      plan_json TEXT NOT NULL,
      skipped_session_count INTEGER NOT NULL,
      skipped_processable_session_count INTEGER NOT NULL,
      approved_by TEXT NOT NULL,
      reason TEXT NOT NULL,
      repository_commit TEXT NOT NULL,
      database_path TEXT NOT NULL,
      backup_path TEXT NOT NULL,
      backup_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  ```

  SHA와 UTC 문자열의 세부 형식은 Core에서도 검증하며, Migration 테스트에서는 잘못된 Detector, Source, 중복 operation/target, `last_processed_id` 변경, 음수 Skip count를 각각 거부하도록 확인한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_migrations.py::test_packet_checkpoint_recovery_base_schema -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```powershell
  git add db/migrations/005_packet_checkpoint_recovery.sql tests/test_migrations.py
  git commit -m "feat: Packet Checkpoint Recovery Audit Migration 추가"
  ```

### Task 2: Migration 계약·회귀 테스트

**Files:**
- Modify: `db/migrations/005_packet_checkpoint_recovery.sql`
- Modify: `tests/test_migrations.py`

**Interfaces:**
- Consumes: Task 1의 Migration 005와 기존 `_write_project_migrations_subset()`.
- Produces: constrained Migration 005 DDL plus 004→005 upgrade, row-preservation, constraint DML, and failed-005 rollback evidence.

- [ ] **Step 1: 004 DB Upgrade와 Row 보존 테스트 작성**

  다음 테스트를 추가해 001~004만 적용한 DB에 기존 Checkpoint·Capture Session Row를 삽입하고 005 적용 후 동일함을 확인한다.

  ```python
  def test_packet_checkpoint_recovery_migration_applies_005_to_existing_004(
      tmp_path: Path,
  ) -> None:
      old_dir = tmp_path / "old"
      _write_project_migrations_subset(
          old_dir,
          (
              "001_init.sql",
              "002_packet_gateway.sql",
              "003_phase4_detection.sql",
              "004_trust_score_compensation.sql",
          ),
      )
      db_path = tmp_path / "existing-004.db"
      apply_migrations(db_path, old_dir)
      with connect_database(db_path) as connection:
          before = {
              "checkpoints": tuple(connection.execute(
                  "SELECT * FROM detector_checkpoints ORDER BY detector_name, source_table"
              ).fetchall()),
              "sessions": tuple(connection.execute(
                  "SELECT * FROM packet_capture_sessions ORDER BY id"
              ).fetchall()),
          }
      result = apply_migrations(db_path, MIGRATIONS_DIR)
      assert result.applied_versions == [5]
      with connect_database(db_path) as connection:
          after = {
              "checkpoints": tuple(connection.execute(
                  "SELECT * FROM detector_checkpoints ORDER BY detector_name, source_table"
              ).fetchall()),
              "sessions": tuple(connection.execute(
                  "SELECT * FROM packet_capture_sessions ORDER BY id"
              ).fetchall()),
          }
      assert after == before
  ```

  함께 추가할 테스트 이름:

  - `test_packet_checkpoint_recovery_rejects_duplicate_operation_id`
  - `test_packet_checkpoint_recovery_rejects_duplicate_detector_target`
  - `test_packet_checkpoint_recovery_rejects_invalid_detector_or_source`
  - `test_packet_checkpoint_recovery_rejects_changed_last_processed_id`
  - `test_packet_checkpoint_recovery_rejects_negative_skip_counts`
  - `test_packet_checkpoint_recovery_foreign_keys_restrict_referenced_rows`
  - `test_failed_005_migration_rolls_back_schema_and_version_record`

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_migrations.py -k "packet_checkpoint_recovery or failed_005" -q`

  Expected: 최소 한 테스트 FAIL — 005 Upgrade/Constraint 또는 Rollback 계약이 아직 충족되지 않는다.

- [ ] **Step 3: Add all constrained DDL required by the Task 2 tests**

  Update `005_packet_checkpoint_recovery.sql` from the Task 1 base table to this constrained DDL. Task 2 owns all UNIQUE, CHECK, FOREIGN KEY, and index constraints; the migration runner remains unchanged.

  ```sql
  CREATE TABLE packet_checkpoint_recoveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT NOT NULL UNIQUE,
      detector_name TEXT NOT NULL CHECK (detector_name IN ('packet_rule', 'packet_if')),
      source_table TEXT NOT NULL CHECK (source_table = 'packet_feature_logs'),
      current_capture_session_id TEXT NOT NULL,
      target_capture_session_id TEXT NOT NULL,
      last_processed_id_before INTEGER,
      last_processed_id_after INTEGER,
      last_completed_window_end_before TEXT NOT NULL,
      last_completed_window_end_after TEXT NOT NULL,
      updated_at_before TEXT NOT NULL,
      updated_at_after TEXT NOT NULL,
      plan_sha256 TEXT NOT NULL CHECK (length(plan_sha256) = 64),
      plan_json TEXT NOT NULL,
      skipped_session_count INTEGER NOT NULL CHECK (skipped_session_count >= 0),
      skipped_processable_session_count INTEGER NOT NULL CHECK (skipped_processable_session_count >= 0),
      approved_by TEXT NOT NULL,
      reason TEXT NOT NULL,
      repository_commit TEXT NOT NULL CHECK (length(repository_commit) = 40),
      database_path TEXT NOT NULL,
      backup_path TEXT NOT NULL,
      backup_sha256 TEXT NOT NULL CHECK (length(backup_sha256) = 64),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CHECK (last_processed_id_before IS last_processed_id_after),
      FOREIGN KEY (detector_name, source_table)
          REFERENCES detector_checkpoints(detector_name, source_table) ON DELETE RESTRICT,
      FOREIGN KEY (current_capture_session_id)
          REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT,
      FOREIGN KEY (target_capture_session_id)
          REFERENCES packet_capture_sessions(session_id) ON DELETE RESTRICT
  );

  CREATE UNIQUE INDEX uq_packet_checkpoint_recovery_detector_target
      ON packet_checkpoint_recoveries(
          detector_name, source_table, target_capture_session_id
      );
  ```

  The Task 2 DML tests explicitly cover duplicate `operation_id`, duplicate `(detector_name, source_table, target_capture_session_id)`, detector/source checks, unchanged `last_processed_id`, both nonnegative skip counts, and `ON DELETE RESTRICT` foreign keys. Its 004→005 upgrade test preserves existing rows, and its failed-005 test proves schema/version rollback.

- [ ] **Step 4: GREEN 및 기존 Migration 회귀 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_migrations.py -q`

  Expected: PASS; Migration 001~005 순서, 기존 Row 보존, 실패 Rollback 모두 통과.

- [ ] **Step 5: Commit**

  ```powershell
  git add db/migrations/005_packet_checkpoint_recovery.sql tests/test_migrations.py
  git commit -m "test: Packet Checkpoint Recovery Migration 계약 검증"
  ```

### Task 3: Canonical Plan과 결정적 SHA

**Files:**
- Create: `edge/detection/packet_checkpoint_recovery.py`
- Create: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Produces: `canonical_plan_binding(plan: Mapping[str, object]) -> dict[str, object]`, `canonical_plan_json(plan: Mapping[str, object]) -> str`, `calculate_plan_sha256(plan: Mapping[str, object]) -> str`, `attach_plan_sha256(payload: Mapping[str, object], *, generated_at: datetime) -> dict[str, object]`, `verify_plan_sha256(plan: Mapping[str, object]) -> None`.
- Canonical SHA 제외 필드: `plan_sha256`, 생성/실행 시각, `operation_id`, Mode, Plan/Backup/Result 경로, Backup SHA, CLI 문자열, Branch, mtime, `data_version`, PID, Lock 획득 시각, Commit 후 검증 시각.

- [ ] **Step 1: 결정성·변조 탐지 테스트 작성**

  ```python
  def test_canonical_plan_sha_is_independent_of_key_order_and_volatile_fields() -> None:
      payload = {
          "plan_schema_version": "packet-checkpoint-gap-recovery-plan-v1",
          "repository_commit": "a" * 40,
          "repository_root": "/repo",
          "database_path": "/data/iot.db",
          "detector_name": "packet_rule",
          "source_table": "packet_feature_logs",
      }
      first = attach_plan_sha256(payload, generated_at=UTC_A)
      second = attach_plan_sha256(dict(reversed(tuple(payload.items()))), generated_at=UTC_B)
      assert first["plan_sha256"] == second["plan_sha256"]

  def test_verify_plan_sha256_rejects_bound_field_tampering() -> None:
      plan = attach_plan_sha256({
          "plan_schema_version": "packet-checkpoint-gap-recovery-plan-v1",
          "repository_commit": "a" * 40,
          "repository_root": "/repo",
          "database_path": "/data/iot.db",
          "detector_name": "packet_rule",
          "source_table": "packet_feature_logs",
          "checkpoint": {
              "before": {"last_completed_window_end": "2026-08-06T10:00:00Z"},
              "after": {"last_completed_window_end": "2026-08-06T11:00:00Z"},
          },
      }, generated_at=UTC_A)
      plan["checkpoint"]["after"]["last_completed_window_end"] = OTHER_UTC
      with pytest.raises(PacketCheckpointRecoveryError, match="plan SHA256"):
          verify_plan_sha256(plan)
  ```

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "canonical_plan or plan_sha" -q`

  Expected: FAIL — Module 또는 Canonical 함수가 없다.

- [ ] **Step 3: Canonical 함수 최소 구현**

  ```python
  PLAN_SCHEMA_VERSION = "packet-checkpoint-gap-recovery-plan-v1"
  _VOLATILE_PLAN_KEYS = frozenset({
      "plan_sha256", "generated_at", "executed_at", "operation_id", "mode",
      "plan_path", "artifact_dir", "backup_path", "result_path", "backup_sha256",
      "execute_command", "repository_branch", "file_mtime_ns", "data_version",
      "process_id", "lock_acquired_at", "post_commit_verified_at",
  })

  def _without_volatile_fields(value: object) -> object:
      if isinstance(value, Mapping):
          return {
              str(key): _without_volatile_fields(item)
              for key, item in value.items()
              if key not in _VOLATILE_PLAN_KEYS
          }
      if isinstance(value, (list, tuple)):
          return [_without_volatile_fields(item) for item in value]
      return value

  def canonical_plan_binding(plan: Mapping[str, object]) -> dict[str, object]:
      binding = _without_volatile_fields(plan)
      if not isinstance(binding, dict):
          raise PacketCheckpointRecoveryError("canonical plan must be an object")
      return binding

  def canonical_plan_json(plan: Mapping[str, object]) -> str:
      return json.dumps(
          canonical_plan_binding(plan),
          ensure_ascii=False,
          sort_keys=True,
          separators=(",", ":"),
      )

  def calculate_plan_sha256(plan: Mapping[str, object]) -> str:
      return hashlib.sha256(canonical_plan_json(plan).encode("utf-8")).hexdigest()

  def attach_plan_sha256(payload: Mapping[str, object], *, generated_at: datetime) -> dict[str, object]:
      plan = {**payload, "generated_at": format_db_utc(generated_at)}
      return {**plan, "plan_sha256": calculate_plan_sha256(plan)}

  def verify_plan_sha256(plan: Mapping[str, object]) -> None:
      expected = plan.get("plan_sha256")
      actual = calculate_plan_sha256(plan)
      if not isinstance(expected, str) or not hmac.compare_digest(expected, actual):
          raise PacketCheckpointRecoveryError("plan SHA256 mismatch")
  ```

  UTC 값은 `edge.detection.phase4_time.format_db_utc()`의 정수 초 `Z` 형식만 Plan에 넣고, List 순서가 계약인 `untracked_inventory`, Lock, Session 목록은 생성 단계에서 먼저 정렬한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "canonical_plan or plan_sha" -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Gap Recovery Canonical Plan 계약 추가"
  ```

### Task 4: Git tracked/staged/untracked inventory 검증

**Files:**
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Produces: `inspect_repository_state(repository_root: str | Path) -> dict[str, object]`.
- Output: `repository_root`, `repository_commit`, `tracked_worktree_clean`, `staged_worktree_clean`, `untracked_inventory[{path,size,sha256}]`.

- [ ] **Step 1: 임시 Git Repository 기반 테스트 작성**

  테스트 이름:

  - `test_repository_state_rejects_tracked_changes`
  - `test_repository_state_rejects_staged_changes`
  - `test_repository_state_records_untracked_path_size_and_sha256`
  - `test_repository_state_does_not_modify_untracked_file_named_zero`
  - `test_repository_state_rejects_untracked_symlink`
  - `test_inventory_entry_rejects_non_regular_file`

  파일 `0` 테스트는 Before/After bytes와 SHA를 비교하며 특정 SHA를 제품 코드에 넣지 않는다. Symlink 테스트는 `os.symlink()` 생성 권한이나 지원이 없을 때 해당 이유로만 `pytest.skip()`한다. 비일반 파일 테스트는 `os.mkfifo()`를 지원하는 플랫폼에서 FIFO를 만들고, 지원하지 않으면 해당 Fixture만 Skip한다. 이 Skip은 Production에서 Symlink·FIFO·Socket 등 비일반 Entry를 허용하는 근거가 아니다. Dry-run/Execute 사이 Inventory 변경 통합 검증은 Execute Workflow가 존재하는 Task 11에서 추가한다.

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "repository_state or untracked_inventory" -q`

  Expected: FAIL — Git 상태 검사 함수가 없다.

- [ ] **Step 3: Git 명령과 Inventory 최소 구현**

  ```python
  def _git(repository_root: Path, *args: str) -> str:
      return subprocess.run(
          ["git", *args],
          cwd=repository_root,
          check=True,
          capture_output=True,
          text=True,
          encoding="utf-8",
      ).stdout

  def _sha256_open_regular_file(path: Path, expected: os.stat_result) -> str:
      flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
      descriptor = os.open(path, flags)
      try:
          opened = os.fstat(descriptor)
          if not stat.S_ISREG(opened.st_mode):
              raise PacketCheckpointRecoveryError("untracked entry must be a regular file")
          if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
              raise PacketCheckpointRecoveryError("untracked entry changed before hashing")
          digest = hashlib.sha256()
          while chunk := os.read(descriptor, 1024 * 1024):
              digest.update(chunk)
          return digest.hexdigest()
      finally:
          os.close(descriptor)

  def _inventory_entry(repository_root: Path, relative_path: str) -> dict[str, object]:
      relative = Path(relative_path)
      if relative.is_absolute() or ".." in relative.parts:
          raise PacketCheckpointRecoveryError("invalid untracked repository path")
      absolute = repository_root / relative
      before = absolute.lstat()
      if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
          raise PacketCheckpointRecoveryError("untracked entry must be a regular file")
      digest = _sha256_open_regular_file(absolute, before)
      after = absolute.lstat()
      identity_before = (
          before.st_mode, before.st_dev, before.st_ino,
          before.st_size, before.st_mtime_ns,
      )
      identity_after = (
          after.st_mode, after.st_dev, after.st_ino,
          after.st_size, after.st_mtime_ns,
      )
      if identity_before != identity_after:
          raise PacketCheckpointRecoveryError("untracked file changed during inventory")
      return {"path": relative.as_posix(), "size": after.st_size, "sha256": digest}

  def inspect_repository_state(repository_root: str | Path) -> dict[str, object]:
      root = Path(repository_root).expanduser().resolve(strict=True)
      commit = _git(root, "rev-parse", "HEAD").strip()
      tracked = _git(root, "diff", "--name-only", "--").splitlines()
      staged = _git(root, "diff", "--cached", "--name-only", "--").splitlines()
      untracked = _git(
          root, "ls-files", "--others", "--exclude-standard", "-z"
      ).split("\0")
      inventory = [_inventory_entry(root, path) for path in untracked if path]
      if tracked or staged:
          raise PacketCheckpointRecoveryError("tracked/staged worktree must be clean")
      return {
          "repository_root": str(root),
          "repository_commit": commit,
          "tracked_worktree_clean": True,
          "staged_worktree_clean": True,
          "untracked_inventory": sorted(inventory, key=lambda row: row["path"]),
      }
  ```

  `_inventory_entry()`는 `resolve()`로 Entry를 따라가지 않는다. `lstat()`으로 Symlink와 비일반 Entry를 Hash 전에 거부하고, 열린 Descriptor의 `fstat()` Identity를 비교한 뒤에만 내용을 읽는다. Hash 후에도 `lstat()` Identity 전체를 다시 비교한다. 기존 Entry는 삭제·수정·이동·Stage하지 않으며 `git clean`을 호출하지 않는다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "repository_state or untracked_inventory" -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Gap Recovery Git Inventory 검증 추가"
  ```

### Task 5: 생성 경로 Git ignore Gate

**Files:**
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Produces: `validate_generated_path(repository_root: Path, candidate: str | Path, *, field_name: str) -> Path`, `require_existing_parent(path: Path, *, field_name: str) -> Path`, `require_existing_directory(path: Path, *, field_name: str) -> Path`, `validate_generated_paths(*, repository_root: Path, plan_output: Path | None = None, artifact_dir: Path | None = None, backup_path: Path | None = None, result_path: Path | None = None, lock_paths: Sequence[Path] = ()) -> dict[str, object]`.
- 검증 대상: Plan, Artifact Directory, Backup DB, Backup `.sha256` Sidecar, Result JSON, 모든 Runtime Lock 파일.

- [ ] **Step 1: Repository 내부/외부 경로 테스트 작성**

  테스트 이름:

  - `test_generated_path_allows_path_outside_repository`
  - `test_generated_path_allows_gitignored_path_inside_repository`
  - `test_generated_path_rejects_unignored_path_before_creation`
  - `test_generated_path_checks_backup_sha256_sidecar`
  - `test_plan_output_requires_existing_parent_directory`
  - `test_artifact_directory_must_already_exist`

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "generated_path or gitignored or existing_parent or artifact_directory" -q`

  Expected: FAIL — 생성 경로 Gate가 없다.

- [ ] **Step 3: `git check-ignore` 기반 최소 구현**

  ```python
  def validate_generated_path(repository_root: Path, candidate: str | Path, *, field_name: str) -> Path:
      raw = Path(candidate).expanduser()
      path = (raw if raw.is_absolute() else repository_root / raw).resolve(strict=False)
      if not path.is_relative_to(repository_root):
          return path
      relative = path.relative_to(repository_root)
      result = subprocess.run(
          ["git", "check-ignore", "--quiet", "--", relative.as_posix()],
          cwd=repository_root,
          check=False,
      )
      if result.returncode != 0:
          raise PacketCheckpointRecoveryError(f"{field_name} must be Git-ignored")
      return path

  def require_existing_parent(path: Path, *, field_name: str) -> Path:
      parent = path.expanduser().resolve(strict=False).parent
      if not parent.is_dir():
          raise PacketCheckpointRecoveryError(f"{field_name} parent must already exist")
      return parent

  def require_existing_directory(path: Path, *, field_name: str) -> Path:
      resolved = path.expanduser().resolve(strict=True)
      if not resolved.is_dir():
          raise PacketCheckpointRecoveryError(f"{field_name} must be an existing directory")
      return resolved

  def validate_generated_paths(
      *, repository_root, plan_output=None, artifact_dir=None,
      backup_path=None, result_path=None, lock_paths=(),
  ) -> dict[str, object]:
      checked: dict[str, object] = {}
      if plan_output is not None:
          require_existing_parent(plan_output, field_name="plan_output")
          checked["plan_output"] = validate_generated_path(
              repository_root, plan_output, field_name="plan_output"
          )
      if artifact_dir is not None:
          checked["artifact_dir"] = validate_generated_path(
              repository_root,
              require_existing_directory(artifact_dir, field_name="artifact_dir"),
              field_name="artifact_dir",
          )
      if backup_path is not None:
          backup = validate_generated_path(repository_root, backup_path, field_name="backup_path")
          checked["backup_path"] = backup
          checked["backup_sha256_path"] = validate_generated_path(
              repository_root,
              backup.with_suffix(backup.suffix + ".sha256"),
              field_name="backup_sha256_path",
          )
      if result_path is not None:
          checked["result_path"] = validate_generated_path(
              repository_root, result_path, field_name="result_path"
          )
      checked["lock_paths"] = tuple(
          validate_generated_path(repository_root, path, field_name="lock_path")
          for path in lock_paths
      )
      return checked
  ```

  Git ignore 여부는 Directory가 없어도 그 안에 생성할 대표 파일 경로로 확인한다. 단, `plan_output.parent`와 최상위 `artifact_dir`는 별도 함수로 이미 존재함을 요구한다. 모든 후보를 검증한 뒤에만 Atomic Plan write, `operation_id` 하위 Directory 생성, Backup, Lock 획득을 허용한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "generated_path or gitignored or existing_parent or artifact_directory" -q`

  Expected: PASS; 거부 Case에서 파일과 Directory가 생성되지 않는다.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Gap Recovery 생성 경로 Gate 추가"
  ```

### Task 6: DB 절대경로 바인딩

**Files:**
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Produces: `resolve_database_path(db_path: str | Path) -> Path`, `require_plan_database_path(plan: Mapping[str, object], db_path: str | Path) -> Path`.

- [ ] **Step 1: 경로 바인딩 테스트 작성**

  ```python
  def test_require_plan_database_path_rejects_different_resolved_path(tmp_path: Path) -> None:
      first_db = tmp_path / "first.db"
      second_db = tmp_path / "second.db"
      first_db.write_bytes(b"first")
      second_db.write_bytes(b"second")
      plan = {"database_path": str(first_db.resolve())}
      with pytest.raises(PacketCheckpointRecoveryError, match="database path"):
          require_plan_database_path(plan, second_db)

  def test_require_plan_database_path_accepts_same_resolved_path(tmp_path: Path) -> None:
      database = tmp_path / "iot.db"
      database.write_bytes(b"sqlite fixture")
      plan = {"database_path": str(database.resolve())}
      assert require_plan_database_path(plan, database) == database.resolve()
  ```

  함께 `test_canonical_plan_sha_changes_when_resolved_database_path_changes`와 `test_database_path_requires_existing_regular_file`을 추가한다. Execute가 다른 DB를 Backup 전에 거부하는 통합 테스트는 Task 11에서 추가한다.

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "database_path" -q`

  Expected: FAIL — Plan DB 바인딩 함수가 없다.

- [ ] **Step 3: `expanduser().resolve(strict=True)` 계약 구현**

  ```python
  def resolve_database_path(db_path: str | Path) -> Path:
      resolved = Path(db_path).expanduser().resolve(strict=True)
      if not resolved.is_file():
          raise PacketCheckpointRecoveryError("database path must be a regular file")
      return resolved

  def require_plan_database_path(plan: Mapping[str, object], db_path: str | Path) -> Path:
      resolved = resolve_database_path(db_path)
      if str(resolved) != plan.get("database_path"):
          raise PacketCheckpointRecoveryError("database path does not match plan")
      return resolved
  ```

  이 Task는 두 순수 경로 함수만 구현한다. Execute 호출 순서와 무변경 보장은 Task 11에서 검증한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "database_path" -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Gap Recovery DB 경로 바인딩 추가"
  ```

### Task 7: Capture Session Readiness와 전역 RUNNING Gate

**Files:**
- Create: `edge/detection/packet_checkpoint_recovery_repository.py`
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Repository produces: `get_checkpoint(connection: sqlite3.Connection, detector_name: str, source_table: str) -> sqlite3.Row | None`, `get_capture_session(connection: sqlite3.Connection, session_id: str) -> sqlite3.Row | None`, `list_capture_segments(connection: sqlite3.Connection, session_id: str) -> list[sqlite3.Row]`, `list_running_capture_sessions(connection: sqlite3.Connection) -> list[sqlite3.Row]`, `list_sessions_between(connection: sqlite3.Connection, *, after_window_end: str, before_window_start: str) -> list[sqlite3.Row]`, `get_existing_recovery(connection: sqlite3.Connection, *, detector_name: str, source_table: str, target_session_id: str) -> sqlite3.Row | None`.
- Repository produces: `RecoverySessionReadiness(session_id: str, first_window_start: datetime | None, packet_feature_ready_through: datetime | None, segment_count: int, feature_row_count: int, full_ready: bool, blocking_reasons: tuple[str, ...])`, `calculate_packet_feature_readiness(connection: sqlite3.Connection, session_id: str) -> RecoverySessionReadiness | None`.
- Core produces: `build_recovery_plan(connection: sqlite3.Connection, *, repository_state: Mapping[str, object], database_path: Path, detector_name: str, current_session_id: str, target_session_id: str, approved_by: str, reason: str, lock_entries: Sequence[Mapping[str, object]]) -> dict[str, object]`.

- [ ] **Step 1: Session Gate 테스트 작성**

  테스트 이름:

  - `test_plan_requires_supported_detector_and_source_table`
  - `test_plan_requires_existing_completed_current_and_target_sessions`
  - `test_plan_requires_current_checkpoint_at_current_ready_through`
  - `test_plan_rejects_current_session_with_remaining_ready_prefix`
  - `test_plan_requires_target_full_ready_processed_or_empty_range`
  - `test_plan_rejects_missing_ready_failed_or_inconsistent_feature_segments`
  - `test_plan_lists_all_running_sessions_as_blocking`
  - `test_plan_rejects_checkpoint_regression_same_session_and_duplicate_recovery`
  - `test_recovery_readiness_matches_existing_helper_for_normal_and_empty_segments`
  - `test_recovery_readiness_matches_existing_helper_for_ready_failed_and_missing_window`
  - `test_recovery_readiness_matches_existing_helper_for_error_code_and_feature_mismatch`
  - `test_target_full_ready_rejects_segment_before_first_window`
  - `test_target_full_ready_rejects_overlapping_or_extra_segment`

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "session or readiness or running" -q`

  Expected: FAIL — 전용 Repository와 Plan Builder가 없다.

- [ ] **Step 3: 고정 SQL Repository와 Readiness Digest 구현**

  ```python
  SUPPORTED_DETECTORS = {
      "packet_rule": "packet_feature_logs",
      "packet_if": "packet_feature_logs",
  }

  @dataclass(frozen=True)
  class RecoverySessionReadiness:
      session_id: str
      first_window_start: datetime | None
      packet_feature_ready_through: datetime | None
      segment_count: int
      feature_row_count: int
      full_ready: bool
      blocking_reasons: tuple[str, ...]

  def list_running_capture_sessions(connection: sqlite3.Connection) -> list[sqlite3.Row]:
      return connection.execute(
          """
          SELECT session_id, started_at
          FROM packet_capture_sessions
          WHERE status = 'RUNNING'
          ORDER BY started_at ASC, session_id ASC
          """
      ).fetchall()

  def _list_segment_feature_counts(
      connection: sqlite3.Connection,
      session_id: str,
  ) -> list[sqlite3.Row]:
      return connection.execute(
          """
          SELECT pcsg.id AS segment_id,
                 pcsg.window_start, pcsg.window_end, pcsg.status, pcsg.error_code,
                 COUNT(pfl.id) AS feature_count
          FROM packet_capture_segments pcsg
          LEFT JOIN packet_feature_logs pfl ON pfl.capture_segment_id = pcsg.id
          JOIN packet_capture_sessions pcs ON pcs.id = pcsg.capture_session_id
          WHERE pcs.session_id = ?
          GROUP BY pcsg.id, pcsg.window_start, pcsg.window_end,
                   pcsg.status, pcsg.error_code
          ORDER BY pcsg.window_start ASC, pcsg.id ASC
          """,
          (session_id,),
      ).fetchall()

  def _last_segment_window_end(rows: Sequence[sqlite3.Row]) -> datetime | None:
      if not rows:
          return None
      return max(parse_db_utc(row["window_end"], "window_end") for row in rows)

  def calculate_packet_feature_readiness(
      connection: sqlite3.Connection,
      session_id: str,
  ) -> RecoverySessionReadiness | None:
      session = get_capture_session(connection, session_id)
      if session is None:
          return None
      raw_first = session["first_window_start"]
      if raw_first is None:
          return RecoverySessionReadiness(session_id, None, None, 0, 0, False, ("NO_FIRST_WINDOW",))
      first = parse_db_utc(raw_first, "first_window_start")
      expected = first
      ready_through: datetime | None = None
      segment_count = 0
      feature_row_count = 0
      consumed_segment_ids: list[int] = []
      blocking_reasons: list[str] = []
      rows = _list_segment_feature_counts(connection, session_id)
      for row in rows:
          start = parse_db_utc(row["window_start"], "window_start")
          if start < expected:
              blocking_reasons.append("SEGMENT_BEFORE_OR_OVERLAPPING_PREFIX")
              continue
          if start > expected:
              blocking_reasons.append("MISSING_WINDOW")
              break
          status = str(row["status"])
          count = int(row["feature_count"])
          if status not in {"PROCESSED", "EMPTY"} or row["error_code"] is not None:
              blocking_reasons.append("NON_TERMINAL_OR_ERROR")
              break
          if (status == "PROCESSED" and count == 0) or (status == "EMPTY" and count != 0):
              blocking_reasons.append("FEATURE_COUNT_MISMATCH")
              break
          end = parse_db_utc(row["window_end"], "window_end")
          if end != start + timedelta(seconds=10):
              blocking_reasons.append("INVALID_WINDOW_DURATION")
              break
          segment_count += 1
          feature_row_count += count
          consumed_segment_ids.append(int(row["segment_id"]))
          ready_through = end
          expected = end
      last_end = _last_segment_window_end(rows)
      all_segment_ids = [int(row["segment_id"]) for row in rows]
      full_ready = (
          session["status"] == "COMPLETED"
          and ready_through is not None
          and ready_through == last_end
          and segment_count == len(rows)
          and consumed_segment_ids == all_segment_ids
          and len(consumed_segment_ids) == len(set(consumed_segment_ids))
          and not blocking_reasons
      )
      return RecoverySessionReadiness(
          session_id, first, ready_through, segment_count,
          feature_row_count, full_ready, tuple(blocking_reasons),
      )
  ```

  기준 의미는 기존 `edge.packet.capture_session_repository.get_packet_feature_ready_through()`다. Parity Test는 같은 임시 SQLite DB를 SQLAlchemy `Session`과 raw `sqlite3.Connection`으로 각각 열고 정상, `EMPTY`, `READY`, `FAILED`, 누락 Window, `error_code`, Feature Row 불일치 Fixture마다 `first_window_start`와 `packet_feature_ready_through`가 동일한 aware `datetime`인지 비교한다. Recovery 구현은 기존 Helper를 리팩터링하지 않고 sqlite3로 동일한 contiguous-prefix를 계산하며 Canonical Plan을 만들 때만 `format_db_utc()`로 변환한다.

  `PROCESSED`에는 같은 Session·Window의 `packet_feature_logs`가 1건 이상, `EMPTY`에는 0건이어야 한다. Target full-ready는 기존 contiguous-prefix 의미 위에 추가되는 더 강한 Recovery 전용 조건이다. Session이 `COMPLETED`이고 전체 Segment가 `PROCESSED/EMPTY`이며 Ready Through가 마지막 Window End와 일치해야 한다. 또한 `first_window_start`보다 앞선 Segment, 중복·겹침 Segment, Prefix에서 소비되지 않은 추가 Segment가 없어야 하며 `segment_count == len(rows)`와 `consumed_segment_ids == all_segment_ids`를 모두 만족해야 `full_ready=True`다. 기존 Helper의 Prefix 결과는 수정하거나 약화하지 않는다.

- [ ] **Step 4: GREEN 확인과 기존 Repository 의미 회귀**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "session or readiness or running" -q`

  Expected: PASS; Plan Builder의 RUNNING Summary는 `session_id`, `started_at`을 포함하고 어떤 Row도 수정하지 않는다. 기존 Helper와 Recovery 계산의 `first_window_start`·`ready_through`가 모든 Fixture에서 일치한다.

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_repositories.py tests/test_packet_stage_readiness.py -q`

  Expected: PASS; 기존 Readiness 계약과 충돌하지 않는다.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/packet_checkpoint_recovery_repository.py edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Gap Recovery Session Readiness Gate 추가"
  ```

### Task 8: full-ready Session Skip 분류와 추가 확인 계약

**Files:**
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Produces: `classify_skipped_sessions(connection: sqlite3.Connection, *, checkpoint_window_end: str, target_first_window_start: str) -> list[dict[str, object]]`, `require_execute_confirmations(plan: Mapping[str, object], *, confirm: str, confirm_skip_processable: str | None) -> None`.
- 고정 분류: `EXHAUSTED_CURRENT`, `SKIPPED_FULL_READY_COMPLETED`, `SKIPPED_NOT_READY`, `SKIPPED_FAILED`, `BLOCKING_RUNNING`, `TARGET_FULL_READY_COMPLETED`.

- [ ] **Step 1: Skip 분류와 확인 문자열 테스트 작성**

  테스트 이름:

  - `test_plan_classifies_full_ready_completed_session_as_processable_skip`
  - `test_plan_classifies_failed_and_not_ready_sessions_separately`
  - `test_processable_skip_requires_plan_sha_bound_confirmation`
  - `test_processable_skip_rejects_missing_or_wrong_confirmation`
  - `test_nonprocessable_gap_does_not_require_processable_skip_confirmation`
  - `test_confirmation_is_rejected_when_plan_has_no_processable_skip`

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "processable_skip or classifies" -q`

  Expected: FAIL — Skip 분류 또는 SHA-bound 확인 Gate가 없다.

- [ ] **Step 3: 분류와 확인 계약 구현**

  ```python
  EXECUTE_CONFIRMATION = "APPLY-PACKET-CHECKPOINT-GAP-RECOVERY"
  PROCESSABLE_SKIP_PREFIX = "SKIP-PROCESSABLE-SESSIONS:"

  def require_execute_confirmations(plan, *, confirm, confirm_skip_processable):
      if confirm != EXECUTE_CONFIRMATION:
          raise PacketCheckpointRecoveryError("execute confirmation mismatch")
      expected = f"{PROCESSABLE_SKIP_PREFIX}{plan['plan_sha256']}"
      skips = bool(plan["summary"]["skips_processable_sessions"])
      if skips and confirm_skip_processable != expected:
          raise PacketCheckpointRecoveryError("processable-session confirmation mismatch")
      if not skips and confirm_skip_processable is not None:
          raise PacketCheckpointRecoveryError("processable-session confirmation not allowed")
  ```

  `SKIPPED_FULL_READY_COMPLETED` Summary에는 Session ID, Window 범위, Segment 수, Feature Row 수, `PROCESSABLE_SESSION_SKIP` Warning Code를 반드시 포함한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "processable_skip or classifies" -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: 처리 가능 Session Skip 승인 계약 추가"
  ```

### Task 9: 실제 Lock 경로 해석·중복 제거·정렬 획득

**Files:**
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Consumes: `edge.orchestration.run_detection_orchestrator.resolve_lock_path`, `edge.detection.run_packet_rule_detector.DEFAULT_LOCK_PATH`, `edge.detection.run_packet_ai_detector.DEFAULT_LOCK_PATH`, `edge.features.run_packet_feature_extractor.DEFAULT_LOCK_PATH`, `edge.runtime_lock.single_instance_lock`.
- Produces: `ResolvedRecoveryLock(path: Path, roles: tuple[str, ...])`, `resolve_recovery_locks(*, repository_root: Path, database_url: str, orchestrator_lock_path: Path | None, manual_lock_path: Path | None, extractor_lock_path: Path | None) -> tuple[ResolvedRecoveryLock, ...]`, `serialize_resolved_locks(locks: Sequence[ResolvedRecoveryLock]) -> tuple[dict[str, object], ...]`, `acquire_recovery_locks(locks: Sequence[ResolvedRecoveryLock], *, lock_factory: Callable[[Path], ContextManager[None]] = single_instance_lock) -> ContextManager[None]`.

- [ ] **Step 1: 실제 경로·중복·순서·충돌 테스트 작성**

  테스트 이름:

  - `test_lock_resolution_uses_orchestrator_manual_and_extractor_contracts`
  - `test_relative_lock_paths_resolve_from_repository_root`
  - `test_shared_rule_if_lock_is_acquired_once_with_both_roles`
  - `test_duplicate_orchestrator_and_manual_path_is_acquired_once`
  - `test_unique_locks_are_acquired_in_sorted_absolute_path_order_with_injected_lock`
  - `test_acquire_recovery_locks_releases_already_acquired_locks_on_conflict`

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "lock_" -q`

  Expected: FAIL — Recovery Lock 조정 함수가 없다.

- [ ] **Step 3: 역할별 경로 계산과 `ExitStack` 획득 구현**

  ```python
  @dataclass(frozen=True)
  class ResolvedRecoveryLock:
      path: Path
      roles: tuple[str, ...]

  def _absolute_lock_path(repository_root: Path, path: Path) -> Path:
      candidate = path if path.is_absolute() else repository_root / path
      return candidate.resolve(strict=False)

  def resolve_recovery_locks(
      *, repository_root, database_url, orchestrator_lock_path,
      manual_lock_path, extractor_lock_path,
  ) -> tuple[ResolvedRecoveryLock, ...]:
      orchestrator = run_detection_orchestrator.resolve_lock_path(
          Settings(
              database_url=database_url,
              orchestrator_lock_path=(
                  str(orchestrator_lock_path)
                  if orchestrator_lock_path is not None
                  else ""
              ),
          )
      )
      manual = manual_lock_path or run_packet_rule_detector.DEFAULT_LOCK_PATH
      extractor = extractor_lock_path or run_packet_feature_extractor.DEFAULT_LOCK_PATH
      roles_by_path: dict[Path, set[str]] = {}
      for role, path in (
          ("detection_orchestrator", orchestrator),
          ("packet_rule_manual", manual),
          ("packet_if_manual", manual),
          ("packet_feature_extractor", extractor),
      ):
          absolute = _absolute_lock_path(repository_root, Path(path))
          roles_by_path.setdefault(absolute, set()).add(role)
      return tuple(
          ResolvedRecoveryLock(path, tuple(sorted(roles)))
          for path, roles in sorted(roles_by_path.items(), key=lambda item: str(item[0]))
      )

  def serialize_resolved_locks(
      locks: Sequence[ResolvedRecoveryLock],
  ) -> tuple[dict[str, object], ...]:
      return tuple(
          {"path": str(lock.path), "roles": list(lock.roles)}
          for lock in sorted(locks, key=lambda item: str(item.path))
      )

  @contextmanager
  def acquire_recovery_locks(
      locks: Sequence[ResolvedRecoveryLock],
      *,
      lock_factory: Callable[[Path], ContextManager[None]] = single_instance_lock,
  ):
      with ExitStack() as stack:
          for lock in sorted(locks, key=lambda item: str(item.path)):
              stack.enter_context(lock_factory(lock.path))
          yield
  ```

  Orchestrator 경로는 제공된 `database_url`과 `orchestrator_lock_path` Override를 담은 실제 `Settings`로 `run_detection_orchestrator.resolve_lock_path()`를 호출한 결과를 사용한다. Override가 없고 URL이 non-SQLite이면 실제 Orchestrator fallback인 `data/detection-orchestrator.lock`을 유지하며 다른 fallback을 만들지 않는다. Manual Rule/IF와 Extractor의 상대 기본값 및 Override는 Repository Root 기준으로 절대경로화한다. `(resolved_path, roles[])`로 합친 후 같은 Path를 두 번 획득하지 않는다. Task 5 Gate가 모든 Lock Path를 먼저 승인한 뒤 획득한다. Windows 단위 테스트는 주입한 Fake Lock으로 순서·중복·해제를 검증하며 실제 상호운용을 주장하지 않는다. Lock 충돌 시 Backup 무변경 통합 테스트는 Task 11, Commit 후 Result 처리까지 Lock 유지 테스트는 Task 12에서 추가한다.

- [ ] **Step 4: GREEN 및 기존 Lock 회귀 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "lock_" -q`

  Expected: PASS.

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_runtime_lock.py tests/test_detection_orchestrator_runner.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Gap Recovery Runtime Lock 조정 추가"
  ```

### Task 10: Dry-run CLI

**Files:**
- Create: `edge/detection/run_packet_checkpoint_recovery.py`
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Produces: `inspect_packet_checkpoint_recovery(*, db_path: str | Path, repository_root: str | Path, detector_name: str, current_session_id: str, target_session_id: str, approved_by: str, reason: str, plan_output: str | Path, orchestrator_lock_path: Path | None = None, manual_lock_path: Path | None = None, extractor_lock_path: Path | None = None) -> dict[str, object]`, `build_parser() -> argparse.ArgumentParser`, `main(argv: Sequence[str] | None = None) -> int`.
- Dry-run 필수 입력: `--db-path`, `--repository-root`, `--detector`, `--current-session-id`, `--target-session-id`, `--approved-by`, `--reason`, `--plan-output`; Lock Override는 역할별 선택 인자.

- [ ] **Step 1: Dry-run 성공·실패 테스트 작성**

  테스트 이름:

  - `test_dry_run_writes_canonical_plan_atomically_after_all_gates_pass`
  - `test_dry_run_is_query_only_and_does_not_create_artifact_directory`
  - `test_dry_run_reports_checkpoint_before_after_running_gate_and_skip_summary`
  - `test_dry_run_rejects_missing_005_row_or_table_before_plan_creation`
  - `test_dry_run_rejects_missing_plan_parent_before_temporary_file_creation`
  - `test_dry_run_plan_output_does_not_change_untracked_inventory`
  - `test_dry_run_does_not_call_posix_execute_platform_gate`
  - `test_dry_run_cli_requires_all_identity_and_output_arguments`
  - `test_dry_run_cli_returns_two_for_precommit_validation_error`

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "dry_run" -q`

  Expected: FAIL — Dry-run API/CLI가 없다.

- [ ] **Step 3: Query-only Dry-run과 Atomic Plan write 구현**

  ```python
  def inspect_packet_checkpoint_recovery(
      *, db_path, repository_root, detector_name, current_session_id,
      target_session_id, approved_by, reason, plan_output,
      orchestrator_lock_path=None, manual_lock_path=None, extractor_lock_path=None,
  ) -> dict[str, object]:
      database = resolve_database_path(db_path)
      root = Path(repository_root).expanduser().resolve(strict=True)
      raw_plan_output = Path(plan_output).expanduser()
      plan_path = (
          raw_plan_output if raw_plan_output.is_absolute() else root / raw_plan_output
      ).resolve(strict=False)
      require_existing_parent(plan_path, field_name="plan_output")
      locks = resolve_recovery_locks(
          repository_root=root,
          database_url=f"sqlite:///{database}",
          orchestrator_lock_path=orchestrator_lock_path,
          manual_lock_path=manual_lock_path,
          extractor_lock_path=extractor_lock_path,
      )
      paths = validate_generated_paths(
          repository_root=root,
          plan_output=plan_path,
          lock_paths=tuple(lock.path for lock in locks),
      )
      repository_state = inspect_repository_state(repository_root)
      with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
          connection.row_factory = sqlite3.Row
          require_migration_005(connection)
          payload = build_recovery_plan(
              connection,
              repository_state=repository_state,
              database_path=database,
              detector_name=detector_name,
              current_session_id=current_session_id,
              target_session_id=target_session_id,
              approved_by=approved_by,
              reason=reason,
              lock_entries=serialize_resolved_locks(locks),
          )
      plan = attach_plan_sha256(payload, generated_at=_utc_now())
      _write_json_atomically(paths["plan_output"], plan)
      return plan
  ```

  같은 Task에서 `_utc_now() -> datetime`은 `datetime.now(timezone.utc)`를 반환하고, `_write_json_atomically(path: Path, payload: Mapping[str, object]) -> None`은 이미 존재하는 `path.parent` 안의 `NamedTemporaryFile(delete=False)`에 UTF-8 JSON과 끝 줄바꿈을 기록·`flush()`·`os.fsync()`한 뒤 `os.replace()`한다. 임시 경로도 Task 5의 Git ignore Gate가 승인한 Directory 안에서만 만든다.

  Migration 005 Row와 Table/Index Schema Digest 검증은 Repository/Git/파일 생성보다 먼저 가능한 순서로 배치한다. `plan_output.parent`가 없으면 임시 파일을 만들기 전에 거부하며 CLI가 상위 Directory를 생성하지 않는다. Dry-run에는 POSIX 전용 Gate를 호출하지 않는다. 출력 JSON은 `can_execute`, Blocking reason, RUNNING Session, Checkpoint Before/After, Skip 분류, Lock 역할/경로, 재현 가능한 Execute 명령을 포함한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "dry_run" -q`

  Expected: PASS; 성공 시 Plan 하나만 생성되고 DB Row·Journal·Artifact Directory는 변하지 않는다.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/run_packet_checkpoint_recovery.py edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Packet Checkpoint Recovery Dry-run CLI 추가"
  ```

### Task 11: SQLite Backup·Transaction·조건부 Checkpoint Mutation·Audit

**Files:**
- Modify: `edge/detection/packet_checkpoint_recovery_repository.py`
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Consumes: `edge.scripts.phase4_cutover_storage.create_sqlite_backup()`와 `verify_database()`.
- Repository produces: `update_checkpoint_conditionally(connection: sqlite3.Connection, *, before: Mapping[str, object], after: Mapping[str, object]) -> int`, `insert_recovery_audit(connection: sqlite3.Connection, *, audit: Mapping[str, object]) -> int`, `get_recovery_audit(connection: sqlite3.Connection, operation_id: str) -> sqlite3.Row | None`.
- Core produces: `_current_platform_name() -> str`, `require_execute_platform(platform_name: str) -> None`, `execute_packet_checkpoint_recovery(*, plan_file: str | Path, db_path: str | Path, artifact_dir: str | Path, confirm: str, confirm_skip_processable: str | None = None) -> dict[str, object]`.

- [ ] **Step 1: Backup·TOCTOU·Mutation 테스트 작성**

  `tests/test_packet_checkpoint_recovery.py`에 공개 Signature 검사용 `import inspect`와 Lock Context Manager Test Double용 `from contextlib import nullcontext`를 추가한다.

  테스트 이름:

  - `test_execute_creates_verified_backup_before_begin_immediate`
  - `test_execute_rechecks_full_canonical_plan_inside_begin_immediate`
  - `test_execute_rejects_changed_checkpoint_updated_at_and_rolls_back`
  - `test_execute_keeps_last_processed_id_and_advances_only_time_boundary`
  - `test_execute_inserts_exactly_one_audit_row_in_same_transaction`
  - `test_execute_requires_total_changes_delta_two`
  - `test_backup_failure_leaves_live_database_and_artifacts_unchanged`
  - `test_precommit_failure_preserves_verified_backup_and_rolls_back_database`
  - `test_duplicate_operation_or_detector_target_is_rejected`
  - `test_execute_rejects_changed_untracked_inventory_before_backup`
  - `test_execute_rejects_database_path_different_from_plan_before_backup`
  - `test_execute_rejects_global_running_session_before_backup`
  - `test_execute_rejects_wrong_processable_skip_confirmation_before_backup`
  - `test_execute_rejects_missing_artifact_directory_without_creating_it`
  - `test_execute_lock_conflict_prevents_backup_artifact_and_database_changes`
  - `test_execute_rejects_windows_before_lock_backup_artifact_and_database_changes`
  - `test_execute_public_signature_has_no_platform_override`
  - `test_execute_rejects_platform_name_keyword_in_general_python_call`
  - `test_execute_public_signature_has_no_lock_factory_override`
  - `test_execute_rejects_lock_factory_keyword_in_general_python_call`

  Windows에서 실행되는 성공 Workflow 테스트는 공개 인자 없이 다음 패턴을 사용한다.

  ```python
  def test_execute_creates_verified_backup_before_begin_immediate(monkeypatch, fixture):
      monkeypatch.setattr(recovery, "_current_platform_name", lambda: "posix")
      monkeypatch.setattr(
          recovery,
          "acquire_recovery_locks",
          lambda locks: nullcontext(),
      )
      kwargs = valid_execute_kwargs(fixture, fixture.plan_output)
      assert "platform_name" not in kwargs
      assert "lock_factory" not in kwargs
      result = execute_packet_checkpoint_recovery(**kwargs)
      assert result["database_committed"] is True

  def test_execute_public_signature_has_no_lock_factory_override():
      assert "lock_factory" not in inspect.signature(
          execute_packet_checkpoint_recovery
      ).parameters

  def test_execute_rejects_lock_factory_keyword_in_general_python_call(fixture):
      kwargs = valid_execute_kwargs(fixture, fixture.plan_output)
      with pytest.raises(TypeError):
          execute_packet_checkpoint_recovery(
              **kwargs,
              lock_factory=lambda path: nullcontext(),
          )
  ```

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "execute or backup or transaction or conditional or audit_row or total_changes" -q`

  Expected: FAIL — Execute Workflow와 Mutation 함수가 없다.

- [ ] **Step 3: 고정 SQL과 승인된 실행 순서 구현**

  조건부 UPDATE는 다음 Predicate를 모두 사용한다.

  ```sql
  UPDATE detector_checkpoints
  SET last_completed_window_end = ?, updated_at = ?
  WHERE detector_name = ?
    AND source_table = ?
    AND last_processed_id IS ?
    AND last_completed_window_end = ?
    AND updated_at = ?
  ```

  먼저 운영체제 Gate를 구현한다.

  ```python
  def _current_platform_name() -> str:
      return os.name

  def require_execute_platform(platform_name: str) -> None:
      if platform_name != "posix":
          raise PacketCheckpointRecoveryError(
              "execute is supported only on POSIX; dry-run is available on Windows"
          )
  ```

  Windows에서는 Manual Runner가 `msvcrt`, 공용 Runtime Lock이 `O_EXCL`, Packet Feature Extractor가 무잠금 경로를 사용하므로 같은 Path만으로 상호배제를 보장하지 못한다. `execute_packet_checkpoint_recovery()`는 공개 인자를 읽거나 파일에 접근하기 전에 `require_execute_platform(_current_platform_name())`을 가장 먼저 호출한다. 공개 Signature와 CLI에는 `platform_name`을 두지 않으므로 일반 Python 호출과 CLI 모두 `platform_name="posix"` 같은 값으로 Gate를 우회할 수 없다.

  Windows에서 Task 11의 성공·Rollback Workflow를 검증할 때는 공개 Execute 인자를 바꾸지 않고 `_current_platform_name()`만 `lambda: "posix"`로 Monkeypatch한다. Lock Test Double이 필요하면 공개 인자로 전달하지 않고 `recovery.acquire_recovery_locks`를 기록 가능한 Context Manager로 Monkeypatch한다. Windows 거부 테스트는 `_current_platform_name()`을 `lambda: "nt"`로 Monkeypatch하고 모든 Mutation Spy의 호출 수가 0인지 확인한다. `inspect.signature()`로 공개 플랫폼·`lock_factory` 인자가 없음을 확인한다. `platform_name="posix"` 또는 `lock_factory=fake_lock_factory` Keyword를 일반 Python 호출에 전달하면 Python `TypeError`로 거부되는지 각각 테스트한다. `valid_execute_kwargs()`에도 두 Override를 포함하지 않는다.

  Workflow를 다음 순서로 구현한다.

  1. POSIX Execute Gate
  2. Plan JSON/SHA와 resolved DB Path 비교
  3. Migration, 확인 문자열, existing `artifact_dir`, 생성 경로 Git ignore 검증
  4. `with acquire_recovery_locks(locks):`로 실제 고유 Lock 획득
  5. Repository/Git/Untracked Inventory/Canonical Plan 1차 재검증과 전역 RUNNING Gate
  6. Transaction 밖 live DB `integrity_check`/`foreign_key_check`
  7. SQLite Backup API 실행과 Backup SHA/DB 검증
  8. 같은 Connection의 `PRAGMA data_version`을 보조 신호로 비교
  9. `BEGIN IMMEDIATE`
  10. Canonical Plan 전체 재생성 및 Plan File Payload/SHA 비교
  11. Mutation 직전 `connection.total_changes` 저장
  12. 조건부 UPDATE 1건, Audit INSERT 1건
  13. Checkpoint/Audit/다른 Checkpoint/FK와 `total_changes - before == 2` 검증
  14. COMMIT
  15. 별도 Connection에서 live DB 전체 검증과 Result JSON Atomic write

  Production Execute는 Task 9의 저수준 `lock_factory` 주입점을 외부로 전달하지 않고 항상 다음 구조로 실제 Lock 구현을 사용한다.

  ```python
  with acquire_recovery_locks(locks):
      return _execute_locked_recovery(...)
  ```

  Task 9의 `acquire_recovery_locks(..., lock_factory=...)`는 Lock 순서·충돌 단위 테스트에만 유지한다. Task 11·12의 Execute 통합 테스트는 이 저수준 인자를 공개 Execute 호출로 전달하지 않는다.

  Transaction 내부에서는 전체 `integrity_check`를 실행하지 않고 변경 Row, Audit Row, 다른 Checkpoint Snapshot, FK만 검증한다.

  `artifact_dir` 최상위는 Execute 전에 존재해야 한다. `operation_id`는 `uuid.uuid4()`로 생성하고, 실제 `backup_path`, Backup `.sha256`, `result_path`를 `artifact_dir / operation_id` 아래에서 계산한다. `artifact_dir`와 세 실제 파일 경로를 Task 5의 Gate로 모두 검증한 뒤 `operation_id` Directory만 생성하고 Backup을 시작한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "execute or backup or transaction or conditional or audit_row or total_changes" -q`

  Expected: PASS; 성공 Transaction의 `total_changes` Delta는 정확히 2다.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/packet_checkpoint_recovery_repository.py edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Packet Checkpoint Recovery Transaction 추가"
  ```

### Task 12: Execute CLI와 Exit Code 2/3·HOLD

**Files:**
- Modify: `edge/detection/run_packet_checkpoint_recovery.py`
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `tests/test_packet_checkpoint_recovery.py`

**Interfaces:**
- Produces: `PacketCheckpointRecoveryError`, `PacketCheckpointRecoveryCommittedArtifactError(operation_id, backup_path)`, Execute JSON Output.
- Execute 필수 입력: `--plan-file`, `--db-path`, `--artifact-dir`, `--confirm`; 처리 가능 Session Skip Plan에는 `--confirm-skip-processable` 추가 필수.

- [ ] **Step 1: CLI Exit/HOLD 테스트 작성**

  테스트 이름:

  - `test_execute_cli_success_returns_zero_and_writes_result_json`
  - `test_execute_cli_precommit_failure_returns_two_without_database_change`
  - `test_execute_cli_postcommit_integrity_failure_returns_three_and_hold`
  - `test_execute_cli_result_json_failure_returns_three_and_preserves_commit_audit_backup`
  - `test_execute_cli_never_auto_restores_committed_database`
  - `test_execute_cli_requires_plan_file_database_artifact_and_confirmation`
  - `test_execute_cli_returns_two_for_windows_platform_rejection`
  - `test_execute_cli_rejects_platform_name_option`
  - `test_execute_holds_all_locks_through_post_commit_verification_and_result_write`

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "execute_cli or postcommit or hold" -q`

  Expected: FAIL — Exit Code 3/HOLD 예외 매핑이 없다.

- [ ] **Step 3: CLI 예외 매핑과 Atomic Result 구현**

  ```python
  def _run_command(args: argparse.Namespace) -> dict[str, object]:
      if args.command == "dry-run":
          return inspect_packet_checkpoint_recovery(
              db_path=args.db_path,
              repository_root=args.repository_root,
              detector_name=args.detector,
              current_session_id=args.current_session_id,
              target_session_id=args.target_session_id,
              approved_by=args.approved_by,
              reason=args.reason,
              plan_output=args.plan_output,
              orchestrator_lock_path=args.orchestrator_lock_path,
              manual_lock_path=args.manual_lock_path,
              extractor_lock_path=args.extractor_lock_path,
          )
      return execute_packet_checkpoint_recovery(
          plan_file=args.plan_file,
          db_path=args.db_path,
          artifact_dir=args.artifact_dir,
          confirm=args.confirm,
          confirm_skip_processable=args.confirm_skip_processable,
      )

  def main(argv: Sequence[str] | None = None) -> int:
      args = build_parser().parse_args(argv)
      try:
          payload = _run_command(args)
      except PacketCheckpointRecoveryCommittedArtifactError as exc:
          print(json.dumps({
              "ok": False,
              "database_committed": True,
              "operation_status": "HOLD",
              "operation_id": exc.operation_id,
              "backup_path": str(exc.backup_path),
              "error": str(exc),
          }, sort_keys=True))
          return 3
      except PacketCheckpointRecoveryError as exc:
          print(json.dumps({"ok": False, "database_committed": False, "error": str(exc)}, sort_keys=True))
          return 2
      print(json.dumps(payload, sort_keys=True))
      return 0
  ```

  Commit 후 live DB 검증 또는 Result JSON 실패 시 Checkpoint/Audit/Backup을 유지하고 자동 Restore를 금지한다. Result에는 `database_committed=true`, `operation_status=HOLD`를 표시한다. CLI의 성공·Exit 3 Mapping 테스트는 Core 함수를 Monkeypatch해 플랫폼과 무관한 출력 계약만 확인한다. Lock 수명 통합 테스트는 `_current_platform_name()`을 `lambda: "posix"`로 Monkeypatch하고 `recovery.acquire_recovery_locks`를 해제 시점을 기록하는 Context Manager Test Double로 Monkeypatch해 모든 Lock이 성공 Result write와 Commit 후 HOLD 처리까지 유지되는지 검증한다. 공개 Execute 호출에는 `lock_factory`를 전달하지 않는다. Windows Execute 거부는 Exit 2이며 Lock 획득 함수, Backup Factory, Artifact Writer, DB Mutation Spy의 호출 수가 모두 0이어야 한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "execute_cli or postcommit or hold" -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/run_packet_checkpoint_recovery.py edge/detection/packet_checkpoint_recovery.py tests/test_packet_checkpoint_recovery.py
  git commit -m "feat: Packet Checkpoint Recovery Execute CLI 추가"
  ```

### Task 13: Packet Rule Manual Runner의 `run_until_for_capture_session` 적용

**Files:**
- Modify: `edge/detection/run_packet_rule_detector.py`
- Modify: `tests/test_packet_rule_runner.py`

**Interfaces:**
- Consumes: 기존 `PacketRuleDetectorStage.run_until_for_capture_session(db, *, cycle_range_start, cycle_cutoff, expected_capture_session_id)`.
- Produces: Manual Runner의 `--session-id`와 실제 Source Selection이 동일 Session으로 바인딩되는 계약.

- [ ] **Step 1: Session-bound 호출 테스트를 먼저 수정**

  ```python
  def test_manual_packet_rule_runner_binds_stage_to_requested_capture_session(monkeypatch) -> None:
      stage = FakeStage()
      monkeypatch.setattr(runner, "PacketRuleDetectorStage", lambda: stage)
      argv = [
          "--session-id", SESSION_ID,
          "--range-start", "2026-08-06T10:00:00Z",
          "--cutoff", "2026-08-06T10:01:00Z",
      ]
      assert runner.main(argv) == 0
      assert stage.capture_session_calls == [{
          "expected_capture_session_id": SESSION_ID,
          "cycle_range_start": RANGE_START,
          "cycle_cutoff": CUTOFF,
      }]
      assert stage.unbound_call_count == 0
  ```

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_rule_runner.py::test_manual_packet_rule_runner_binds_stage_to_requested_capture_session -q`

  Expected: FAIL — Runner가 현재 `stage.run_until()`을 호출한다.

- [ ] **Step 3: 호출부 한 곳만 최소 수정**

  ```python
  result = stage.run_until_for_capture_session(
      db,
      cycle_range_start=args.range_start,
      cycle_cutoff=args.cutoff,
      expected_capture_session_id=args.session_id,
  )
  ```

  `_validate_manual_range`, Lock, Transaction, JSON Output 계약은 변경하지 않는다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_rule_runner.py tests/test_packet_rule_detector.py -q`

  Expected: PASS; Gap 거부와 단일 Transaction 회귀도 유지된다.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/run_packet_rule_detector.py tests/test_packet_rule_runner.py
  git commit -m "fix: Packet Rule Manual Runner Session 바인딩"
  ```

### Task 14: Packet IF Manual Runner의 `run_until_for_capture_session` 적용

**Files:**
- Modify: `edge/detection/run_packet_ai_detector.py`
- Modify: `tests/test_run_packet_ai_detector.py`

**Interfaces:**
- Consumes: 기존 `PacketIsolationForestStage.run_until_for_capture_session(db, *, cycle_range_start, cycle_cutoff, expected_capture_session_id)`.
- Produces: Manual Packet IF Runner의 Session-bound Source Selection.

- [ ] **Step 1: Session-bound 호출 테스트를 먼저 수정**

  ```python
  def test_manual_packet_if_runner_binds_stage_to_requested_capture_session(monkeypatch) -> None:
      stage = FakeStage()
      monkeypatch.setattr(runner.PacketIsolationForestStage, "from_settings", lambda **_: stage)
      argv = [
          "--session-id", SESSION_ID,
          "--range-start", "2026-08-06T10:00:00Z",
          "--cutoff", "2026-08-06T10:01:00Z",
      ]
      assert runner.main(argv) == 0
      assert stage.capture_session_calls[0]["expected_capture_session_id"] == SESSION_ID
      assert stage.unbound_call_count == 0
  ```

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_run_packet_ai_detector.py::test_manual_packet_if_runner_binds_stage_to_requested_capture_session -q`

  Expected: FAIL — Runner가 현재 `stage.run_until()`을 호출한다.

- [ ] **Step 3: 호출부 한 곳만 최소 수정**

  ```python
  result = stage.run_until_for_capture_session(
      db,
      cycle_range_start=args.range_start,
      cycle_cutoff=args.cutoff,
      expected_capture_session_id=args.session_id,
  )
  ```

  Artifact/Model 검증, `_validate_manual_range`, Lock, Transaction, JSON Output은 유지한다.

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_run_packet_ai_detector.py tests/test_packet_ai_detector.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```powershell
  git add edge/detection/run_packet_ai_detector.py tests/test_run_packet_ai_detector.py
  git commit -m "fix: Packet IF Manual Runner Session 바인딩"
  ```

### Task 15: 보호 테이블·다른 Checkpoint 불변성 테스트

**Files:**
- Modify: `tests/test_packet_checkpoint_recovery.py`
- Modify: `edge/detection/packet_checkpoint_recovery.py`
- Modify: `edge/detection/packet_checkpoint_recovery_repository.py`

**Interfaces:**
- Consumes: Task 11의 Execute API.
- Produces: `snapshot_protected_rows(connection: sqlite3.Connection, *, requested_checkpoint_key: tuple[str, str]) -> dict[str, tuple[tuple[object, ...], ...]]`와 허용된 두 Row 외 DB·PCAP 불변 실행 증거.

- [ ] **Step 1: 보호 대상의 실제 Row/파일 Snapshot 테스트 작성**

  ```python
  PROTECTED_TABLES = (
      "detection_events", "trust_score_history", "devices", "isolation_history",
      "firewall_rules", "mqtt_logs", "feature_logs", "packet_capture_sessions",
      "packet_capture_segments", "packet_feature_logs",
  )

  def test_snapshot_protected_rows_excludes_only_requested_checkpoint(tmp_path: Path):
      fixture = create_recovery_fixture(tmp_path)
      with sqlite3.connect(fixture.db_path) as connection:
          snapshot = snapshot_protected_rows(
              connection,
              requested_checkpoint_key=(fixture.detector_name, "packet_feature_logs"),
          )
      assert "detector_checkpoints" in snapshot
      assert all(
          row[:2] != (fixture.detector_name, "packet_feature_logs")
          for row in snapshot["detector_checkpoints"]
      )

  def test_execute_changes_only_requested_checkpoint_and_one_audit_row(
      tmp_path: Path,
      monkeypatch,
  ):
      fixture = create_recovery_fixture(tmp_path)
      monkeypatch.setattr(recovery, "_current_platform_name", lambda: "posix")
      monkeypatch.setattr(
          recovery,
          "acquire_recovery_locks",
          lambda locks: nullcontext(),
      )
      inspect_packet_checkpoint_recovery(**valid_dry_run_kwargs(fixture))
      before = database_snapshot(fixture.db_path, PROTECTED_TABLES)
      checkpoints_before = checkpoint_snapshot(fixture.db_path)
      pcap_hashes = file_hash_snapshot(fixture.pcap_dir)
      execute_packet_checkpoint_recovery(
          **valid_execute_kwargs(fixture, fixture.plan_output)
      )
      assert database_snapshot(fixture.db_path, PROTECTED_TABLES) == before
      assert unchanged_checkpoint_rows(
          checkpoints_before,
          checkpoint_snapshot(fixture.db_path),
          requested_key=(fixture.detector_name, "packet_feature_logs"),
      )
      assert file_hash_snapshot(fixture.pcap_dir) == pcap_hashes
  ```

  추가 테스트:

  - `test_packet_rule_recovery_does_not_change_packet_if_or_trust_checkpoint`
  - `test_packet_if_recovery_does_not_change_packet_rule_or_trust_checkpoint`
  - `test_failed_execute_keeps_all_protected_tables_and_checkpoint_rows_unchanged`
  - `test_execute_does_not_modify_untracked_file_zero_or_pcap_files`

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "changes_only or does_not_change or protected or untracked_file_zero" -q`

  Expected: FAIL — `snapshot_protected_rows()`가 아직 정의되지 않았다.

- [ ] **Step 3: 보호 Snapshot 함수와 Execute 비교를 최소 구현**

  `snapshot_protected_rows()`는 `PROTECTED_TABLES` 전체와 요청 Key를 제외한 모든 `detector_checkpoints` Row를 고정 `ORDER BY`로 읽는다. Execute는 Mutation 직전 Snapshot과 Transaction 내부 검증 Snapshot을 비교한다. 변경 허용 SQL은 요청 Detector Checkpoint의 조건부 UPDATE와 Audit INSERT뿐이며, PCAP과 untracked 파일은 외부 SHA Snapshot 테스트로 불변성을 확인한다.

  ```python
  PROTECTED_TABLES = (
      "detection_events", "trust_score_history", "devices", "isolation_history",
      "firewall_rules", "mqtt_logs", "feature_logs", "packet_capture_sessions",
      "packet_capture_segments", "packet_feature_logs",
  )

  def snapshot_protected_rows(connection, *, requested_checkpoint_key):
      snapshot = {
          table: tuple(connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall())
          for table in PROTECTED_TABLES
      }
      snapshot["detector_checkpoints"] = tuple(connection.execute(
          """
          SELECT * FROM detector_checkpoints
          WHERE NOT (detector_name = ? AND source_table = ?)
          ORDER BY detector_name, source_table
          """,
          requested_checkpoint_key,
      ).fetchall())
      return snapshot
  ```

- [ ] **Step 4: GREEN 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -q`

  Expected: PASS; 성공 시 Target Checkpoint 1건과 Audit 1건 외 Row/파일 Digest가 동일하다.

- [ ] **Step 5: Commit**

  ```powershell
  git add tests/test_packet_checkpoint_recovery.py edge/detection/packet_checkpoint_recovery.py edge/detection/packet_checkpoint_recovery_repository.py
  git commit -m "test: Gap Recovery 보호 데이터 불변성 검증"
  ```

### Task 16: 인접·전체 회귀 테스트

**Files:**
- Verify only; 신규 변경 파일 없음.

**Interfaces:**
- Consumes: Tasks 1~15 전체 구현.
- Produces: Migration, Packet Repository/Readiness, Manual Runner, Orchestrator Gap 차단, Runtime Lock, Cutover, Trust 안전 계약의 회귀 결과.

- [ ] **Step 1: 집중·인접 테스트 실행**

  Run:

  ```powershell
  C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py tests/test_migrations.py tests/test_packet_repositories.py tests/test_packet_stage_readiness.py tests/test_packet_rule_detector.py tests/test_packet_rule_runner.py tests/test_packet_ai_detector.py tests/test_run_packet_ai_detector.py tests/test_detection_orchestrator_runner.py tests/test_runtime_lock.py tests/test_phase4_cutover.py tests/test_baseline_recovery.py tests/test_trust_compensation.py -q
  ```

  Expected: PASS; Orchestrator의 자동 Gap 차단 테스트가 그대로 통과한다. Windows에서는 Task 9 저수준 Lock Factory 주입과 `recovery.acquire_recovery_locks` Workflow Monkeypatch로 함수·Workflow 계약만 검증하며 실제 POSIX Lock 상호운용 통과로 보고하지 않는다.

- [ ] **Step 2: Windows Bash Wrapper 제외 전체 회귀 실행**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest -q --ignore=tests/test_firewall_rule_wrapper.py`

  Expected: PASS with no new failures.

- [ ] **Step 3: 전체 pytest를 별도로 실행해 기존 Windows 환경 실패 구분**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest -q`

  Expected: `tests/test_firewall_rule_wrapper.py`의 기존 Windows Bash/CP949 계열 실패 외 신규 실패 0. 실패 수와 이름은 실제 출력 그대로 기록한다.

- [ ] **Step 4: 정적·Diff 검증**

  Run:

  ```powershell
  C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m compileall -q backend edge tests
  git diff --check origin/develop...HEAD
  git status --short
  ```

  Expected: compileall과 diff check PASS; Status에는 의도한 구현 파일만 나타난다.

- [ ] **Step 5: 회귀 실패 처리 Gate**

  신규 실패가 있으면 커밋·Push를 중단하고 최초 실패부터 원인을 수정한 뒤 Task 16의 모든 명령을 처음부터 재실행한다. 검증만으로 변경이 없다면 빈 Commit을 만들지 않는다.

### Task 17: Runbook·DB Schema·Detection Core 문서 갱신

**Files:**
- Create: `docs/packet-checkpoint-gap-recovery-runbook.md`
- Modify: `docs/db-schema.md`
- Modify: `docs/phase4-detection-core.md`

**Interfaces:**
- Consumes: 최종 CLI 인자, Exit Code, Migration 005, Lock/Transaction/Session 계약.
- Produces: 병합 후 운영자가 별도로 수행할 Migration·Dry-run·Execute·Manual Detector 검증 절차.

- [ ] **Step 1: 문서 계약 검증 테스트를 먼저 정의**

  `tests/test_packet_checkpoint_recovery.py`에 다음 이름의 문서 Smoke Test를 추가한다.

  - `test_gap_recovery_runbook_separates_migration_dry_run_and_execute`
  - `test_gap_recovery_runbook_documents_service_process_and_running_session_gates`
  - `test_gap_recovery_runbook_documents_exit_three_hold_and_no_auto_restore`
  - `test_gap_recovery_runbook_documents_cross_platform_dry_run_and_posix_only_execute`
  - `test_gap_recovery_runbook_requires_existing_plan_parent_and_artifact_directory`
  - `test_gap_recovery_docs_preserve_orchestrator_gap_block_and_holdout_e2e_scope`

  각 테스트는 필수 명령 토큰과 정책 문구를 UTF-8로 읽어 확인한다. 실제 DB·Pi 명령을 실행하지 않는다.

- [ ] **Step 2: RED 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "runbook or recovery_docs" -q`

  Expected: FAIL — Runbook이 아직 없거나 필수 계약이 없다.

- [ ] **Step 3: 세 문서에 확정된 운영 계약 기록**

  `docs/packet-checkpoint-gap-recovery-runbook.md`에는 순서대로 다음을 작성한다.

  1. Migration 005 Backup·검증·별도 적용 단계
  2. Dry-run은 Windows/POSIX 지원, Execute는 공개 플랫폼 Override 없이 실제 OS를 검사하며 Raspberry Pi의 POSIX에서만 수행하고 Windows Execute는 금지
  3. 실제 POSIX `flock` 상호운용은 병합 후 Pi 운영 DB가 아닌 복사 DB Smoke에서 확인
  4. Repository Root에서 tracked/staged clean 확인과 untracked inventory 보존
  5. `plan_output.parent`와 최상위 `artifact_dir` 사전 생성·권한·Git ignore 확인
  6. 관련 systemd enabled/active 기록, active Writer 중지, Packet Capture/공격/Extractor/Manual Runner 미실행 확인
  7. 전역 RUNNING Session 0, 현재 Session 소진, Target COMPLETED/full-ready SQL
  8. Dry-run 명령과 Plan SHA/DB Path/Lock/Skip/RUNNING Summary 검토
  9. 처리 가능 Session Skip 시 SHA-bound 두 번째 확인
  10. Execute, Exit 2 사전 실패, Exit 3 HOLD, 자동 Restore 금지
  11. 사후 Checkpoint/Audit/Backup SHA/integrity/FK/보호 Table 확인
  12. 승인된 Target Session으로 Packet Rule 또는 Packet IF Manual Runner 실행
  13. Recovery 전에 active였던 서비스만 복구
  14. 공식 Trust/Firewall E2E는 병합 후 새 Holdout Session에서 별도 수행

  `docs/db-schema.md`에는 Migration `(5, packet_checkpoint_recovery)`와 `packet_checkpoint_recoveries` Column/Unique/FK/불변 Check를 추가한다. `docs/phase4-detection-core.md`에는 Orchestrator 자동 Gap 차단 유지, Recovery의 Detector별 독립 승인, Manual Runner의 `run_until_for_capture_session()` 사용을 추가한다.

- [ ] **Step 4: GREEN과 문서 검색 확인**

  Run: `C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest tests/test_packet_checkpoint_recovery.py -k "runbook or recovery_docs" -q`

  Expected: PASS.

  Run: `rg -n "Migration 005|RUNNING|SKIP-PROCESSABLE-SESSIONS|Exit Code 3|HOLD|run_until_for_capture_session|Holdout" docs/packet-checkpoint-gap-recovery-runbook.md docs/db-schema.md docs/phase4-detection-core.md`

  Expected: 각 계약이 지정 문서에 존재하며 자동 Gap 통과나 운영 DB 실행 완료 표현이 없다.

- [ ] **Step 5: 최종 전체 검증과 Commit**

  Run:

  ```powershell
  C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m pytest -q --ignore=tests/test_firewall_rule_wrapper.py
  C:\Users\woomin\Desktop\iot-edge-zero-trust\venv\Scripts\python.exe -m compileall -q backend edge tests
  git diff --check origin/develop...HEAD
  ```

  Expected: 모든 명령 PASS.

  ```powershell
  git add docs/packet-checkpoint-gap-recovery-runbook.md docs/db-schema.md docs/phase4-detection-core.md tests/test_packet_checkpoint_recovery.py
  git commit -m "docs: Packet Checkpoint Gap Recovery 운영 계약 추가"
  ```

## 설계 요구사항 추적표

| 설계 요구사항 | 구현 Task |
|---|---|
| Migration 005 별도 적용과 Audit | 1, 2, 10, 17 |
| Canonical Plan·결정적 SHA·Plan JSON 입력 | 3, 10, 11, 12 |
| tracked/staged 거부·untracked inventory 보존 | 4, 10, 11 |
| untracked Symlink·FIFO·Socket 등 비일반 Entry 거부 | 4, 10, 11 |
| Repository 내부 생성 경로 Git ignore Gate | 5, 9, 10, 11 |
| Plan Parent·Artifact Directory 사전 존재 | 5, 10, 11, 17 |
| resolved absolute DB Path 바인딩 | 6, 10, 11 |
| 기존 Helper와 Readiness 의미 Parity | 7, 16 |
| Target full-ready 강화·전역 RUNNING Gate | 7, 10, 11 |
| Target Segment 전체·정확히 1회 Prefix 소비 | 7, 10, 11 |
| full-ready Session Skip 분류·추가 승인 | 8, 10, 12 |
| 실제 Lock 경로·중복 제거·정렬 획득 | 9, 11 |
| Windows/POSIX Dry-run·POSIX 전용 Execute | 10, 11, 12, 17 |
| 공개 플랫폼 Override 없는 실제 OS Gate | 11, 12, 17 |
| 공개 Lock Factory Override 없는 실제 Lock 획득 | 9, 11, 12 |
| 실제 POSIX Lock 상호운용은 병합 후 Pi 복사 DB Smoke | 9, 17 |
| Backup·TOCTOU·조건부 UPDATE·Audit·Delta 2 | 11 |
| Exit 2/3·Commit 후 HOLD | 12 |
| Rule/IF Session-bound Manual Runner | 13, 14 |
| Trust/보호 Table/다른 Checkpoint 불변 | 15 |
| 인접·전체 회귀 | 16 |
| 운영 Runbook·Schema·Detection 문서 | 17 |
| Orchestrator 자동 Gap 통과 제외 | 16, 17 |
| 공식 E2E를 새 Holdout Session으로 분리 | 17 |

## 구현 완료 판정

- 요청 Detector의 `last_processed_id`는 유지되고 시간 경계만 Target `first_window_start`로 전진한다.
- Checkpoint 1건과 Audit 1건 외 DB Row, PCAP, untracked 파일은 불변이다.
- Dry-run Plan과 Execute 재생성 Plan의 Canonical Payload/SHA가 동일하고 다른 DB Path에서는 재사용되지 않는다.
- Untracked Inventory는 `lstat()`·`fstat()`으로 확인한 일반 파일만 Hash하며 Symlink와 기타 비일반 Entry를 변경 없이 거부한다.
- Target full-ready는 모든 Segment가 정확히 한 번 연속 Prefix에 소비되고 `segment_count == len(rows)`일 때만 성립한다.
- 처리 가능 Session Skip은 Plan SHA에 바인딩된 추가 확인 없이는 실행되지 않는다.
- 모든 실제 고유 Lock은 Repository Root 기준 절대경로로 계산해 정렬·단일 획득하고 사후 검증까지 유지한다.
- 공개 Execute API에는 `lock_factory` Override가 없으며 Production Execute는 항상 `acquire_recovery_locks(locks)`로 실제 Lock을 획득한다.
- Dry-run은 Windows와 POSIX에서 동작하고, Execute는 공개 Override 없이 실제 `os.name`을 검사하여 POSIX가 아니면 어떤 Lock·Backup·Artifact·DB 변경 전에도 Exit 2로 거부된다.
- Plan 상위 Directory와 최상위 Artifact Directory는 미리 존재하며, CLI는 Plan 상위를 만들지 않고 Execute는 Artifact 아래 operation Directory만 만든다.
- Migration 미적용, RUNNING Session, Git 상태/Inventory/경로/Checkpoint/Readiness/TOCTOU 불일치는 Backup 또는 Mutation 전에 차단된다.
- Commit 전 실패는 Exit 2와 Rollback, Commit 후 검증·Artifact 실패는 Exit 3/HOLD로 구분된다.
- Manual Rule/IF Runner는 요청 Session에 바인딩되며 Orchestrator의 자동 Gap 차단은 유지된다.
- 운영 DB Migration·Recovery와 Raspberry Pi Holdout E2E는 병합 후 별도 운영 승인 단계로 남는다.
