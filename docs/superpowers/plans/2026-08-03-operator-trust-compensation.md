# Operator Trust Compensation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 운영자가 승인한 Trust Score v2 Source Event 한 건의 실제 감점만 자동 역산해 복구하고, 기존 이력을 보존하는 감사 가능한 CLI를 제공한다.

**Architecture:** Migration 004가 전용 `trust_score_compensations` 감사 테이블을 추가한다. `trust_compensation.py`는 SQLite read-only 사전검사와 `BEGIN IMMEDIATE` 기반 Execute를 담당하고, `run_trust_compensation.py`는 입력·JSON·종료 코드를 담당한다. 보상값은 Source History의 `actual_delta`로만 계산하며 Device status는 변경하지 않는다.

**Tech Stack:** Python 3.10, stdlib `sqlite3`, `argparse`, `hashlib`, `json`, Pytest, SQLite Migration Runner

## Global Constraints

- Base는 `origin/develop`의 `afbc72f5d5a7cd5ebe91da28eebe38e62446cd63`이다.
- 브랜치는 `feature/operator-trust-compensation`이다.
- 운영 DB, Raspberry Pi, systemd, iptables, ESP32에 접근하지 않는다.
- 기존 Detection Event, Trust Score History와 다른 운영 이력을 UPDATE·DELETE하지 않는다.
- 한 번에 Device 한 대와 Source Event 한 건만 처리한다.
- 운영자가 보상값이나 최종 점수를 입력하는 옵션을 추가하지 않는다.
- API와 Frontend를 변경하지 않는다.
- Baseline Recovery를 공통화하거나 리팩터링하지 않는다.
- Draft PR까지만 만들고 병합하지 않는다.

---

### Task 1: Migration 004 감사 테이블

**Files:**
- Create: `db/migrations/004_trust_score_compensation.sql`
- Modify: `tests/test_migrations.py`

**Interfaces:**
- Consumes: `db.migration_runner.apply_migrations()`의 연속 Migration 발견·적용 계약
- Produces: `trust_score_compensations` 테이블과 FK·CHECK·UNIQUE 제약

- [ ] **Step 1: 신규 DB Schema 실패 테스트 작성**

`tests/test_migrations.py`에 신규 DB에 Migration을 적용한 뒤 컬럼, FK와 제약을
검증하는 `test_trust_score_compensation_schema_and_constraints`를 추가한다. 실제
Device, Event, History를 넣고 정상 감사 Row를 INSERT한 뒤 다음 변경이
`sqlite3.IntegrityError`인지 확인한다.

```python
assert {
    "id", "operation_id", "device_id", "source_event_id",
    "source_trust_history_id", "previous_score", "compensation_delta",
    "new_score", "reason", "approved_by", "backup_path",
    "backup_sha256", "created_at",
} <= _column_names(connection, "trust_score_compensations")
```

검증할 실패는 중복 operation/event/history, 0 이하 delta, 범위 밖 점수,
산술 불일치, 빈 reason/approved_by/path, 잘못된 SHA와 FK 삭제다.

- [ ] **Step 2: 기존 003 DB Upgrade 실패 테스트 작성**

`test_trust_score_compensation_migration_applies_004_to_existing_003`에서 001~003만
적용한 DB에 기존 Device·Event·History를 넣고 전체 Migration을 실행한다.

```python
assert result.applied_versions == [4]
assert _migration_versions(connection) == [1, 2, 3, 4]
assert preserved_event == original_event
assert preserved_history == original_history
```

- [ ] **Step 3: RED 확인**

Run:

```powershell
python -m pytest tests/test_migrations.py -k trust_score_compensation -q
```

Expected: Migration 004가 없어 테이블 또는 version 4 assertion 실패.

- [ ] **Step 4: Migration 최소 구현**

`004_trust_score_compensation.sql`에 설계 문서의 `CREATE TABLE`만 추가한다.
Migration Runner는 수정하지 않는다.

- [ ] **Step 5: GREEN 확인**

```powershell
python -m pytest tests/test_migrations.py -k trust_score_compensation -q
```

Expected: 신규 Migration 테스트 통과.

### Task 2: Read-only 사전검사와 자동 계산

**Files:**
- Create: `edge/trust/trust_compensation.py`
- Create: `tests/test_trust_compensation.py`

**Interfaces:**
- Produces: `TrustCompensationError`, `CONFIRMATION`,
  `inspect_trust_compensation(...) -> dict[str, object]`
- Consumes: `edge.trust.trust_policy.status_for_trust_score`

- [ ] **Step 1: 성공 Dry-run RED 테스트 작성**

독립 DB Fixture에 `normal/80` Device, 처리 완료 Event와
`policy_version='trust-score-v2'`, `actual_delta=-20`, 대표 ID `[event_id]`인
History를 저장한다.

```python
result = core.inspect_trust_compensation(
    db_path=db_path,
    device_id="esp32_01",
    source_event_id=event_id,
    expected_status="normal",
    expected_trust_score=80,
    reason="subscriber backlog false positive",
    approved_by="operator@example",
    artifact_dir=tmp_path / "artifacts",
)
assert result["can_execute"] is True
assert result["compensation"]["compensation_delta"] == 20
assert result["compensation"]["proposed_score"] == 100
assert not (tmp_path / "artifacts").exists()
```

- [ ] **Step 2: Source 계약 RED 테스트 작성**

각 테스트는 한 조건만 바꿔 `can_execute=False`와 DB·Artifact 불변을 확인한다.

- Device 없음, status/score 예상값 불일치
- current status가 `status_for_trust_score(current_score)`와 불일치
- Event 없음, 다른 Device, `applied_to_score=0`, 미처리,
  `processing_reason!='APPLIED_TO_TRUST'`, 비음수 score_delta
- History 없음·여러 건, 잘못된 policy version, 비음수 actual_delta,
  산술 불일치, Event delta 불일치
- 대표 JSON 손상, 문자열 ID, 여러 ID
- 기존 Compensation, 미처리 Event, 활성 Firewall Rule
- proposed score 100 초과와 proposed 정책 status 변화
- Migration 미적용 DB

- [ ] **Step 3: RED 확인**

```powershell
python -m pytest tests/test_trust_compensation.py -q
```

Expected: 신규 모듈 부재로 실패.

- [ ] **Step 4: Core Read-only 최소 구현**

다음 public signature를 구현한다.

```python
def inspect_trust_compensation(
    *, db_path: str | Path, device_id: str, source_event_id: int,
    expected_status: str, expected_trust_score: int,
    reason: str, approved_by: str, artifact_dir: str | Path,
) -> dict[str, object]:
    ...
```

내부 `_inspect_connection()`은 Migration, Device, Event, History, 기존 감사,
미처리 Event와 Firewall을 검증하고 literal `compensation_delta`와
`proposed_score`를 계산한다. History JSON은 Python `json.loads()`로 파싱하고
`type(value) is int`인 한 요소 배열만 허용한다.

- [ ] **Step 5: GREEN 확인**

```powershell
python -m pytest tests/test_trust_compensation.py -q
```

Expected: Dry-run과 모든 사전검사 통과.

### Task 3: Backup·Transaction·감사 INSERT

**Files:**
- Modify: `edge/trust/trust_compensation.py`
- Modify: `tests/test_trust_compensation.py`

**Interfaces:**
- Produces: `execute_trust_compensation(...) -> dict[str, object]`와 Commit 후
  Artifact 실패를 나타내는 `TrustCompensationCommittedArtifactError`
- Consumes: Task 2의 `_inspect_connection()` 결과

- [ ] **Step 1: 성공 Execute RED 테스트 작성**

```python
result = core.execute_trust_compensation(
    db_path=db_path,
    device_id="esp32_01",
    source_event_id=event_id,
    expected_status="normal",
    expected_trust_score=80,
    reason="subscriber backlog false positive",
    approved_by="operator@example",
    artifact_dir=tmp_path / "artifacts",
    confirm="APPLY-TRUST-COMPENSATION",
)
assert result["result"] == "SUCCESS"
assert _device_state(db_path, "esp32_01") == ("normal", 100)
assert _compensation_rows(db_path) == [(event_id, history_id, 80, 20, 100)]
```

Backup 파일·SHA와 integrity/FK, 성공 JSON도 실제 파일로 확인한다.

- [ ] **Step 2: Rollback RED 테스트 작성**

다음 실패마다 Device, Event, Source History와 감사 테이블 불변을 확인한다.

- 잘못된 confirmation
- Backup 생성 실패
- Backup integrity/FK 실패
- 조건부 UPDATE `rowcount != 1`
- 감사 INSERT Trigger 실패
- Commit 전 DB integrity/FK 실패

- [ ] **Step 3: Commit 후 JSON 실패 RED 테스트 작성**

`_write_json_log`만 실패시키고 `TrustCompensationCommittedArtifactError`가
발생하는지 확인한다. 이때 점수 100, 감사 Row 1개, Backup 파일은 유지되고
Event와 Source History는 불변이어야 한다.

- [ ] **Step 4: RED 확인**

```powershell
python -m pytest tests/test_trust_compensation.py -q
```

Expected: Execute 함수가 없어 실패.

- [ ] **Step 5: Execute 최소 구현**

`BEGIN IMMEDIATE` 이후 모든 사전조건을 재검증하고 Backup을 만든다. 다음 SQL을
사용하며 status 컬럼은 SET하지 않는다.

```sql
UPDATE devices
SET trust_score = :new_score
WHERE device_id = :device_id
  AND status = :expected_status
  AND trust_score = :expected_trust_score
```

`rowcount=1` 뒤 감사 Row를 INSERT하고 Commit 전후 상태와 DB 검증을 수행한다.
JSON은 Commit 후 원자적으로 기록한다.

- [ ] **Step 6: GREEN 확인**

```powershell
python -m pytest tests/test_trust_compensation.py -q
```

Expected: 성공·Rollback·Commit 후 Artifact 실패 계약 통과.

### Task 4: CLI 입력과 종료 코드

**Files:**
- Create: `edge/trust/run_trust_compensation.py`
- Modify: `tests/test_trust_compensation.py`

**Interfaces:**
- Produces: `build_parser()`와 `main(argv: Sequence[str] | None) -> int`
- Consumes: Task 2·3 public Core 함수와 Exception

- [ ] **Step 1: CLI RED 테스트 작성**

- Dry-run 성공 JSON과 Artifact 무생성, 종료 코드 0
- Dry-run 차단 JSON과 종료 코드 2
- Execute 성공 JSON과 종료 코드 0
- 잘못된 confirm, 빈 reason/approved_by, 범위 밖 score와 음수 Event ID 종료 코드 2
- Commit 후 JSON 실패는 stderr에 `database_committed=true`와 Backup 경로를
  포함하고 종료 코드 3
- 보상 delta와 final score를 입력하는 CLI 옵션이 없음

- [ ] **Step 2: RED 확인**

```powershell
python -m pytest tests/test_trust_compensation.py -q
```

Expected: CLI 모듈 부재로 실패.

- [ ] **Step 3: CLI 최소 구현**

`dry-run`과 `execute` subcommand에 공통 입력을 추가한다. Execute는
`--confirm`을 필수화한다. Core 안전 거부는 JSON stderr와 종료 코드 2,
Commit 후 Artifact 실패는 종료 코드 3으로 구분한다.

- [ ] **Step 4: GREEN 확인**

```powershell
python -m pytest tests/test_trust_compensation.py -q
```

Expected: CLI 계약 통과.

### Task 5: 이력 불변성과 운영 문서

**Files:**
- Modify: `tests/test_trust_compensation.py`
- Create: `docs/operator-trust-compensation-runbook.md`
- Modify: `docs/db-schema.md`

**Interfaces:**
- Consumes: 완성된 Core·CLI·Migration
- Produces: 운영 Gate, Dry-run/Execute/검증/HOLD 절차와 Schema 설명

- [ ] **Step 1: 전체 이력 불변 테스트 작성**

성공 Execute 전후 다음 테이블의 Row를 비교한다. 감사 테이블과 선택 Device의
`trust_score`만 달라야 한다.

```python
preserved_tables = (
    "mqtt_logs", "feature_logs", "detection_events", "trust_score_history",
    "isolation_history", "firewall_rules", "detector_checkpoints",
    "gateway_metrics", "packet_capture_sessions", "packet_capture_segments",
    "packet_feature_logs",
)
assert after == before
```

- [ ] **Step 2: Runbook 작성**

서비스 상태 기록, active Writer만 중지, Packet Capture disabled/inactive 유지,
ESP32 전송 중지, Migration 확인, Event·History Read-only SQL, Firewall·pending
Event Gate, Dry-run과 Execute 명령, Backup·감사·JSON 검증, Commit 후 JSON 실패
HOLD와 증적 재구성 절차를 작성한다. 실제 Event 21은 예시로만 사용한다.

- [ ] **Step 3: DB Schema 갱신**

`trust_score_compensations`를 자동 Detection History와 구분해 설명하고 모든
컬럼·FK·UNIQUE·CHECK 의미를 기록한다.

- [ ] **Step 4: 집중 GREEN 확인**

```powershell
python -m pytest tests/test_trust_compensation.py tests/test_migrations.py -q
```

Expected: 신규 기능과 Migration 전체 통과.

### Task 6: 인접·전체 회귀와 출판

**Files:**
- Review: `origin/develop...HEAD` 전체

**Interfaces:**
- Produces: 검증된 Commit, 원격 기능 브랜치, develop 대상 Draft PR

- [ ] **Step 1: 인접 회귀 실행**

```powershell
python -m pytest tests/test_baseline_recovery.py tests/test_phase4_trust_firewall.py tests/test_trust_score_integration.py tests/test_trust_score_service.py tests/test_detection_orchestrator_runner.py -q
```

- [ ] **Step 2: 전체 및 정적 검증 실행**

```powershell
python -m pytest -q
python -m compileall -q backend edge tests
git diff --check
```

Windows Bash Wrapper의 기존 실패와 신규 실패를 구분한다.

- [ ] **Step 3: 변경 범위 자체 검토**

API, Frontend, Firmware, Pi 자산, Baseline Recovery와 기존 Event·History 변경이
없는지 `git diff --name-only origin/develop...HEAD`와 전체 diff로 확인한다.

- [ ] **Step 4: 관련 변경만 커밋하고 Push**

Migration·Core·CLI·테스트·Runbook·Schema·계획 문서만 Stage한다. Commit 메시지는
실제 diff에 맞춰 한국어로 작성하고 `feature/operator-trust-compensation`만 일반
Push한다.

- [ ] **Step 5: Draft PR 생성**

Base `develop`, Head `feature/operator-trust-compensation`으로 Draft PR을 만들고
변경·검증·운영 미실행·병합 전 Gate를 본문에 기록한다. PR은 병합하지 않는다.
