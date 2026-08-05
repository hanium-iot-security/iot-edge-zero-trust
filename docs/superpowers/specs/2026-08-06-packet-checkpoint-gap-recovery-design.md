# Packet Checkpoint Gap Recovery 설계

## 1. 문서 상태와 기준

- 상태: 최종 승인된 설계
- 작성 기준 Commit: `65714579610afa077dbb486a8fee92b020634d1d`
- 구현 기준 브랜치: `feat/packet-checkpoint-gap-recovery`
- 대상 저장소: `hanium-iot-security/iot-edge-zero-trust`
- 대상 DB: SQLite 운영 DB 또는 운영자가 명시한 독립 복사본
- 설계 범위: Packet Detector Checkpoint의 Capture Session Gap 전환

이 문서는 구현 계획이나 운영 실행 기록이 아니다. 구현 전에 지켜야 할 계약과 불변조건을
고정한다. 실제 Raspberry Pi, 운영 DB, systemd, Packet Capture, 공격 프로세스에는 이
설계 단계에서 접근하지 않는다.

## 2. 문제와 목표

Packet Rule과 Packet IF는 `packet_feature_logs`를 Source로 사용하고
`detector_checkpoints.last_completed_window_end` 이후 Window를 처리한다. 현재 Manual
Runner와 Orchestrator의 Packet Readiness Gate는 하나의 Capture Session 내부에서 연속된
`PROCESSED`·`EMPTY` 구간만 허용한다. 한 Detector의 Checkpoint가 과거 COMPLETED Session
끝에 남아 있으면 이후 COMPLETED Session에 처리 가능한 Packet Feature가 있어도 Session
Gap을 자동으로 건너지 않는다.

자동 Gap 연결은 데이터가 존재하지 않는 시간을 정상 데이터로 오인하거나, Packet Rule과
Packet IF 또는 Trust 처리 경계를 서로 다르게 만들 수 있다. 따라서 목표는 운영자가 특정
Detector 하나와 대상 Capture Session을 명시적으로 승인했을 때만 Checkpoint의 시간 경계를
대상 Session 시작점으로 전진시키는 감사 가능한 복구 도구를 제공하는 것이다.

복구는 과거 Packet Feature를 탐지하는 실행 자체가 아니다. 복구 후 Manual Runner가 대상
Session에 바인딩된 범위만 처리하도록 준비하는 운영 단계다.

## 3. 확인된 현재 코드 계약

### 3.1 Source 선택과 Checkpoint

- Packet Rule Detector와 Packet IF Detector의 Source 선택은 Window 시각 범위를 기준으로
  한다.
- `last_processed_id`는 선택된 Source Row의 최대 ID를 기록하지만 다음 Session 선택 경계를
  결정하지 않는다.
- `last_completed_window_end`가 다음 실행 범위의 시간 하한을 결정한다.
- Checkpoint Repository는 `last_processed_id`와 `last_completed_window_end`의 역행을
  거부한다.

### 3.2 Session Readiness

- Packet Readiness는 한 Capture Session의 `first_window_start`부터 연속된 10초 Window
  Prefix로 계산한다.
- `PROCESSED`와 `EMPTY`만 완료 상태로 인정한다.
- 누락 Window, `READY`, `FAILED`, 오류가 있는 Segment 또는 Session Gap에서 Prefix가
  중단된다.
- `PROCESSED` Segment에는 Packet Feature Row가 있어야 하고 `EMPTY` Segment에는 없어야
  한다.

### 3.3 현재 Gap 차단

- Manual Packet Runner는 현재 Checkpoint보다 뒤의 다른 Capture Session을 선택하면 Gap을
  건너는 실행으로 보고 거부한다.
- Orchestrator는 Packet 계층이 처음 활성화되고 관련 Checkpoint가 모두 비어 있을 때만 첫
  Session 경계로 정렬한다.
- 이미 초기화된 Checkpoint의 이후 Session Gap은 자동으로 건너지 않는다.

이 차단 동작은 유지한다. 본 복구 도구만 승인된 Gap을 명시적으로 전환할 수 있다.

## 4. 선택한 접근

Checkpoint를 대상 Session 시작 경계로 감사 가능하게 Rebase하는 운영자 승인형 CLI를
사용한다.

선택 이유는 다음과 같다.

- 기존 Detector Source 선택과 Checkpoint 의미를 유지한다.
- Orchestrator가 임의로 Gap을 정상 구간으로 연결하지 않는다.
- Detector별 승인과 복구 이력을 남길 수 있다.
- Session별 별도 Cursor 체계나 Orchestrator 자동 Gap 정책보다 변경 범위가 작다.
- 8월 시연 전에 기존 Detection·Trust Barrier를 크게 바꾸지 않는다.

Session별 별도 Detector 실행 경로와 Orchestrator 자동 Gap 인식은 이번 범위에서 제외한다.

## 5. Checkpoint 전환 의미

지원하는 Detector Key는 다음 두 개뿐이다.

| Detector | Source Table |
|---|---|
| `packet_rule` | `packet_feature_logs` |
| `packet_if` | `packet_feature_logs` |

복구 전후 계약은 다음과 같다.

```text
last_processed_id_after = last_processed_id_before
last_completed_window_end_after = target_session.first_window_start
updated_at_after = target_session.first_window_start
```

`last_processed_id`를 대상 Session 직전 Row ID로 조작하지 않는다. Packet Detector의 Source
선택이 시간 범위 기반이고, 미래 Session의 Row ID가 과거 Session보다 항상 연속이라는 별도
계약도 없기 때문이다.

`updated_at`은 기존 Runtime Checkpoint가 처리 경계 시각을 기록하는 방식에 맞춰 대상
`first_window_start`로 설정한다. 실제 복구 실행 시각은 Audit의 `created_at`에 별도로 남긴다.

복구 후 Manual Runner는 반드시 대상 Capture Session을 명시해
`run_until_for_capture_session()` 경로를 사용한다. 시간 범위만 전달하는
`run_until()`로 복구 직후 Session을 처리하지 않는다.

## 6. Detector 독립성과 Trust 경계

- `packet_rule`과 `packet_if`는 각각 별도의 Plan, 승인, Backup, Execute 및 Audit이 필요하다.
- 한 명령으로 두 Detector를 함께 전환하는 `--detector all`은 제공하지 않는다.
- 한 Detector를 복구해도 다른 Detector와 Trust Checkpoint는 변경하지 않는다.
- Required Packet Detector들의 경계가 서로 다른 중간 상태에서는 Detection Orchestrator를
  재가동하지 않는다.
- Trust Checkpoint를 과거로 이동하거나 과거 Detection Event를 Trust에 다시 적용하지 않는다.

과거 Session을 Manual Detector로 처리해 Event가 생성되더라도 이미 완료된 Trust Window보다
과거라면 `LATE_EVENT` 처리될 수 있다. 따라서 공식 Trust·Isolation·Firewall E2E는 복구한
과거 Session이 아니라 복구 이후 새로 수집한 Holdout Session으로 수행한다.

## 7. Migration 005와 DB Audit

Migration `005_packet_checkpoint_recovery.sql`은 Recovery Execute와 별도 운영 단계로 적용한다.
Recovery CLI는 Migration을 자동 실행하거나 Table을 생성하지 않는다.

Migration 적용 확인은 다음 두 조건을 모두 요구한다.

1. `schema_migrations`에 정확히 `(5, 'packet_checkpoint_recovery')`가 존재한다.
2. `packet_checkpoint_recoveries` Table과 설계된 Index·Constraint가 존재한다.

불일치하면 Dry-run Plan, Recovery Artifact Directory 및 Backup을 생성하기 전에 거부한다.

Audit Table은 최소 다음 정보를 보존한다.

- `operation_id`
- `detector_name`, `source_table`
- 현재·대상 Capture Session ID
- Checkpoint Before·After 전체 값
- `plan_sha256`와 실행에 사용된 Canonical Plan JSON
- 건너뛴 시간 범위, Session 분류와 개수
- `approved_by`, `reason`
- Repository Commit과 Git 상태·untracked inventory
- resolved absolute Database Path
- Backup Path와 SHA256
- 실행 시각

`operation_id`는 UNIQUE다. `(detector_name, source_table,
target_capture_session_id)`도 UNIQUE로 만들어 같은 Detector가 같은 대상 Session으로 중복
복구되는 것을 DB에서 최종 차단한다. 현재·대상 Session FK는 삭제를 제한한다.

## 8. Canonical Plan과 SHA

Dry-run은 사람이 읽는 요약과 Execute 입력용 Canonical Plan JSON을 만든다. Execute는 SHA
문자열만 받지 않고 `--plan-file`을 필수로 받는다.

Canonical JSON은 UTF-8, Key 정렬, 고정 Separator, UTC 정수 초 `Z` 형식으로 직렬화한다.
`plan_sha256` 필드를 제외한 Canonical Payload의 SHA256을 계산한다.

### 8.1 SHA에 포함하는 필드

- `plan_schema_version`
- `repository_commit`
- resolved Repository Root
- `tracked_worktree_clean`
- `staged_worktree_clean`
- 정렬된 `untracked_inventory`
- resolved absolute Database Path
- Migration version·name과 Table·Index Schema Digest
- Detector와 Source Table
- 승인자와 사유
- Checkpoint Before·After 전체 값
- 현재 Session의 상태, 시간 범위, Ready Through 및 Readiness Digest
- 대상 Session의 상태, 시간 범위, Capture Interface, Segment·Feature 개수 및 Readiness
  Digest
- 건너뛸 시간 범위와 정렬된 Session 목록
- 건너뛴 Session별 상태, Ready 분류, Segment·Feature 개수
- 실제로 획득할 고유 Lock 경로와 각 Lock의 역할
- Mutation 계약과 보호 대상 Table 목록

### 8.2 SHA에서 제외하는 변동 필드

- `plan_sha256`
- Plan 생성 시각과 Execute 시각
- `operation_id`
- 실행 Mode
- Plan·Artifact·Backup·Result 파일 경로
- Backup SHA256
- 재구성된 CLI 문자열
- Git Branch 이름
- 파일 mtime
- `PRAGMA data_version`
- Process ID와 Lock 획득 시각
- Commit 후 검증 시각

Database Path는 실행 대상을 결정하는 값이므로 제외 목록에 들어가지 않는다.

## 9. Repository 상태와 Pi의 untracked 파일

Dirty Worktree 전체를 하나의 Boolean으로 판단하지 않는다.

### 9.1 Tracked·Staged 상태

- tracked file의 unstaged 변경이 있으면 거부한다.
- staged 변경이 있으면 거부한다.
- `repository_worktree_clean` 필드는 사용하지 않는다.
- Plan에는 `tracked_worktree_clean=true`, `staged_worktree_clean=true`를 각각 기록한다.

### 9.2 Untracked inventory

`.gitignore` 대상은 제외하고 Git이 보고하는 모든 untracked 파일을 Repository 상대 POSIX
경로로 정렬한다. 각 파일에 다음을 기록한다.

- 상대 경로
- Byte 크기
- 파일 내용 SHA256

일반 파일이 아닌 untracked Entry가 있으면 안전하게 거부한다. Recovery는 inventory 계산을
위해 파일을 읽을 뿐 삭제·수정·이동·Stage하지 않는다. `git clean`을 호출하지 않는다.

현재 Raspberry Pi에는 보존해야 하는 untracked 파일 `0`이 있으며 운영자가 확인한 값은
다음과 같다.

- size: `4`
- SHA256: `f0448ca7d8645d6c1d4902a2c058a37abfc44f1de59ab54163c80faaf72f6a4c`

이 값은 코드나 허용 목록에 하드코딩하지 않는다. Dry-run 시 실제 경로·크기·SHA256을
계산해 Plan에 기록하고 DB Audit에도 같은 inventory를 저장한다.

Execute는 Plan의 inventory와 실제 inventory를 Backup 전에 비교하고, `BEGIN IMMEDIATE`
이후 Canonical Plan 재생성 시 다시 비교한다. Entry 추가·삭제, 경로 변경, 크기 변경 또는
SHA 변경이 하나라도 있으면 거부한다.

## 10. Database Path 바인딩

`--db-path`는 `expanduser().resolve(strict=True)`로 실제 절대경로를 구한다. 이 resolved
Path를 Canonical Plan과 Plan SHA에 포함한다.

- Execute의 `--db-path` resolved Path가 Plan과 다르면 Lock 또는 Backup 전에 거부한다.
- Symlink가 다른 실제 파일을 가리키면 다른 DB로 취급한다.
- 운영 DB 복사본에서 실행하려면 그 복사본용 Dry-run Plan을 새로 만든다.
- Plan의 DB와 Runtime Settings의 운영 DB가 다르면 운영 Execute로 진행하지 않는다.

이 계약은 동일한 내용의 Snapshot이라도 다른 경로에 있는 DB에 기존 Plan을 재사용하지
못하게 한다.

## 11. 실제 Lock 계약

현재 코드에서 확인된 Lock은 다음과 같다.

| 주체 | 코드상 경로 결정 | 기본 경로 | 관계 |
|---|---|---|---|
| Detection Orchestrator | `ORCHESTRATOR_LOCK_PATH` 또는 DB URL 기반 Resolver | `<DB>.orchestrator.lock` | Manual Runner와 기본값이 다름 |
| Packet Rule Manual Runner | `--lock-path` | `<repo>/data/phase4-detection-cycle.lock` | Packet IF와 기본값 공유 |
| Packet IF Manual Runner | `--lock-path` | `<repo>/data/phase4-detection-cycle.lock` | Packet Rule과 기본값 공유 |
| Packet Feature Extractor | `--lock-path` | `<repo>/data/pcap/.extractor.lock` | 별도 Lock |

상대 Lock Path는 각 기존 실행 주체와 같은 기준인 Repository Working Directory를 기준으로
절대경로화한다. Runbook은 모든 관련 명령을 Repository Root에서 실행하도록 고정한다.

Recovery는 각 역할의 실제 설정을 읽어 `(resolved_path, roles[])` 목록을 만든다. 같은 Path가
여러 역할에서 나오면 역할만 합치고 한 번만 획득한다. 고유 Path를 문자열 오름차순으로
정렬해 non-blocking 방식으로 획득한다. 따라서 기본 설정에서는 세 개일 수 있지만 Lock
개수를 고정 계약으로 두지 않는다.

모든 Lock은 Backup 전부터 Commit 후 DB 검증과 JSON 결과 처리 종료까지 유지한다. 하나라도
획득하지 못하면 DB·Backup·Recovery Artifact를 변경하지 않고 실패한다.

Packet Feature Extractor에는 실제 별도 Lock이 있으므로 Recovery에서 함께 획득한다. 그러나
Lock만으로 systemd 재시작이나 별도 공격 프로세스까지 통제할 수 있다고 보지 않는다.
관련 서비스의 enabled·active 상태 기록, 서비스 중지, Packet Capture·공격 프로세스 미실행
확인은 Runbook Gate로 유지한다.

## 12. CLI 입력과 Dry-run 계약

### 12.1 CLI 입력

Dry-run은 최소 다음 입력을 받는다.

- `--db-path`
- `--repository-root`
- `--detector packet_rule|packet_if`
- `--current-session-id <UUIDv4>`
- `--target-session-id <UUIDv4>`
- `--approved-by`
- `--reason`
- `--plan-output`
- 실제 운영 명령이 기본값을 바꾼 경우 이를 그대로 전달하는 Lock Path Override

현재 Session을 Checkpoint 시각만으로 임의 추정하지 않는다. 운영자가
`--current-session-id`를 명시하고, CLI가 그 Session의 Ready Through와 Checkpoint 경계가
정확히 일치하는지 검증한다. Target도 명시된 UUID 하나만 사용한다.

Lock Override는 역할별로 받되 Plan에는 역할별 원본 입력과 최종 resolved Path를 모두
기록한다. Override를 생략하면 각 기존 실행 주체의 코드상 기본값을 사용한다. Runbook은
Recovery 입력이 실제 Orchestrator·Manual Runner·Extractor 실행 인자와 같음을 사람이
대조하도록 요구한다.

Execute는 다음을 추가로 요구한다.

- `--plan-file`
- Plan에 기록된 것과 동일한 `--db-path`
- 일반 실행 확인 문자열
- 처리 가능한 Session을 건너뛸 때만
  `--confirm-skip-processable "SKIP-PROCESSABLE-SESSIONS:<plan_sha256>"`

Execute에서 Detector, Session, 승인자, 사유를 별도 값으로 다시 받아 Plan을 덮어쓰지
않는다. 이 값들은 Plan 파일에서 읽고 현재 DB·Repository 상태로 재생성한 Canonical
Payload와 비교한다.

### 12.2 Dry-run 검증

Dry-run은 DB를 Query-only로 열고 다음을 검증한다.

1. 입력 형식, Detector Key, 승인자와 사유
2. Migration 005 metadata와 Schema
3. Repository Commit, tracked·staged 상태와 untracked inventory
4. resolved Repository Root·Database Path·Lock Path
5. 현재 Checkpoint와 그 Checkpoint가 속한 Session
6. 현재 Session이 `COMPLETED`이고 Checkpoint가 Ready Through에 정확히 도달했는지
7. 현재 Session에 처리 가능한 남은 Prefix가 없는지
8. 대상 Session의 UUID, 존재, `COMPLETED` 상태와 full-ready 범위
9. Checkpoint가 전진하며 동일 Session 지정이나 역행이 아닌지
10. 건너뛸 Session 전체 분류와 개수
11. 대상 Detector의 기존 Recovery Audit 중복 여부
12. 보호 대상 Table과 다른 Checkpoint Snapshot

모든 검증 후에만 명시된 기존 Directory에 Canonical Plan을 Atomic Write한다. Migration
미적용이나 사전 검증 실패 시 Plan 파일이나 Artifact Directory를 만들지 않는다.

## 13. Session 분류와 명시적 Skip 승인

현재 Checkpoint 경계와 대상 Session 시작 사이의 모든 Capture Session을 다음처럼 분류한다.

| 분류 | 조건 | 처리 |
|---|---|---|
| `EXHAUSTED_CURRENT` | 현재 Checkpoint가 Session Ready Through에 도달 | 정상 사전조건 |
| `SKIPPED_FULL_READY_COMPLETED` | `COMPLETED`이며 전체 범위가 연속 `PROCESSED/EMPTY` | 강한 경고와 별도 확인 필요 |
| `SKIPPED_NOT_READY` | READY·누락·불연속 Prefix 포함 | 일반 미준비 Gap으로 기록 |
| `SKIPPED_FAILED` | Session 상태가 `FAILED` | 실패 Gap으로 기록 |
| `BLOCKING_RUNNING` | Session 상태가 `RUNNING` | Execute 거부 |
| `TARGET_FULL_READY_COMPLETED` | 대상 Session이 COMPLETED이며 전체 Ready | 대상에만 허용 |

`SKIPPED_FULL_READY_COMPLETED`는 처리 가능한 데이터를 의도적으로 건너뛰는 결정이므로
일반 FAILED·미준비 Session Skip과 같은 경고로 취급하지 않는다. Plan의 최상위에 다음을
기록한다.

- `skips_processable_sessions=true`
- 건너뛸 Session ID와 Window 범위
- Segment·Feature Row 개수
- `PROCESSABLE_SESSION_SKIP` Warning Code

이 경우 Execute에는 일반 확인 문자열 외에 Plan SHA에 바인딩된 별도 확인을 요구한다.

```text
--confirm-skip-processable "SKIP-PROCESSABLE-SESSIONS:<plan_sha256>"
```

처리 가능한 Session을 건너뛰지 않는 Plan에서 이 옵션을 주면 입력 오류로 거부한다. 이
확인은 `approved_by`와 `reason`을 대체하지 않는다.

## 14. Execute와 Transaction 순서

Execute는 다음 순서를 따른다.

1. Plan JSON과 내부 SHA 검증
2. `--db-path`와 Plan의 resolved Database Path 비교
3. Migration 005 Row·Table·Index 계약 확인
4. 처리 가능한 Session Skip 여부와 필요한 확인 문자열 검증
5. 실제 Lock Path 계산, Plan과 비교, 중복 제거 및 정렬
6. 모든 고유 Lock 획득
7. Repository 상태와 Canonical Plan 1차 재생성·전체 비교
8. Write Transaction 밖에서 live DB `integrity_check`와
   `foreign_key_check`
9. Python SQLite Backup API로 Snapshot 생성
10. Backup SHA256, `integrity_check`, `foreign_key_check` 검증
11. 같은 Connection의 `PRAGMA data_version` 비교
12. `BEGIN IMMEDIATE`
13. Canonical Plan 전체 재생성 및 Plan 파일과 Payload·SHA 전체 비교
14. Mutation 직전 `connection.total_changes` 저장
15. 조건부 Checkpoint UPDATE
16. Recovery Audit INSERT
17. UPDATE·INSERT Row 수, Checkpoint·Audit Row, FK 및
    `total_changes` Delta 검증
18. COMMIT
19. Write Transaction 밖의 새 Connection에서 live DB 전체
    `integrity_check`, `foreign_key_check`, Checkpoint·Audit 재검증
20. 외부 JSON 결과를 Atomic Write
21. Lock 해제

`PRAGMA data_version`은 같은 Connection에서 Backup 전후 외부 변경을 빨리 감지하기 위한
보조 신호일 뿐이다. 권위 있는 TOCTOU Gate는 `BEGIN IMMEDIATE` 후 Canonical Plan 전체를
재생성해 Payload와 SHA를 비교하는 단계다.

전체 `integrity_check`는 Write Transaction 안에서 실행하지 않는다. Transaction 안에서는
변경 Row, Audit Row, Checkpoint 상태 및 `foreign_key_check`만 검증한다.

## 15. 조건부 Mutation 계약

Checkpoint UPDATE의 `WHERE`에는 다음 Before 값이 모두 들어간다.

- `detector_name`
- `source_table`
- expected `last_processed_id`
- expected `last_completed_window_end`
- expected `updated_at`

`rowcount`는 정확히 1이어야 한다. Audit INSERT도 정확히 1건이어야 한다. Mutation 직전
기준값과 비교한 `connection.total_changes` Delta는 정확히 2여야 한다. Trigger나 예상하지
않은 추가 변경으로 Delta가 달라지면 Rollback한다.

Transaction 안에서 다시 조회해 다음을 확인한다.

- 대상 Checkpoint After가 Plan과 정확히 일치
- 다른 모든 Detector Checkpoint가 Before Snapshot과 동일
- Recovery Audit의 `operation_id`, Plan SHA, Before·After, Backup 정보가 일치
- FK 위반 0건
- Trust Checkpoint 불변

전용 Repository에는 고정된 SELECT, 조건부 UPDATE, Audit INSERT만 둔다. SQLite Authorizer는
v1 필수 구현에서 제외한다. 기존 SQLAlchemy·PRAGMA·Backup 경로와의 호환성을 별도 입증한
경우에만 후속 방어 계층으로 검토한다.

## 16. Backup·Artifact와 실패 정책

### 16.1 Backup 전 실패

- DB 변경 없음
- Backup 없음
- Recovery 결과 Artifact 없음
- 기존 Dry-run Plan은 보존
- 종료 코드 2

### 16.2 Backup 후 Commit 전 실패

- Transaction이 시작됐다면 Rollback
- DB 변경 없음
- Backup 보존
- 기존 Artifact Directory가 있을 때 가능한 범위에서 실패 JSON Atomic Write
- 종료 코드 2
- 새 Dry-run부터 다시 수행

### 16.3 Commit 후 검증 또는 JSON 실패

- Checkpoint 변경과 DB Audit을 되돌리지 않음
- Backup 보존
- 자동 Restore 금지
- CLI는 `database_committed=true`, `operation_status=HOLD`를 표시
- 종료 코드 3
- 운영자가 DB Audit과 Backup을 확인하기 전 후속 Detector 실행 금지

동일 대상 재실행은 UNIQUE 계약과 사전 조회로 거부한다. Commit 여부가 불확실한 상태에서
자동 재시도하지 않는다.

## 17. 기존 안전 패턴의 재사용 경계

Baseline Recovery와 Trust Score Compensation에서 다음 패턴을 재사용한다.

- Python `sqlite3.Connection.backup()`
- Backup SHA256
- live DB·Backup의 integrity/FK 검증
- 조건부 UPDATE와 `rowcount == 1`
- DB Mutation과 Audit INSERT의 단일 Transaction
- 임시 파일 작성 후 `os.replace()`하는 Atomic JSON
- Commit 후 Artifact 실패 시 DB·Audit·Backup 유지
- Commit 이후 실패의 Exit Code 3과 운영 HOLD
- `schema_migrations` Row와 실제 Table을 함께 검사하는 Migration Gate

다음은 기존 구현을 그대로 호출하지 않고 Gap Recovery 전용으로 새로 구현한다.

- Backup을 Write Transaction 밖에서 수행하는 전체 Workflow
- Canonical Plan·SHA와 Plan 파일 입력
- Repository tracked·staged 상태와 untracked inventory
- resolved Database Path 바인딩
- 실제 Lock 경로의 합집합·중복 제거·정렬 획득
- Capture Session Readiness와 Skip 분류 Digest
- 처리 가능한 Session Skip의 추가 확인 계약
- expected `updated_at`을 포함한 Checkpoint 조건부 UPDATE
- `total_changes` Delta 2 검증
- Migration 005 Audit Schema와 Detector별 중복 방지
- Manual Runner의 Session-bound 실행

Baseline Recovery나 Trust Score Compensation의 private Helper를 직접 Import하거나 두 기능을
광범위하게 공통화하지 않는다. 특히 기존 구현은 Backup을 `BEGIN IMMEDIATE` 안에서 수행하는
구조이므로 실행 순서를 복사하지 않는다.

## 18. 보호 대상과 불변성

Recovery Execute가 변경할 수 있는 DB Row는 정확히 다음 두 개다.

1. 요청받은 Detector의 `detector_checkpoints` Row 1건
2. `packet_checkpoint_recoveries` Audit Row 1건

다음은 UPDATE·DELETE·INSERT하지 않는다.

- 다른 `detector_checkpoints` Row
- `detection_events`
- `trust_score_history`
- `devices`
- `isolation_history`
- `firewall_rules`
- `mqtt_logs`, `feature_logs`
- `packet_capture_sessions`, `packet_capture_segments`
- `packet_feature_logs`
- Dataset·Model·PCAP 파일

Backup, Plan, Result JSON 및 기존 Lock 파일 외의 파일도 변경하지 않는다. Pi의 untracked 파일
`0`은 Hash 계산 외에 접근 목적을 두지 않는다.

## 19. 운영 Runbook 책임

Python CLI가 수행하지 않는 운영 Gate는 다음과 같다.

- 관련 systemd Unit의 enabled·active 상태 기록
- Detection Orchestrator 중지
- Packet Rule·Packet IF Manual Runner 미실행 확인
- Packet Feature Extractor 미실행 확인
- `packet-capture.service`의 disabled/inactive 유지
- 공격·Scenario Runner·수동 Packet Capture Process 미실행 확인
- Recovery 전후 서비스 복구 대상 목록 기록

모든 Gate와 Recovery 검증을 통과한 뒤에만 Recovery 전에 active였던 서비스만 복구한다.
기존에 inactive였던 서비스를 새로 시작하지 않는다.

## 20. 검증 전략

독립 SQLite Fixture와 임시 Git Repository를 사용해 다음 경계를 검증한다.

### Plan과 Repository

- Dry-run DB·Artifact 무변경
- Canonical JSON과 SHA 결정성
- resolved DB Path 변경 시 거부
- tracked 변경과 staged 변경 거부
- untracked 파일 허용 및 경로·크기·SHA 기록
- 파일 `0`과 같은 untracked 파일 무변경
- Dry-run과 Execute 사이 inventory 추가·삭제·내용 변경 거부
- 다른 Commit과 Plan Payload 변조 거부

### Lock

- Rule과 IF의 같은 Lock Path를 한 번만 획득
- Orchestrator Override가 Manual Path와 같을 때 중복 제거
- 고유 Lock의 정렬된 획득 순서
- 각 Lock 경합 시 Backup·DB 무변경
- Extractor Lock 경합 거부
- Lock이 Commit 후 검증·JSON 처리까지 유지됨

### Session과 Checkpoint

- `last_processed_id` 유지와 시간 경계 전진
- expected `updated_at` 변경 시 TOCTOU 거부
- Checkpoint 역행·동일 Session·없는 Session·FAILED Target 거부
- RUNNING Session 존재 시 거부
- Ready Range 없음·누락·READY·FAILED Segment·Feature 불일치 거부
- current Session이 미완료이거나 아직 처리 가능한 Prefix가 있으면 거부
- `SKIPPED_FULL_READY_COMPLETED`의 강한 표시와 추가 확인 필수
- 추가 확인 문자열 누락·Plan SHA 불일치 거부
- 일반 FAILED·미준비 Skip에는 추가 확인을 요구하지 않음
- Detector별 독립 실행과 다른 Checkpoint 불변
- 중복 Operation과 동일 Detector·Target 재실행 거부

### Transaction과 장애

- Migration Row만 있거나 Table만 있는 DB 거부
- Migration 미적용 시 Plan·Backup·Artifact 없음
- Backup 실패·Backup 검증 실패 시 DB 불변
- Backup 후 Canonical Plan 변경 시 Rollback
- 조건부 UPDATE 0건·2건 거부
- Audit INSERT 실패 시 Rollback
- `total_changes` Delta가 2가 아니면 Rollback
- Commit 전 FK 위반 시 Rollback
- Commit 후 integrity/FK 실패 시 Exit Code 3과 HOLD
- JSON 실패 시 Checkpoint·Audit·Backup 유지와 Exit Code 3
- 보호 Table, 다른 Checkpoint 및 PCAP Hash 불변

### 인접 회귀

- Packet Rule Detector와 Manual Runner
- Packet IF Detector와 Manual Runner
- Packet Stage Readiness
- Detection Orchestrator Initial Activation과 Gap 차단
- Runtime Checkpoint 역행 방지
- Phase 4 Cutover
- Migration 전체 순차 적용

## 21. 구현 범위와 제외 범위

설계 승인 이후 구현 대상으로 예상되는 구성은 다음과 같다.

- Migration 005
- Gap Recovery Core·Repository·CLI
- Packet Rule·Packet IF Manual Runner의 Session-bound 호출
- 집중·인접·Migration 테스트
- 운영 Runbook과 DB Schema·Detection Core의 최소 문서 갱신

다음은 제외한다.

- Orchestrator의 자동 Gap 인식
- Trust Checkpoint 변경이나 과거 Trust 재처리
- Packet Capture 실행
- Packet Feature 재생성
- 공격 실행 또는 Threshold 변경
- Device·Trust·Isolation·Firewall 복구
- API·Frontend
- Raspberry Pi 자동 배포
- Migration 자동 적용
- 운영 DB 자동 Restore
- 기존 Baseline Recovery·Trust Compensation 리팩터링

## 22. 완료 기준

기능 구현은 다음 조건을 모두 증명해야 완료로 볼 수 있다.

- 승인된 Detector 한 개의 시간 경계만 대상 Session 시작점으로 전진한다.
- `last_processed_id`, Trust Checkpoint와 보호 대상 데이터는 불변이다.
- Plan이 Repository 상태, untracked inventory, DB Path, Lock, Session Readiness 및
  Checkpoint Before·After를 완전히 바인딩한다.
- 처리 가능한 Session Skip은 별도 확인 없이는 실행되지 않는다.
- Backup은 Write Transaction 밖에서 생성·검증된다.
- Transaction 안의 권위 있는 Plan 재검증과 expected `updated_at` 조건부 UPDATE가
  TOCTOU를 차단한다.
- Commit 후 실패는 DB Audit과 Backup을 보존하고 Exit Code 3·HOLD로 구분된다.
- Manual Runner는 대상 Session에 바인딩되고 Orchestrator의 자동 Gap 차단은 유지된다.
- 공식 Trust·Firewall E2E는 새 Holdout Session에서 별도로 검증된다.
