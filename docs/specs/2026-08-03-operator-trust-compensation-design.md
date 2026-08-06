# 운영자 승인형 Trust Score 보상 복구 설계

## 1. 목적

Trust Score v2가 실제 점수에 반영한 오탐 Detection Event 한 건의 감점만
운영자 승인으로 역산해 복구한다. 이 기능은 임의 점수 설정 도구가 아니며,
운영자가 보상값이나 최종 점수를 입력할 수 없다.

첫 적용 사례는 다음과 같다.

- Device: `esp32_01`
- Source Detection Event: `21`
- Source Trust Score History: `9`
- 현재 상태: `normal / 80`
- Source History의 `actual_delta`: `-20`
- 자동 계산 보상: `+20`
- 결과: `normal / 100`

## 2. 기존 이력과 책임 분리

자동 탐지 처리 이력과 운영자 보상 이력을 분리한다.

- `detection_events`와 `trust_score_history`는 자동 Detection·Trust 처리의 원본
  증적이므로 UPDATE·DELETE하지 않는다.
- 운영자 보상은 가짜 분석 Window를 만들지 않고 전용
  `trust_score_compensations` 감사 테이블에 기록한다.
- MQTT·Feature·Packet·Isolation·Firewall·Checkpoint 이력도 변경하지 않는다.
- v1은 Device 한 대와 Source Event 한 건만 처리하며 자동 실행, 일괄 처리,
  API와 Frontend를 제공하지 않는다.

## 3. 데이터 모델

Migration `004_trust_score_compensation.sql`에서 다음 테이블을 추가한다.

```sql
CREATE TABLE trust_score_compensations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE
        CHECK(length(trim(operation_id)) > 0),
    device_id TEXT NOT NULL,
    source_event_id INTEGER NOT NULL UNIQUE,
    source_trust_history_id INTEGER NOT NULL UNIQUE,
    previous_score INTEGER NOT NULL
        CHECK(previous_score BETWEEN 0 AND 100),
    compensation_delta INTEGER NOT NULL
        CHECK(compensation_delta > 0),
    new_score INTEGER NOT NULL
        CHECK(new_score BETWEEN 0 AND 100),
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    approved_by TEXT NOT NULL CHECK(length(trim(approved_by)) > 0),
    backup_path TEXT NOT NULL CHECK(length(trim(backup_path)) > 0),
    backup_sha256 TEXT NOT NULL
        CHECK(length(backup_sha256) = 64
              AND backup_sha256 NOT GLOB '*[^0-9a-f]*'),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id)
        REFERENCES devices(device_id) ON DELETE RESTRICT,
    FOREIGN KEY (source_event_id)
        REFERENCES detection_events(id) ON DELETE RESTRICT,
    FOREIGN KEY (source_trust_history_id)
        REFERENCES trust_score_history(id) ON DELETE RESTRICT,
    CHECK(new_score = previous_score + compensation_delta)
);
```

각 UNIQUE 제약은 같은 작업, Event 또는 Trust History가 두 번 보상되는 것을
DB 최종 방어선에서 차단한다. FK의 `ON DELETE RESTRICT`는 감사 Row가 참조하는
기존 증적 삭제를 막는다. Migration은 현재 최신 003 DB와 신규 DB 모두에
순차 적용할 수 있어야 한다.

## 4. Source Event와 Trust History 검증

CLI는 Backup 또는 DB 변경 전에 다음을 검증하고, Execute Transaction 안에서
같은 검증을 다시 수행한다.

### Device

- Device가 존재한다.
- 현재 status와 Trust Score가 `--expected-status`,
  `--expected-trust-score`와 정확히 일치한다.
- `current_status == status_for_trust_score(current_score)`다.

### Detection Event

- Source Event가 존재하고 대상 Device에 속한다.
- `applied_to_score = 1`이다.
- `processed_at IS NOT NULL`이다.
- `processing_reason = 'APPLIED_TO_TRUST'`다.
- `score_delta < 0`이다.

### Trust Score History

- 대상 Device의 History 중 `representative_event_ids_json`이 정수 ID 배열
  `[source_event_id]`와 정확히 일치하는 Row가 하나뿐이다.
- Source Event를 포함하지 않는 정상 정수 배열은 관계없는 History로 무시한다.
- Source Event를 다른 Event와 함께 포함한 History, 손상 JSON, 문자열 ID,
  동일 Event를 가리키는 여러 History는 모두 거부한다.
- `policy_version = 'trust-score-v2'`다.
- `actual_delta < 0`이다.
- `capped_delta = max(calculated_delta, -30)`이다.
- `new_score`는 `previous_score + capped_delta`를 `0..100`으로 clamp한 값이다.
- `new_score - previous_score = actual_delta`다.
- 단일 대표 Event의 `calculated_delta = source_event.score_delta`다.

### 주변 실행 상태

- 같은 Event 또는 History의 기존 Compensation이 없다.
- 대상 Device에 `processed_at IS NULL` Detection Event가 없다.
- 대상 Device 또는 실제 IP에 `PENDING`·`APPLIED` Firewall Rule이 없다.
- `schema_migrations`에 정확한 `(4, 'trust_score_compensation')` Row가 없거나
  `trust_score_compensations` 테이블이 없으면 Migration 미적용 또는 불일치로
  판단해 Backup 생성 전에 거부한다.

## 5. 보상 계산과 상태 불변 계약

보상값은 다음처럼 자동 계산한다.

```text
compensation_delta = -source_history.actual_delta
proposed_score = current_score + compensation_delta
```

다음 조건을 모두 만족해야 한다.

- `compensation_delta > 0`
- `proposed_score`가 `0..100` 범위다.
- 100 초과 시 cap하지 않고 거부한다.
- `status_for_trust_score(proposed_score) == current_status`다.

v1은 `devices.status`를 UPDATE하지 않는다. 보상으로 정책상 상태가 바뀌어야 하는
경우에는 감사 모델에 상태 변경 정보가 없으므로 거부한다. 따라서 현재
`normal / 80 -> normal / 100`은 허용하지만 `warning / 60 -> normal / 80`은
허용하지 않는다.

## 6. Core와 CLI

신규 파일은 다음 책임을 가진다.

- `edge/trust/trust_compensation.py`: Read-only 검사, 자동 계산, Backup,
  조건부 UPDATE, 감사 INSERT, 검증과 Artifact 기록
- `edge/trust/run_trust_compensation.py`: `argparse` 입력과 JSON stdout/stderr,
  종료 코드 관리

CLI 입력은 다음과 같다.

- `--db-path`
- `--device`
- `--source-event-id`
- `--expected-status`
- `--expected-trust-score`
- `--reason`
- `--approved-by`
- `--artifact-dir`
- Execute 전용 `--confirm APPLY-TRUST-COMPENSATION`

`reason`과 `approved_by`는 trim 후 빈 값이면 거부한다. Device와 Event는 각각
한 개만 받으며 점수, delta 또는 최종 점수를 직접 입력하는 옵션은 두지 않는다.

Dry-run은 DB와 Artifact Directory를 변경하지 않고 다음을 JSON으로 출력한다.

- `can_execute`와 모든 사전 검증 결과
- Device, Event와 Source History 요약
- 자동 계산된 `compensation_delta`, `proposed_score`
- 실제 Execute 명령 예시

## 7. Execute Transaction

Execute는 확인 문자열과 입력 형식을 먼저 검증한 뒤 다음 순서로 수행한다.

1. `BEGIN IMMEDIATE`
2. Migration 적용 여부와 모든 사전조건 재검증
3. Artifact 충돌 확인
4. Python `sqlite3` Backup API로 실행 전 Snapshot 생성
5. Backup SHA-256, `integrity_check`, `foreign_key_check` 검증
6. 다음 조건부 UPDATE 실행

```sql
UPDATE devices
SET trust_score = :new_score
WHERE device_id = :device_id
  AND status = :expected_status
  AND trust_score = :expected_trust_score;
```

7. `rowcount = 1` 확인
8. `trust_score_compensations` 감사 Row INSERT
9. Device 상태·점수, 감사 Row, DB integrity/FK 검증
10. COMMIT
11. 별도 연결로 Commit 결과 재조회 및 integrity/FK 검증
12. JSON 결과 Artifact 원자적 기록

Backup Helper는 Baseline Recovery의 private 함수에 의존하지 않고 신규 Core에
작게 유지한다. Baseline Recovery의 기존 코드와 동작은 수정하지 않는다.

## 8. 실패와 Artifact 정책

Commit 전 실패는 Transaction을 Rollback한다. 기존 Event·History와 다른 운영
테이블은 항상 불변이어야 한다. 사전 검증 실패는 Artifact Directory를 만들지
않는다. 이미 존재하는 Artifact Directory에는 가능한 경우 실패 JSON을 원자적으로
기록할 수 있지만 Backup 이전 실패에는 Backup을 만들지 않는다.

Commit 후 JSON 저장만 실패한 경우에는 이미 Commit된 점수와 감사 Row를 되돌리지
않는다. Backup을 보존하고 CLI는 non-zero로 종료하며 운영 절차를 HOLD한다.
감사 Row의 `operation_id`, Backup 경로·SHA와 DB 변경 결과를 기준으로 JSON 증적을
재구성한 후에만 후속 운영을 진행한다. CLI 오류는 DB가 Commit됐음을 명확히
표시해야 한다.

## 9. 테스트 전략

독립 SQLite DB에 Migration을 적용하고 실제 Core·CLI를 테스트한다.

- 003 기존 DB와 신규 DB에 004 적용
- FK, CHECK, UNIQUE와 재실행 계약
- `normal / 80 -> normal / 100` 성공 및 감사 Row 검증
- Dry-run 무변경과 자동 계산·Execute 명령
- 입력, Device, status, score, Event 처리 상태와 Device 귀속 실패
- History 없음·중복·정책 버전·산술·JSON 형태 실패
- 기존 Compensation, 미처리 Event, 활성 Firewall Rule 실패
- 현재·제안 점수의 정책 상태 불일치와 100 초과 실패
- Backup·Backup 검증·조건부 UPDATE·감사 INSERT 실패 Rollback
- Commit 후 JSON 실패 시 점수·감사 Row·Backup 유지와 non-zero
- Detection Event, Trust History, MQTT·Feature·Isolation·Firewall·Checkpoint·Packet
  데이터 불변
- Baseline Recovery, Migration, Trust Score v2 인접 회귀

## 10. 운영 경계

이 구현과 테스트는 로컬 Fixture DB에서만 수행한다. Raspberry Pi, 운영 DB,
systemd, iptables, ESP32에는 접근하지 않는다. 실제 Pi Migration과 보상 Execute는
Draft PR 병합 이후 별도 승인된 Runbook 절차에서만 수행한다.
