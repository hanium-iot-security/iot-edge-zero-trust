# Operator Trust Score Compensation Runbook

## 1. 목적과 범위

이 절차는 검증된 단일 오탐 Detection Event가 Trust Score v2에서 실제로 적용한
감점만 운영자 승인으로 정확히 되돌립니다. Event와 기존 Trust Score History는
수정하거나 삭제하지 않으며, 별도 감사 Row를 추가합니다.

v1은 보상 전후의 정책 상태가 같은 경우만 지원합니다. 현재 상태도 점수 정책과
일치해야 하며 `devices.status`는 변경하지 않습니다. 따라서 현재 승인 사례인
`esp32_01 normal/80 -> normal/100`은 가능하지만, 상태 전환이 필요한 보상은
거부합니다.

## 2. 필수 안전 계약

- Source Event는 대상 Device 소속이며 `applied_to_score=1`, `processed_at IS NOT NULL`,
  `processing_reason='APPLIED_TO_TRUST'`, `score_delta < 0`이어야 합니다.
- Source Trust History는 `policy_version='trust-score-v2'`이고
  `representative_event_ids_json`이 정확한 정수 배열 `[source_event_id]`여야 합니다.
  Source Event를 포함하지 않는 정상 정수 배열은 관계없는 History로 무시하지만,
  Source Event와 다른 Event를 함께 포함하는 History는 v1에서 거부합니다.
- History의 점수 산술과 `actual_delta`가 Event 감점과 일치해야 합니다.
- 대상 Device의 미처리 Event와 대상 Device/IP의 `PENDING`·`APPLIED` Firewall Rule이
  없어야 합니다.
- 같은 Event 또는 History를 보상한 감사 Row가 없어야 합니다.
- `schema_migrations`의 정확한 `(4, 'trust_score_compensation')` Row와
  `trust_score_compensations` 테이블 중 하나라도 없으면 Artifact Directory와
  Backup을 만들기 전에 거부합니다.
- 보상 점수는 `-actual_delta`로만 계산하며 운영자가 임의 Delta나 최종 점수를
  입력할 수 없습니다. 100 초과 값은 cap하지 않고 거부합니다.

## 3. 서비스 격리와 사전 증적

운영 DB를 사용하는 서비스의 `is-enabled`, `is-active` 결과와 ESP32 전송 상태를
먼저 기록합니다. Recovery 중에는 active DB Writer만 중지하고, 원래 inactive였던
서비스를 새로 시작하지 않습니다. `packet-capture.service`는 disabled/inactive를
유지합니다. 실제 iptables의 Hanium Rule도 별도로 0건인지 확인합니다.

운영 DB·서비스에서 이 Runbook을 실행하기 전에는 승인된 변경 창, DB 경로,
Artifact 전용 경로, Device·Event·History 증적을 교차 확인해야 합니다.

## 4. Migration 확인

```sql
SELECT version, name, applied_at
FROM schema_migrations
WHERE version = 4;

SELECT name
FROM sqlite_master
WHERE type = 'table' AND name = 'trust_score_compensations';
```

첫 결과는 `version=4`, `name='trust_score_compensation'`이어야 하고 두 번째 결과는
정확히 `trust_score_compensations`여야 합니다. 하나라도 없거나 이름이 다르면
실행하지 않습니다. CLI도 두 조건을 Backup보다 먼저 검사합니다.

## 5. Source 증적 확인

```sql
SELECT device_id, ip_address, status, trust_score
FROM devices
WHERE device_id = 'esp32_01';

SELECT id, device_id, detector_type, event_type, score_delta,
       applied_to_score, processed_at, processing_reason,
       analysis_window_start, analysis_window_end, detected_at
FROM detection_events
WHERE id = 21;

SELECT id, device_id, previous_score, calculated_delta, capped_delta,
       actual_delta, new_score, representative_event_ids_json, policy_version
FROM trust_score_history
WHERE device_id = 'esp32_01'
ORDER BY id;
```

`representative_event_ids_json`은 문자열 ID(`['21']`)와 손상 JSON을 허용하지
않습니다. `[31, 32]`처럼 Source Event 21을 포함하지 않는 정상 다중 Event History는
무시하지만, `[21, 32]`처럼 Source Event와 다른 Event를 함께 포함하면 거부합니다.
Source History는 `capped_delta=max(calculated_delta, -30)`, 점수 범위 clamp,
`actual_delta=new_score-previous_score` 산술도 충족해야 합니다.

## 6. Dry-run

Dry-run은 DB와 Artifact Directory를 변경하지 않습니다.

```bash
python -m edge.trust.run_trust_compensation dry-run \
  --db-path <DB_PATH> \
  --device esp32_01 \
  --source-event-id 21 \
  --expected-status normal \
  --expected-trust-score 80 \
  --reason "MQTT backlog false-positive Event 21" \
  --approved-by "<APPROVER>" \
  --artifact-dir <ARTIFACT_DIR>
```

`can_execute=true`, 보상 `+20`, 제안 점수 `100`, 전후 정책 상태 `normal`, 활성
Firewall Rule 0, 미처리 Event 0, 기존 보상 0을 확인합니다. 출력된 Execute 명령을
검토하되 승인 없이 실행하지 않습니다.

## 7. Execute

```bash
python -m edge.trust.run_trust_compensation execute \
  --db-path <DB_PATH> \
  --device esp32_01 \
  --source-event-id 21 \
  --expected-status normal \
  --expected-trust-score 80 \
  --reason "MQTT backlog false-positive Event 21" \
  --approved-by "<APPROVER>" \
  --artifact-dir <ARTIFACT_DIR> \
  --confirm "APPLY-TRUST-COMPENSATION"
```

Execute는 `BEGIN IMMEDIATE` 안에서 사전 조건을 다시 검사합니다. 그 뒤 SQLite
Backup API Snapshot과 SHA256·integrity_check·foreign_key_check를 검증하고,
`devices.trust_score` 조건부 UPDATE와 감사 Row INSERT를 한 Transaction으로
Commit합니다. `devices.status`는 UPDATE하지 않습니다.

## 8. 결과와 종료 코드

- `0`: Dry-run 적격 또는 Execute 성공
- `2`: 사전 검증·Backup·Transaction 실패. DB Commit 없음
- `3`: DB와 감사 Row는 Commit됐으나 Commit 후 검증 또는 JSON Artifact 저장 실패.
  Backup과 DB 변경을 보존하고 운영 절차를 즉시 `HOLD`합니다.

종료 코드 3에서 재실행하면 중복 보상 Gate가 거부합니다. 수동으로 점수를 되돌리거나
감사 Row·Backup을 삭제하지 말고, DB와 Backup SHA256을 보존한 채 원인을 조사합니다.

## 9. 사후 Gate

```sql
SELECT device_id, status, trust_score
FROM devices
WHERE device_id = 'esp32_01';

SELECT id, operation_id, device_id, source_event_id,
       source_trust_history_id, previous_score, compensation_delta,
       new_score, reason, approved_by, backup_path, backup_sha256, created_at
FROM trust_score_compensations
WHERE source_event_id = 21;

SELECT id, processed_at, processing_reason, applied_to_score, score_delta
FROM detection_events
WHERE id = 21;
```

또한 live DB와 Backup의 `PRAGMA integrity_check`, `PRAGMA foreign_key_check`, JSON의
`operation_id`·Backup 경로·SHA256을 대조합니다. 기존 Event와 Trust History가
그대로이고 점수만 `100`, 상태는 계속 `normal`인지 확인합니다.

모든 Gate가 통과한 경우에만 Recovery 전에 active였던 서비스만 원상 복구합니다.
이 PR 자체는 Raspberry Pi 운영 DB, 서비스, iptables를 변경하지 않습니다.
