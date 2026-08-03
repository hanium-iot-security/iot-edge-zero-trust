# Device Baseline Recovery Runbook

## 1. 목적과 범위

이 절차는 Phase 5 Profile 0 Pilot 전에 운영자가 명시한 Device의 현재
`devices.status='isolated'`와 예상 `trust_score`를 확인하고 다음 두 컬럼만
복구한다.

- `devices.status`: `isolated` → `normal`
- `devices.trust_score`: 운영자가 입력한 예상값 → `100`

다음 데이터는 수정하거나 삭제하지 않는다.

- `detection_events`
- `trust_score_history`
- `isolation_history`
- `firewall_rules`
- `detector_checkpoints`
- MQTT·Feature·Packet Capture·Packet Feature 데이터

이 CLI는 Firewall Release나 iptables 제거 도구가 아니다. API, Frontend,
Migration, 신규 Audit 테이블도 만들지 않는다. 실행 증적은 DB 밖의 Backup과 JSON
파일로 남긴다.

## 2. 실행 전 Gate

1. 실제 운영 DB 경로를 `DATABASE_URL`과 대조한다. 예시 경로를 추측해서 실행하지
   않는다.
2. 정상 Firmware, 물리 Device, Device ID, MQTT Topic, 실제 IP를 대조한다.
3. Artifact Directory는 저장소 밖의 충분한 여유 공간에 준비한다. 실제 DB와 같은
   파일을 Backup 경로로 사용하지 않는다.
4. 다음 서비스의 `enabled`와 `active` 상태를 Recovery 전 증적으로 기록한다.

   - `mqtt-subscriber.service`
   - `mqtt-feature-builder.service`
   - `detection-orchestrator.service`
   - `firewall-worker.service`
   - `gateway-metrics.service`
   - `packet-capture.service`

5. 기록 시점에 `active`였던 DB Writer만 중지한다. 여기서 DB Writer는
   `mqtt-subscriber`, `mqtt-feature-builder`, `detection-orchestrator`,
   `firewall-worker`, `gateway-metrics` 다섯 서비스다. Recovery 전에 `inactive`였던
   서비스는 시작하거나 상태를 바꾸지 않는다.
6. `packet-capture.service`는 `disabled`·`inactive` 상태를 유지한다. Recovery를 위해
   시작하거나 enable하지 않는다. 상태가 다르면 Recovery를 중단하고 승인된 Packet
   Capture 운영 절차로 먼저 정리한다.
7. ESP32는 MQTT 전송을 중지하거나 네트워크 연결을 해제한다.
8. 대상 Device의 모든 Firewall Rule이 공식 Release되어 DB 상태가 `REMOVED` 또는
   `FAILED`인지 확인한다.
9. DB의 `REMOVED`만으로 실제 iptables 제거를 단정하지 않는다.
   [`firewall-runbook.md`](firewall-runbook.md)에 따라 실제 Rule 제거를 별도로
   확인한다.
10. 대상 Device의 `processed_at IS NULL` Detection Event가 0건인지 확인한다.
    `processed_at`은 현재 Trust Score v2의 처리 완료 계약이다. 대표 Event가 아닌
    처리 완료 Row는 `applied_to_score=0`일 수 있으므로 `applied_to_score`는 이 Gate에
    사용하지 않는다.

```bash
DB_PATH="/absolute/path/to/iot_security.db"
ARTIFACT_DIR="/absolute/path/to/baseline-recovery-artifacts"

SERVICES=(
  mqtt-subscriber.service
  mqtt-feature-builder.service
  detection-orchestrator.service
  firewall-worker.service
  gateway-metrics.service
  packet-capture.service
)

for service in "${SERVICES[@]}"; do
  printf '%s\t%s\t%s\n' \
    "$service" \
    "$(systemctl is-enabled "$service" 2>/dev/null || true)" \
    "$(systemctl is-active "$service" 2>/dev/null || true)"
done | tee "$ARTIFACT_DIR/service-state-before.tsv"

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT device_id, ip_address, status, trust_score, last_seen_at
FROM devices
WHERE device_id IN ('esp32_01', 'esp32_02')
ORDER BY device_id;
"

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT id, device_id, source_ip, status, applied_at, released_at
FROM firewall_rules
WHERE (device_id IN ('esp32_01', 'esp32_02')
       OR source_ip IN (
         SELECT ip_address FROM devices
         WHERE device_id IN ('esp32_01', 'esp32_02')
       ))
  AND status IN ('PENDING', 'APPLIED')
ORDER BY id;
"

sqlite3 -readonly -header -column "$DB_PATH" "
SELECT id, device_id, detector_type, event_type,
       analysis_window_start, analysis_window_end,
       detected_at, processing_reason
FROM detection_events
WHERE device_id IN ('esp32_01', 'esp32_02')
  AND processed_at IS NULL
ORDER BY id;
"
```

서비스 상태 증적을 확인한 뒤, Recovery 전에 `active`였던 DB Writer만 명시적으로
중지한다. 전체 목록을 일괄 중지하거나 `packet-capture.service`를 시작·enable하지
않는다.

## 3. 입력 계약

`--device`와 `--expected-trust-score DEVICE=SCORE`는 반복 가능하며 두 집합이 정확히
일치해야 한다. 점수는 `0~100` 정수다. 다음 입력은 DB Backup과 변경 전에 거부한다.

- Device별 예상값 누락 또는 개수 불일치
- 같은 Device의 예상값 중복
- `--device`에 없는 Device의 예상값
- 같은 `--device` 중복
- 범위를 벗어나거나 정수가 아닌 점수

예상 status는 인자로 받지 않고 `isolated`로 고정한다. Device ID와 점수는 코드에
하드코딩하지 않는다.

## 4. Dry-run

Dry-run은 DB를 읽기만 하며 Artifact Directory도 만들지 않는다.

```bash
python -m edge.trust.run_baseline_recovery dry-run \
  --db-path "$DB_PATH" \
  --device esp32_01 \
  --device esp32_02 \
  --expected-trust-score esp32_01=20 \
  --expected-trust-score esp32_02=20 \
  --artifact-dir "$ARTIFACT_DIR"
```

JSON에는 다음이 포함된다.

- Device ID와 DB `ip_address`
- 현재 status·Trust Score
- 운영자가 입력한 expected status·Trust Score
- 변경 예정값 `normal`·`100`
- Device ID 또는 IP에 연결된 `PENDING`·`APPLIED` Firewall Rule 확인 결과
- `processed_at IS NULL`인 대상 Device Detection Event의 개수·ID·상세와 Gate 결과
- 동일 입력을 사용하는 실제 Execute 명령 예시
- `can_execute`와 `preflight_errors`

`can_execute=false`면 JSON을 출력한 뒤 종료 코드 `2`로 끝난다. 원인을 해결하고
Dry-run을 다시 실행한다. JSON을 Plan 파일처럼 Execute 입력으로 재사용하는 기능은
없다.

## 5. Execute

Dry-run 직후 Device 상태와 예상값을 다시 대조한 다음 동일한 값을 전달한다.

```bash
python -m edge.trust.run_baseline_recovery execute \
  --db-path "$DB_PATH" \
  --device esp32_01 \
  --device esp32_02 \
  --expected-trust-score esp32_01=20 \
  --expected-trust-score esp32_02=20 \
  --artifact-dir "$ARTIFACT_DIR" \
  --confirm "RESET-TO-NORMAL-100"
```

Execute 순서:

1. 확인 문구와 입력 집합을 검증한다.
2. `BEGIN IMMEDIATE`로 다른 Writer의 변경을 차단한다.
3. Transaction 안에서 Device status·Trust Score, 활성 Firewall Rule과
   `processed_at IS NULL` Detection Event를 다시 확인한다.
4. 아직 DB를 변경하지 않은 상태에서 Python `sqlite3` Backup API로 Snapshot을
   생성한다.
5. Backup SHA256, `PRAGMA integrity_check`, `PRAGMA foreign_key_check`를 검증한다.
6. 각 Device에 다음 조건부 UPDATE를 적용한다.

```sql
UPDATE devices
SET status = 'normal', trust_score = 100
WHERE device_id = :device_id
  AND status = 'isolated'
  AND trust_score = :expected_trust_score;
```

7. 한 Device라도 정확히 1개 Row가 변경되지 않으면 전체 Transaction을 Rollback한다.
8. Commit 전과 후에 대상 상태와 DB integrity·FK를 검증한다.
9. 결과, Backup 경로·SHA256과 검증값을 JSON Log에 기록한다.

성공 시 종료 코드 `0`, 안전 계약 거부 시 `2`다. 실행 실패 시 이미 생성된 Backup과
`result=FAILED` JSON은 원인 분석을 위해 보존한다.

## 6. Artifact

한 Execute마다 충돌하지 않는 UTC·난수 기반 이름을 사용한다.

```text
baseline-recovery-YYYYMMDDTHHMMSSZ-<suffix>.db
baseline-recovery-YYYYMMDDTHHMMSSZ-<suffix>.json
```

JSON의 `backup_sha256`, `backup_integrity_check`,
`backup_foreign_key_violations`, `integrity_check`, `foreign_key_violations`를 확인한다.
Backup은 Reset 직전 상태이므로 대상 Device가 여전히 `isolated`와 이전 점수여야 한다.

## 7. 실행 후 검증

```bash
sqlite3 -readonly -header -column "$DB_PATH" "
SELECT device_id, ip_address, status, trust_score, last_seen_at
FROM devices
WHERE device_id IN ('esp32_01', 'esp32_02')
ORDER BY device_id;

PRAGMA integrity_check;
PRAGMA foreign_key_check;
"
```

통과 조건:

- 명시한 Device만 `normal`, `100`이다.
- 대상 Device의 `processed_at IS NULL` Detection Event가 `0건`이다.
- 대상 Device 또는 IP의 `PENDING`·`APPLIED` Firewall DB Rule이 `0건`이다.
- 실제 Hanium iptables Rule이 `0건`이다.
- `last_seen_at`, `ip_address` 등 다른 Device 컬럼은 그대로다.
- 대상 외 Device가 그대로다.
- 과거 Detection·Trust·Isolation·Firewall·Checkpoint·Packet Row가 그대로다.
- `integrity_check=ok`, `foreign_key_check=0건`이다.
- Recovery JSON의 결과·Backup 경로와 실제 Backup SHA256이 일치한다.

모든 Gate를 통과한 뒤에만 `service-state-before.tsv`에서 Recovery 전에
`active`였던 서비스만 원상복구한다. Recovery 전에 `inactive`였던 서비스는 새로
시작하지 않으며 `packet-capture.service`는 `disabled`·`inactive`를 유지한다. 복구한
서비스 상태를 다시 기록하고 ESP32를 연결한 뒤 정상 Firmware MQTT·Feature Smoke를
수행한다. Smoke 통과 후 승인된 Packet Capture 절차로 새 Capture Session을 시작하며,
Recovery 서비스 복구 과정에서 `packet-capture.service`를 임의로 시작하지 않는다.

## 8. 실패와 복구

- 입력·Device·Firewall·미처리 Event 사전검증 실패: DB와 Backup은 변경되지 않는다.
  Artifact Directory가 아직 없으면 JSON도 생성하지 않는다. Directory가 운영자에
  의해 미리 준비되어 있으면 기존 실패 증적 정책에 따라 Backup 없는
  `result=FAILED` JSON만 기록한다.
- Backup 실패: DB는 변경되지 않는다. 생성된 실패 증적을 보존하고 Dry-run부터 다시
  수행한다.
- 조건부 UPDATE 또는 Commit 전 검증 실패: 전체 UPDATE가 Rollback된다.
- Commit 후 검증 또는 JSON 기록 실패: Pilot을 시작하지 않고 Backup·오류 증적을
  보존한다.
- 복원이 필요하면 자동 복구를 추측해서 실행하지 않는다. JSON의 Backup 경로와
  SHA256을 확인하고 [`db-backup-restore.md`](db-backup-restore.md)의 승인된 전체 DB
  복구 절차를 따른다.
- 이 CLI로 Detection Event, Trust History, Isolation History, Firewall History를
  삭제하거나 보정하지 않는다.
