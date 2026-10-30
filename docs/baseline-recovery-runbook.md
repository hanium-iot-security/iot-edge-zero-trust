# Device Baseline Recovery Runbook

## 대시보드의 일반 기기 복구

일반 `/api/recovery/execute`는 대상 기기의 상태·점수 변경과
`device_recovery_audits`의 성공 기록을 **같은 SQLite Transaction**에서 확정한다.
매 요청마다 전체 DB를 복사하거나 전체 DB 무결성 검사를 수행하지 않는다.
기존 수동 Baseline CLI는 아래 절차대로 전체 Backup과 검사를 수행한다.

- 일반 API 반영 전 `017_device_recovery_audits.sql`까지 적용해야 한다. 미적용이면
  사전 점검은 `AUDIT_STORAGE_UNAVAILABLE`로 차단한다. 운영 DB Migration 전에는
  별도 전체 백업을 확보한다. 자동·정기 백업 작업은 추가하지 않는다.
- 관리자 인증, 명시적 확인 문구, 예상 격리 점수, 대상 IP의 활성 규칙·해제 대기·
  미처리 탐지 Event, 실제 방화벽 해제 Snapshot의 최신성 검증은 유지한다.
- 점수 변경·변경 후 검증·최종 Runtime 확인·감사 INSERT 중 저장 확정 전에 실패하면
  점수 변경과 성공 감사는 함께 Rollback된다. 이미 공식 해제된 Firewall을 자동으로
  다시 추가하는 의미는 아니다.
- 감사에는 승인자·사유·변경 전후 기기 상태·실제 점검한 현재/과거 IP와 Runtime
  근거를 보존한다. `audit_reference`는 `device_recovery_audits:<operation_id>`이다.
  신규 일반 복구의 `backup_reference`와 `backup_sha256`는 의도적으로 `null`이다.
- Commit 뒤 HTTP 응답이 유실돼도 성공 감사는 보존된다. 복구를 무조건 재실행하지
  않고 `/api/recovery/history`와 실제 기기·전체 규칙 상태를 다시 조회한다.
  이력 API는 DB 감사와 과거 JSON 감사를 함께 읽으며 동일 작업은 DB 기록을 우선한다.
  Commit 결과를 감사에서 확인할 수 없으면 `BASELINE_RECOVERY_COMMITTED_UNVERIFIED`와
  확인 불가인 변경 후 상태를 반환한다. 실패 감사로 덮지 않으며 대시보드도 재실행을
  막고 실제 상태를 다시 조회한다.
- 전체 백업은 중요한 시험 결과를 확보하거나 큰 변경을 하기 전에 별도 운영 절차로
  수행한다. 아래 CLI의 `execute`는 **백업 전용 명령이 아니라 상태를 복구하는 명령**이다.

현재 변경은 로컬 검증 대상이다. Pi 반영 전에는 정상 수집 중인 환경에서 복구 시간,
다른 기기의 수신, Capture 연속성, 여섯 필수 Stage의 전진, Observer 최신성 및
실제 대시보드의 최종 상태 확인을 별도로 검증한다.

## 1. 수동 CLI의 목적과 범위

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

이 수동 CLI는 Firewall Release나 iptables 제거 도구가 아니다.
실행 증적은 DB 밖의 Backup과 JSON 파일로 남긴다. 일반 API의 DB 감사와 구분한다.

Backend Recovery API는 위의 일반 기기 복구 경로를 호출하는 관리 Command Adapter다. Backend는
`devices.status`나 `devices.trust_score`를 직접 UPDATE하지 않고, systemd 제어,
iptables 조회 계층 생성, Firewall Release 실행도 하지 않는다. Runtime Firewall
검증을 수행할 안전한 기존 read helper가 없는 환경에서는 Preflight를 `HOLD`로 닫고
Recovery Execute를 허용하지 않는다.

API와 CLI 모두 Core에서 Runtime Snapshot을 검증한다. `FAILED` Firewall Rule도
실제 차단이 남아 있을 수 있으므로 실패 상태만으로 복구를 허용하지 않는다.
Snapshot은 TTL 내에 있어야 하고, 대상 Device **또는 같은 IP**의 마지막 차단
시도·적용·해제·Release 처리보다 뒤에 관측되어야 한다. 같은 초에 기록된 관측은
선후를 증명할 수 없어 거부한다. 이후 Observer의 새 관측을 기다린 뒤 재검사한다.

API·CLI·Observer·Firewall Worker는 같은 DB와 `FIREWALL_LOCK_PATH` 설정을 사용한다.
기본 잠금 경로가 DB에서 파생되는 환경에서는 실제 DB 경로도 같아야 한다.
Recovery Execute 전체는 정규화된 실제 DB 경로에서 파생한 별도 DB별 Recovery
Command 잠금으로 직렬화한다. 이 잠금은 Backup부터 사후 검증·Audit 기록까지 유지하며,
Observer·Firewall Worker가 사용하는 Firewall 공용 잠금과 구분한다. Firewall 공용
잠금은 최종 Gate 재검사와 짧은 변경 Transaction에만 사용한다.
잠금 파일을 지워 우회하거나 Snapshot 파일을 수동으로 수정하지 않는다. Recovery를
위해 Runtime Snapshot TTL을 늘리지 않으며 Observer가 계속 새 관측을 기록하게 한다.

## 2. 실행 전 Gate

실제 운영 DB에 대한 Execute(CLI·API)는 해당 후보의 Pi 검증에서 Writer 전체
Transaction 지연 기준(200ms), Capture 연속성, Observer 갱신을 충족한 증적이
기록된 경우에만 진행한다. 증적이 없거나 기준을 초과하면 운영 Execute를 진행하지
않는다. 기능 테스트 통과나 Dry-run의 `can_execute=true`는 이 운영 Gate를
대체하지 않는다.

1. 실제 운영 DB 경로를 `DATABASE_URL`과 대조한다. 예시 경로를 추측해서 실행하지
   않는다. 읽기 전용 `PRAGMA journal_mode`로 WAL 모드인지 확인한다. Execute는
   WAL DB만 허용하며, Recovery가 Journal 모드를 변경하지 않는다.
2. 정상 Firmware, 물리 Device, Device ID, MQTT Topic, 실제 IP를 대조한다.
3. Artifact Directory는 저장소 밖의 충분한 여유 공간에 준비한다. 실제 DB와 같은
   파일을 Backup 경로로 사용하지 않는다. 원본 DB의 WAL을 유지해야 하므로 운영 DB가
   있는 파일시스템에도 Backup 진행 중 WAL이 증가할 여유 공간이 있어야 한다.
4. 다음 서비스의 `enabled`와 `active` 상태를 Recovery 전 증적으로 기록한다.

   - `mqtt-subscriber.service`
   - `mqtt-feature-builder.service`
   - `detection-orchestrator.service`
   - `firewall-worker.service`
   - `gateway-metrics.service`
   - `packet-capture.service`

5. 승인된 현재 서비스의 `enabled`·`active` 상태를 유지한다. Recovery 때문에 DB
   Writer를 중지하거나 비활성 서비스를 시작하지 않는다. Runtime Firewall Observer도
   계속 실행하여 Snapshot을 갱신하게 한다.
6. `packet-capture.service`도 승인된 현재 운영 상태와 Capture Session을 유지한다.
   Recovery를 위해 중지·시작·enable·disable하지 않으며, `disabled`·`inactive`를
   일괄 전제하지 않는다.
7. 정상 Firmware의 ESP32와 MQTT 전송도 승인된 운영 상태를 유지한다. Recovery를 위해
   네트워크를 끊을 필요는 없다. 새 Detection Event나 상태 변경이 발생하면 최종 Gate가
   복구를 거부할 수 있으므로 실제 상태를 확인한 뒤 다시 판단한다.
8. 대상 Device 또는 같은 IP의 모든 Firewall Rule이 공식 Release되어 DB 상태가
   `REMOVED` 또는 `FAILED`인지 확인한다.
9. 대상 Device 또는 IP에 연결된 `firewall_release_requests`가 `PENDING`으로 남아
   있으면 Recovery를 진행하지 않는다. `FAILED` Release Request는 감사 이력으로
   보존하며, Recovery 가능 여부는 Firewall Rule의 `REMOVED` 상태와 runtime
   `VERIFIED_RELEASED` 기준으로 판단한다.
10. DB의 `REMOVED`만으로 실제 iptables 제거를 단정하지 않는다.
   [`firewall-runbook.md`](firewall-runbook.md)에 따라 실제 Rule 제거를 별도로
   확인한다.
11. 대상 Device의 `processed_at IS NULL` Detection Event가 0건인지 확인한다.
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
PRAGMA journal_mode;
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

서비스 상태 증적은 실행 후 승인된 운영 상태가 유지되는지 확인하는 기준이다.
위 조회는 해당 시점의 관측이며 대상 상태를 예약하지 않는다. Writer와 Observer는
계속 동작하므로 Execute의 최종 Transaction에서 모든 Gate를 다시 확인한다.

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
- Device ID 또는 IP에 연결된 `PENDING` Firewall Release Request 확인 결과
- `processed_at IS NULL`인 대상 Device Detection Event의 개수·ID·상세와 Gate 결과
- Device별 `last_firewall_activity_at`과 `runtime_firewall_check`
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

1. 확인 문구와 입력 집합을 검증하고, DB별 Recovery Command 잠금을 얻는다.
   같은 실제 DB를 사용하는 다른 Recovery Execute가 진행 중이면 이번 요청을
   `HOLD`·`RECOVERY_IN_PROGRESS`로 거부한다. 이 잠금은 일반 DB Writer나 Observer의
   실행을 막지 않는다.
2. 읽기 전용 Preflight로 대상 Device ID·IP·status·예상 Trust Score와 Firewall,
   Pending Release, 미처리 Detection Event, Runtime Gate를 확인한다.
3. 원본 DB를 읽기 전용(`mode=ro`)으로 열고 WAL 모드를 확인한다. WAL이 아니면
   Backup 대상 파일을 만들거나 복사하기 전에 `FAILED`로 거부한다. 읽기 Transaction과
   실제 조회로 변경 전 Snapshot을 고정한다. Python `sqlite3` Online Backup API는
   한 번에 16 Page를 복사하고 남은 Page가 있는 진행 콜백마다 20ms씩 쉰다.
   이는 I/O 경합을 줄이기 위한 Pacing이며 Writer 지연 상한이나 Capture 연속성을
   보장하지 않는다.
   복사한 Page 수와 원본 Page 크기로 계산한 약 2MiB 진행마다 Backup 파일의
   `fsync`를 요청하고, 남은 복사량도 마지막 진행에서 동기화한다. 이는 동기화
   요청 간격이며 커널의 Dirty 메모리 크기나 지연 상한을 보장하지 않는다.
   동기화 실패는 Backup 실패로 처리하고 부분 Artifact와 실패 증적을 보존한다.
   Backup Helper의 제한 시간은 600초다. 이후 Hash·전체 Health 검사는 이 제한 시간에
   포함하지 않는다. 이 Pacing 때문에 전체 Backup 시간은 길어질 수 있다.
   Backup을 마치고 원본 읽기 Transaction을 종료한 뒤 Backup SHA256과 Backup 전체의
   `PRAGMA integrity_check`·`PRAGMA foreign_key_check`를 검증하고, 실제 운영 DB
   전체에도 변경 전 Health 검사를 수행한다. Backup·Hash·전체
   Health 검사 중에는 Firewall 공용 잠금과 `BEGIN IMMEDIATE` 쓰기 잠금을 점유하지
   않는다. Observer는 이 동안에도 Snapshot을 갱신한다. Backup 안에서도 대상의
   ID·IP·예상 상태와 Gate를 확인하고, 최초 Preflight와 마지막 Firewall 활동 시각이
   같은지 검증한다.
4. Firewall 공용 잠금을 얻은 뒤 `BEGIN IMMEDIATE`를 시작한다. 공용 잠금을 기다리는
   동안 DB 쓰기 잠금을 점유하지 않는다. Transaction 안에서 Preflight 때의 대상
   Device ID·IP가 유지되는지, status가 `isolated`이고 점수가 예상값인지 다시 확인한다.
   대상 Device 또는 같은 IP의 마지막 Firewall 활동 시각도 최초 Preflight·Backup·
   최종 Transaction에서 같아야 한다. 그 사이 활동이 추가되면 새 Runtime 관측이
   있어도 이번 Command를 거부하고 다시 점검한다.
   대상 Device 또는 같은 IP의 `PENDING`·`APPLIED` Firewall Rule, `PENDING` Release
   Request와 대상 Device의 `processed_at IS NULL` Detection Event가 없어야 한다.
5. 최신 Runtime Snapshot을 읽어 TTL·마지막 Firewall 활동 이후 관측·대상 Rule 부재를
   검증한다. Backup 전에 읽은 Snapshot을 그대로 재사용하거나 TTL을 늘리지 않는다.
6. 각 Device의 status·Trust Score만 다음 조건부 UPDATE로 변경한다.

```sql
UPDATE devices
SET status = 'normal', trust_score = 100
WHERE device_id = :device_id
  AND status = 'isolated'
  AND trust_score = :expected_trust_score;
```

7. 각 UPDATE가 정확히 1개 Row를 변경했는지와 대상의 ID·IP·`normal`·`100` 상태를
   확인한다. 한 Device라도 조건을 만족하지 않으면 전체 Transaction을 Rollback한다.
8. Commit 직전에 최신 Runtime Snapshot을 다시 검증한다. 검증 실패 시 전체 UPDATE를
   Rollback한다. Commit까지 Firewall 공용 잠금을 유지하고, Transaction이 끝나면
   공용 잠금을 해제한다.
9. Firewall 공용 잠금과 SQLite 쓰기 잠금을 해제한 상태에서 실제 대상 사후 상태와
   운영 DB 전체의 integrity·FK를 확인하고 결과, Backup 경로·SHA256과 검증값을
   JSON Log에 기록한다. 마지막에 Recovery Command 잠금을 해제한다.

위 운영 Gate를 통과한 실행에서도 승인된 Writer·Packet Capture와 Runtime Observer는
계속 실행한다.
고정된 읽기 Snapshot이 끝날 때까지 필요한 WAL을 정리하지 못하므로 WAL 크기가
증가할 수 있다. Backup 중 Observer는 계속 새 Snapshot을 기록하며, 긴 Backup 시간을
이유로 Runtime Snapshot TTL을 늘리거나 최종 Runtime 검증을 생략하지 않는다.
Pacing 수치만으로 Pi의 Writer 지연 허용 기준을 충족한다고 판단하지 않는다.
Pi 재검증에서 Writer 지연·Capture 연속성·Observer 갱신을 함께 확인하여 위 운영
Gate의 통과 증적을 기록하기 전에는 운영 Execute를 진행하지 않는다.

전체 DB Health 검사는 변경 전·후에 수행한다. 최종 Transaction 안에서 전체 DB
integrity·FK를 다시 검사하지 않으므로, 전체 DB 오류를 Commit 전에 반드시 찾아
Rollback한다는 보장은 없다. 사후 Health 검사나 Audit 기록 실패 시에도 Reset은
이미 Commit되었을 수 있다. 실패 결과만 보고 미변경으로 간주하거나 Backup을 자동
복원하지 말고 실제 Device 상태와 Commit 증적을 확인한다.

성공 시 종료 코드 `0`, 안전 계약 거부 시 `2`다. 실행 실패 시 이미 생성된 Backup과
`result=FAILED` JSON은 원인 분석을 위해 보존한다.
Runtime 검증 또는 공용 잠금 획득이 실패하면 CLI는 `result=HOLD`, 종료 코드 `2`로
끝나며, API는 `409`/`HOLD`와 `firewall_release_status=NOT_VERIFIED`를 반환한다.
DB별 Recovery Command 잠금 경합은 별도로 `HOLD`·`RECOVERY_IN_PROGRESS`로 기록하며
API는 `409`를 반환한다. 이 경우 통과한 Preflight의 Firewall Release 증적을 보존한다.
Commit 후 검증·Audit 실패는 `FAILED`·`BASELINE_RECOVERY_COMMITTED_UNVERIFIED`로
구분한다. Core 증적의 `database_committed=true`와 실제 `devices.current` 상태를
확인한다. DB를 읽을 수 없으면 실제 사후 상태 필드가 없거나 확인 불가일 수 있다.
이 경우 변경 전 값으로 사후 상태를 추정하지 않는다. 이 코드가 Rollback을 의미하지는
않는다.
Core 실패 증적과 API Command 증적은 같은 `operation_id`로 연결된다.

## 6. Artifact

한 Execute마다 충돌하지 않는 UTC·난수 기반 이름을 사용한다.

```text
baseline-recovery-YYYYMMDDTHHMMSSZ-<suffix>.db
baseline-recovery-YYYYMMDDTHHMMSSZ-<suffix>.json
```

JSON의 `backup_sha256`, `backup_integrity_check`,
`backup_foreign_key_violations`와 운영 DB 전체의 변경 전 검증값인
`pre_integrity_check`·`pre_foreign_key_violations`, 변경 후 검증값인
`integrity_check`·`foreign_key_violations`를 확인한다.
Backup은 원본의 읽기 Snapshot을 고정한 시점의 일관된 변경 전 상태이며, 대상 Device의
`isolated` 상태와 예상 점수를 확인한다. 복사가 진행되는 동안과 Backup 이후에도
일반 Writer가 계속 동작하므로 다른 Row의
정상 변경은 Backup에 반영되지 않을 수 있다. Backup과 Commit 시점의 전체 DB가
완전히 같다는 의미는 아니다. 최종 Transaction에서 대상 상태와 모든 Gate를 재검사한다.

이전 Backend API를 통해 실행한 과거 JSON에는 `audit` 객체에 `reason`, `requested_by`,
`approved_by`, `requested_at`, `firewall_release_status`, 실행 직전 Preflight 요약이
추가된다. 이 값은 Recovery 관리자 인증 Context에서 파생하며 요청 Body의 임의
`approved_by` 문자열을 신뢰하지 않는다. 단순 Preflight 호출은 Artifact를 생성하지
않는다.

현재 일반 API는 요청별 `operation_id`를 DB 감사에 저장한다. DB와 과거 JSON이
함께 남더라도 History API는 같은 작업을 하나로 정규화하며 DB 값을 우선한다.
신규 성공 기록은 백업 파일이나 JSON 저장에 의존하지 않는다. 실패·거부 기록은
DB에 우선 저장하고, DB에 저장할 수 없으면 기존 JSON 방식으로 기록을 시도한다.
과거 JSON에 있는 실제 Backup 파일명·SHA256은 원본대로 보존한다.

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
- Recovery는 대상 Device의 status·Trust Score만 변경했으며 `last_seen_at`,
  `ip_address` 등 다른 컬럼, 대상 외 Device, 과거 Detection·Trust·Isolation·Firewall·
  Checkpoint·Packet Row를 수정하지 않았다.
- `integrity_check=ok`, `foreign_key_check=0건`이다.
- Recovery JSON의 결과·Backup 경로와 실제 Backup SHA256이 일치한다.

위 결과는 각 확인 시점의 상태다. 일반 Writer가 계속 동작하므로 정상 활동에 따른
새 Row나 `last_seen_at`·Trust Score 변경이 생길 수 있다. 사후 상태가 기대와 다르면
Recovery 증적과 새 Detection·Firewall 활동을 함께 확인하고 Pilot 진행을 판단한다.
전체 DB를 Backup과 단순 비교하여 모든 차이를 Recovery 변경으로 간주하지 않는다.

실행 후 서비스 상태를 다시 기록하여 `service-state-before.tsv`와 대조한다.
승인된 서비스·Packet Capture·ESP32 운영 상태와 기존 Capture Session을 유지한 채
정상 Firmware MQTT·Feature Smoke를 수행한다. Recovery가 서비스 상태를 바꾸지
않으므로 일괄 재시작이나 새 Capture Session 생성은 이 절차에 포함하지 않는다.

## 8. 실패와 복구

- 입력 또는 최초 읽기 전용 Preflight 실패: Recovery는 DB를 변경하거나
  Backup을 생성하지 않는다. 일반 Writer의 정상 작업은 계속될 수 있다.
  Artifact Directory가 아직 없으면 JSON도 생성하지 않는다. Directory가 운영자에
  의해 미리 준비되어 있으면 기존 실패 증적 정책에 따라 Backup 없는
  `result=FAILED` JSON만 기록한다.
- WAL이 아닌 DB: Execute는 `FAILED`로 거부하며 Recovery가 원본 DB나 Journal 모드를
  변경하지 않는다. Artifact Directory와 실패 JSON은 생성될 수 있지만 Backup DB는
  만들지 않는다.
- Backup 실패·600초 제한 시간 초과 또는 변경 전 전체 DB Health 검사 실패:
  Recovery의 UPDATE는 실행되지 않으며 Reset하지 않는다. 생성된 Backup·실패 증적을
  보존하고 원인을 해결한 뒤 Dry-run부터 다시 수행한다. 중단되어 완료·검증되지 않은
  Backup을 복원본으로 사용하지 않는다. 서비스나 Observer를 중지하여 우회하지 않는다.
- 조건부 UPDATE 또는 Commit 전 검증 실패: 전체 UPDATE가 Rollback된다.
- Commit 후 전체 DB Health 검사·대상 상태 검증 또는 JSON 기록 실패: Reset이 이미
  Commit되었을 수 있다. Pilot을 시작하지 않고 Backup·오류 증적을 보존하며 실제
  Device 상태와 Commit 여부를 확인한다. 승인된 서비스와 Observer 운영 상태는 유지한다.
- 복원이 필요하면 자동 복구를 추측해서 실행하지 않는다. JSON의 Backup 경로와
  SHA256을 확인하고 [`db-backup-restore.md`](db-backup-restore.md)의 승인된 전체 DB
  복구 절차를 따른다.
- 이 CLI로 Detection Event, Trust History, Isolation History, Firewall History를
  삭제하거나 보정하지 않는다.
