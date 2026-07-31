# Phase 4 MQTT UTC 시각 계약 보완 설계

## 1. 목적

Phase 4 독립 DB Smoke Test에서 운영 DB 최신 MQTT 로그 ID가 `2578`인데도
`mqtt_feature_builder+mqtt_logs` 및 `mqtt_message_rule+mqtt_logs` Checkpoint가
`2565`로 초기화되는 문제가 확인되었다.

원인은 MQTT Subscriber가 Raspberry Pi의 로컬 시각(`Asia/Seoul`)을 타임존 정보 없는
문자열로 저장하는 반면, Phase 4 Cutover와 Runtime은 UTC 기준 `unixepoch()` 비교를
사용하기 때문이다.

이 설계의 목적은 다음 세 가지다.

1. 신규 MQTT 수신 시각을 항상 UTC로 저장한다.
2. 잘못된 미래 시각이 존재하면 Cutover가 조용히 진행되지 않도록 차단한다.
3. 출처가 확실한 실기기 Smoke 데이터 13건만 안전하게 보정한다.

## 2. 현재 확인된 사실

- MQTT Subscriber 진입점은 `edge/mqtt/subscriber.py`이다.
- 현재 기본 수신 시각은 `datetime.now()`이며, 결과를 `%Y-%m-%d %H:%M:%S` 형식으로 저장한다.
- Pi 타임존은 `Asia/Seoul`이다.
- 2026-07-31 수동 Subscriber Smoke Test로 `mqtt_logs.id=2566~2578` 총 13건이 생성되었다.
- 해당 13건은 한국 로컬 시각 `2026-07-31 19:59:47~20:00:14`로 저장되었다.
- 같은 시점의 UTC Cutover 경계는 약 `2026-07-31T11:12:00Z`였다.
- SQLite는 타임존 없는 문자열을 UTC처럼 해석해 최신 13건을 Cutover 이후 미래 데이터로 판단했다.
- 운영 DB는 아직 실제 Phase 4 Cutover를 수행하지 않았고 `detector_checkpoints`는 0건이다.

## 3. 범위

### 포함

- MQTT Subscriber의 UTC 저장 계약
- 타임존 입력 검증
- Cutover 미래 MQTT 시각 방어 검증
- 관련 단위·통합 테스트
- 실기기 Smoke 데이터 13건 보정 Runbook
- 독립 DB Smoke Test 재검증 기준

### 제외

- 기존 `mqtt_logs` 전체 일괄 시각 변환
- `feature_logs` 전체 재작성
- MQTT Subscriber systemd Unit 추가
- 실제 Phase 4 Cutover 실행
- Trust Score 또는 Firewall 정책 변경

Subscriber systemd Unit은 이 UTC 계약 수정과 Smoke 재검증이 완료된 뒤 별도 작업으로 진행한다.

## 4. 시각 저장 계약

### 4.1 기본 수신 시각

`received_at`이 전달되지 않으면 다음 값을 사용한다.

```python
datetime.now(timezone.utc)
```

### 4.2 외부에서 전달된 datetime

- timezone-aware datetime: UTC로 변환한다.
- timezone-naive datetime: `ValueError`로 거부한다.
- 마이크로초: 제거한다.

Naive datetime을 자동으로 UTC 또는 로컬 시각으로 추정하지 않는다. 잘못된 입력을 조용히
수용하면 같은 문제가 다시 발생해도 감지할 수 없기 때문이다.

### 4.3 DB 문자열 형식

Phase 4의 기존 UTC 헬퍼와 같은 형식을 사용한다.

```text
YYYY-MM-DDTHH:MM:SSZ
```

예시:

```text
2026-07-31T10:59:47Z
```

가능하면 `edge.detection.phase4_time.format_db_utc()`를 재사용해 프로젝트 내부 UTC 포맷을
하나로 유지한다.

### 4.4 devices.last_seen_at

`mqtt_logs.received_at`과 동일한 UTC 문자열을 사용한다. Subscriber가 한 메시지를 저장할 때
두 필드의 시각 표현이 달라지지 않아야 한다.

## 5. Cutover 방어 검증

### 5.1 목표

Cutover가 잘못된 미래 MQTT 로그를 조용히 제외한 채 성공하지 않도록 한다.

### 5.2 허용 범위

Cutover 시각은 10초 Window 경계다. 현재 열린 Window 또는 경계 직후 입력은 정상적인
경쟁 조건으로 발생할 수 있으므로, 모든 `received_at >= cutover_at` 데이터를 오류로 보지 않는다.

허용 기준:

```text
received_at < cutover_at + 10초
```

거부 기준:

```text
received_at >= cutover_at + 10초
```

이 기준은 현재 열린 한 개의 10초 Window만 허용하고, 이번처럼 약 9시간 미래로 해석되는
데이터는 확실하게 차단한다.

### 5.3 검증 위치

`initialize_phase4_cutover()`가 Transaction을 시작한 직후, Detection Event 변경이나
Checkpoint UPSERT 전에 검증한다.

검증 실패 시:

- Transaction Rollback
- 기존 Detection Event `processed_at` 변경 없음
- Checkpoint 생성 없음
- 명확한 오류 메시지에 최대 미래 ID와 `received_at` 포함

### 5.4 파싱 불가능한 시각

`unixepoch(received_at) IS NULL`인 행이 존재하면 Cutover를 거부한다. 파싱할 수 없는 값을
과거 또는 미래로 임의 판단하지 않는다.

## 6. 테스트 설계

### 6.1 Subscriber 테스트

1. `received_at=None`
   - UTC `Z` 형식으로 저장되는지 검증한다.
   - 시스템 타임존에 의존하지 않도록 Clock 주입 또는 패치 가능한 최소 구조를 사용한다.

2. UTC aware datetime
   - 같은 UTC 시각으로 저장되는지 검증한다.

3. Asia/Seoul aware datetime
   - `2026-07-31T19:59:47+09:00`이 `2026-07-31T10:59:47Z`로 저장되는지 검증한다.

4. Naive datetime
   - `ValueError`가 발생하는지 검증한다.

5. `insert_mqtt_log()`
   - `mqtt_logs.received_at`과 `devices.last_seen_at`이 같은 UTC 문자열인지 검증한다.

### 6.2 Cutover 테스트

1. 서울 aware datetime을 Subscriber 포맷으로 생성한 MQTT 로그
   - UTC Cutover 이전 로그로 정상 포함되는지 검증한다.

2. Cutover 경계 직후 9초 이내 로그
   - 허용되고 Checkpoint에는 포함되지 않는지 검증한다.

3. Cutover 경계 이후 10초 이상 미래 로그
   - Cutover가 실패하는지 검증한다.
   - Checkpoint와 Detection Event가 변경되지 않는지 검증한다.

4. 파싱 불가능한 `received_at`
   - Cutover가 실패하는지 검증한다.

5. 정상 DB
   - `MAX(id) WHERE received_at < cutover_at` 값이 MQTT 관련 두 Checkpoint와 일치하는지 검증한다.

### 6.3 회귀 테스트

최소 실행 범위:

```text
tests/test_mqtt_feature_pipeline.py
tests/test_phase4_cutover_repository.py
tests/test_mqtt_feature_builder_runtime.py
tests/test_phase4_detection_core.py
```

그 후 전체 `pytest`를 실행한다.

## 7. 실기기 DB 13건 보정 설계

### 7.1 대상

```text
mqtt_logs.id BETWEEN 2566 AND 2578
```

보정 전에 다음 조건을 모두 검증한다.

- 정확히 13건
- device_id가 `esp32_01` 또는 `esp32_02`
- topic이 `iot/{device_id}/sensor`
- `received_at` 범위가 `2026-07-31 19:59:47~20:00:14`
- `is_json_valid=1`
- `is_topic_valid=1`
- `error_message IS NULL`

조건이 하나라도 다르면 자동 보정을 중단한다.

### 7.2 보정 방식

확인된 13건만 9시간 차감하고 UTC `Z` 문자열로 변환한다.

예시:

```text
2026-07-31 19:59:47
→ 2026-07-31T10:59:47Z
```

전체 과거 데이터를 변환하지 않는다. 과거 Row가 모두 같은 호스트·타임존·수집 경로에서
생성됐다고 확정할 수 없고, 이미 생성된 Legacy Feature Window와 불필요한 충돌이 생길 수 있다.

### 7.3 last_seen_at 재계산

보정 후 `esp32_01`, `esp32_02`의 `last_seen_at`을 각 기기의 `mqtt_logs.MAX(received_at)`으로
재계산한다.

### 7.4 안전 절차

1. DB Writer 서비스 중지
2. SQLite Backup API로 백업
3. 백업 DB SHA256 기록
4. 백업 `integrity_check=ok`, `foreign_key_check=0` 확인
5. 대상 13건 사전 조건 검증
6. 단일 Transaction에서 보정과 `last_seen_at` 재계산
7. 운영 DB `integrity_check`, `foreign_key_check`
8. 변경 전후 대상 Row 출력
9. 기존 서비스 원상복구

보정은 코드 수정과 테스트가 병합되고 Pi에 반영된 뒤 수행한다.

## 8. 독립 Smoke Test 재검증

재실행 시 다음 값을 비교한다.

```sql
SELECT MAX(id)
FROM mqtt_logs
WHERE unixepoch(received_at) < unixepoch(:cutover_at);
```

이 값은 다음 Checkpoint와 일치해야 한다.

- `mqtt_feature_builder+mqtt_logs.last_processed_id`
- `mqtt_message_rule+mqtt_logs.last_processed_id`

단순 `SELECT MAX(id)` 비교는 현재 열린 Window의 정상 메시지가 존재할 수 있어 사용하지 않는다.

추가 성공 기준:

- Source DB Snapshot 전후 SHA256 일치
- Source Row Count 전후 일치
- Smoke DB Checkpoint 7개
- 운영 DB Checkpoint 0개 유지
- 기존 서비스 원상복구
- 신규 Runtime 3개 inactive 유지
- iptables Rules 불변

## 9. 구현 순서

1. 실패 테스트 추가
2. Subscriber UTC 정규화 구현
3. Subscriber 저장 테스트 통과
4. Cutover 미래 시각 방어 실패 테스트 추가
5. Cutover 검증 구현
6. 관련 회귀 테스트
7. 전체 테스트
8. PR 생성 및 검토
9. Pi 반영
10. 운영 DB 13건 백업·보정
11. 독립 Smoke Test 재실행
12. MQTT Subscriber systemd Unit 별도 작업
13. 실제 Phase 4 Cutover

## 10. 완료 조건

- 모든 신규·기존 테스트 통과
- 서울 타임존 aware 입력이 정확한 UTC 문자열로 저장됨
- Naive datetime이 거부됨
- 잘못된 미래 MQTT 로그가 있는 DB에서 Cutover 실패
- 정상 DB에서 MQTT 관련 두 Checkpoint가 완료된 Cutover 경계의 최대 ID와 일치
- Pi 운영 DB 13건 보정 백업과 SHA256 기록
- 재실행 Smoke Test 통과
- 실제 Phase 4 Cutover는 별도 승인 전까지 실행하지 않음
