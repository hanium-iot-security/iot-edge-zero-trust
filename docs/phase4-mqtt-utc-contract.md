# Phase 4 MQTT UTC 시각 계약

## 1. 목적

Phase 4의 MQTT 수집·Feature 생성·Detection·Cutover 경로가 동일한 UTC 시각 계약을 사용하도록 한다.

노션 `Phase 4 세부계획`은 Phase 4 입력과 Window를 UTC 정수 초 기준의 정확한 10초 반개구간
`[window_start, window_end)`으로 운영하도록 정의한다. 현재 Detection Core도 MQTT Source Row를
`received_at < producer_cutoff` 조건으로 선택하고, Producer Checkpoint와 Cutover Checkpoint를 UTC
10초 경계로 관리한다.

그러나 현재 `edge/mqtt/subscriber.py`는 Raspberry Pi의 로컬 시각을 타임존 정보 없는 문자열로
저장한다. Pi 타임존이 `Asia/Seoul`인 상태에서 이 값이 SQLite `unixepoch()`와 Phase 4 UTC Parser에
전달되면 한국 로컬 시각이 UTC로 잘못 해석될 수 있다.

이 문서는 다음 계약을 고정한다.

1. 신규 MQTT 수신 시각은 항상 UTC로 저장한다.
2. 타임존을 알 수 없는 `datetime` 입력은 조용히 추정하지 않고 거부한다.
3. Cutover는 파싱 불가능하거나 비정상적으로 미래인 MQTT 시각이 있으면 Checkpoint를 만들지 않는다.
4. 기존 운영 DB 보정은 전체 일괄 변환이 아니라 검증된 대상만 백업 후 수행한다.

## 2. 현재 구현과 문제 경계

### 2.1 MQTT Subscriber

현재 `edge/mqtt/subscriber.py`는 다음 방식으로 `received_at`을 생성한다.

```python
(received_at or datetime.now()).replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
```

이 방식에는 두 문제가 있다.

- `datetime.now()`가 Host Local Time을 사용한다.
- 저장 문자열에 UTC Offset 또는 `Z`가 없다.

동일 문자열은 `mqtt_logs.received_at`과 `devices.last_seen_at`에 함께 저장된다.

### 2.2 Phase 4 Time Helper

`edge.detection.phase4_time.parse_db_utc()`는 타임존 없는 DB 문자열을 UTC로 간주한다.
이는 기존 Legacy Row 호환을 위한 동작이지만, 실제 한국 로컬 시각이 타임존 없이 저장되면
잘못된 시각을 정상 UTC로 받아들이게 된다.

### 2.3 MQTT Feature Producer

`edge.features.collect_feature_logs.produce_mqtt_features_until()`은 Phase 4 경로에서 다음 계약을 사용한다.

- `producer_cutoff`: timezone-aware UTC, 정수 초, 10초 경계
- Source Eligibility: `unixepoch(received_at) < unixepoch(cutoff)`
- Feature Window: UTC `YYYY-MM-DDTHH:MM:SSZ`
- 현재 열린 Window는 처리하지 않음
- Feature 저장과 Producer Checkpoint 갱신은 같은 Transaction

따라서 `received_at`이 실제 UTC가 아니면 Source 선택과 Window 배치가 모두 잘못될 수 있다.

### 2.4 Phase 4 Cutover

`edge.detection.phase4_cutover_repository.initialize_phase4_cutover()`는 MQTT 관련 Checkpoint를
다음 Source Boundary로 초기화한다.

```sql
SELECT MAX(id)
FROM mqtt_logs
WHERE unixepoch(received_at) < unixepoch(:completed_window_end);
```

잘못된 미래 시각은 오류로 처리되지 않고 단순 제외되므로, Cutover 자체는 성공하면서 최신 MQTT Row가
Checkpoint에서 빠질 수 있다.

## 3. 문서 역할과 범위

### 포함

- MQTT Subscriber의 UTC 저장 계약
- 외부 `datetime` 입력 검증
- `mqtt_logs.received_at`과 `devices.last_seen_at`의 동일 시각 계약
- Cutover의 MQTT Timestamp Preflight
- 관련 단위·통합·회귀 테스트
- 운영 DB 보정의 일반 안전 원칙
- 독립 DB Smoke Test 재검증 기준

### 제외

- 기존 `mqtt_logs` 전체 일괄 변환
- Legacy `feature_logs` 전체 재작성
- MQTT Subscriber systemd Unit 추가
- 실제 운영 DB Cutover 실행
- Trust Score, Detection Policy, Firewall Policy 변경
- 실기기별 Row ID·백업 경로·SHA256 같은 실행 결과 기록

실기기별 실행 결과는 노션 `Phase 4 실기기 설정·검증 기록`에 남긴다. 저장소 문서는 재사용 가능한
계약과 절차만 유지한다.

## 4. MQTT 저장 시각 계약

### 4.1 기본 시각

`received_at`이 전달되지 않으면 UTC Clock을 사용한다.

```python
datetime.now(timezone.utc)
```

테스트에서 기본 Clock을 고정할 수 있도록 Subscriber 모듈에 작은 `_utc_now()` Helper를 두고,
`build_mqtt_log_row()`가 이를 호출하도록 한다. 공개 함수에 테스트 전용 Clock Parameter를 추가하지 않는다.

### 4.2 외부에서 전달된 datetime

- timezone-aware datetime: UTC로 변환한다.
- timezone-naive datetime: `ValueError`로 거부한다.
- 마이크로초: 제거한다.
- Host Timezone을 조회해 자동 보정하지 않는다.
- Naive 값을 UTC라고 묵시적으로 간주하지 않는다.

Naive 입력을 허용하면 한국 로컬 시각과 UTC 시각을 구분할 수 없으므로 같은 문제가 재발해도 탐지할 수 없다.

### 4.3 DB 문자열 형식

Phase 4 공통 Helper인 `edge.detection.phase4_time.format_db_utc()`를 사용한다.

```text
YYYY-MM-DDTHH:MM:SSZ
```

예시:

```text
2026-07-31T10:59:47Z
```

별도 MQTT 전용 Formatter를 만들지 않는다.

### 4.4 last_seen_at

한 MQTT 메시지 Transaction에서 다음 두 값은 완전히 동일해야 한다.

```text
mqtt_logs.received_at
=
devices.last_seen_at
```

Subscriber가 생성한 UTC 문자열 하나를 두 Query에 재사용한다.

### 4.5 기존 호출부 호환

현재 자동 테스트 중 `build_mqtt_log_row()`에 Naive `datetime`을 전달하는 테스트는 새 계약에 맞춰
UTC-aware 값으로 수정한다. 운영 Runtime의 일반 메시지 수신은 `received_at`을 전달하지 않으므로
기본 UTC Clock 경로를 사용한다.

## 5. Cutover MQTT Timestamp Preflight

### 5.1 위치

`initialize_phase4_cutover()`가 `BEGIN IMMEDIATE`를 시작한 직후, 다음 작업보다 먼저 수행한다.

- Legacy Detection Event 표시
- Detector Checkpoint UPSERT
- 기타 Cutover DB 변경

검증 실패 시 Transaction을 Rollback하고 Checkpoint를 만들지 않는다.

### 5.2 파싱 검증

다음 Row가 하나라도 존재하면 Cutover를 거부한다.

```sql
SELECT id, received_at
FROM mqtt_logs
WHERE unixepoch(received_at) IS NULL
LIMIT 1;
```

오류에는 최소한 Source Table, Row ID, 원래 `received_at`을 포함한다.

### 5.3 미래 시각 검증

Cutover 시각은 UTC 10초 Window 경계다. Cutover가 시작된 시점에 현재 열린 Window의 MQTT Row가
이미 저장돼 있을 수 있으므로 `received_at >= cutover_at`을 전부 오류로 보지 않는다.

허용 범위:

```text
received_at < cutover_at + 10초
```

거부 범위:

```text
received_at >= cutover_at + 10초
```

이 기준은 현재 열린 한 Window만 허용한다. Host Timezone 오해, Clock 오설정 또는 비정상 입력으로
수십 초·수시간 미래에 기록된 Row는 Cutover 전에 차단한다.

Preflight Query는 미래 Row Count와 가장 이른 문제 Row를 확인할 수 있어야 하며, 오류에는 다음을 포함한다.

- 문제 Row 수
- 첫 문제 Row ID
- 첫 문제 `received_at`
- 허용 상한

### 5.4 정상 Checkpoint 기준

Cutover가 성공한 경우 다음 값이 MQTT 관련 두 Checkpoint와 일치해야 한다.

```sql
SELECT MAX(id)
FROM mqtt_logs
WHERE unixepoch(received_at) < unixepoch(:cutover_at);
```

대상 Checkpoint:

- `mqtt_feature_builder+mqtt_logs.last_processed_id`
- `mqtt_message_rule+mqtt_logs.last_processed_id`

단순 `SELECT MAX(id)`는 현재 열린 Window Row를 포함할 수 있으므로 성공 기준으로 사용하지 않는다.

## 6. 테스트 설계

### 6.1 Subscriber 단위 테스트

1. 기본 Clock
   - `_utc_now()`를 고정한다.
   - 결과가 정확한 UTC `Z` 문자열인지 확인한다.

2. UTC-aware 입력
   - 동일 UTC 정수 초 문자열로 저장되는지 확인한다.

3. Asia/Seoul aware 입력
   - `2026-07-31T19:59:47+09:00`이 `2026-07-31T10:59:47Z`가 되는지 확인한다.

4. Naive 입력
   - `ValueError`가 발생하는지 확인한다.

5. DB 저장
   - `mqtt_logs.received_at`과 `devices.last_seen_at`이 같은 UTC 문자열인지 확인한다.

### 6.2 Cutover 단위·통합 테스트

1. 정상 UTC MQTT Row
   - Cutover 이전 Row가 MQTT 관련 두 Checkpoint에 포함되는지 확인한다.

2. 현재 열린 Window Row
   - `cutover_at`부터 `cutover_at + 9초`까지는 Preflight를 통과한다.
   - 해당 Row는 Cutover Checkpoint에는 포함되지 않는다.

3. 비정상 미래 Row
   - `cutover_at + 10초` 이상이면 Cutover가 실패한다.
   - Detection Event와 Checkpoint가 변경되지 않는다.

4. 파싱 불가능한 Row
   - Cutover가 실패한다.
   - Detection Event와 Checkpoint가 변경되지 않는다.

5. Boundary 일치
   - `MAX(id) WHERE received_at < cutover_at`과 MQTT 관련 두 Checkpoint가 일치한다.

### 6.3 회귀 테스트

우선 실행:

```text
tests/test_mqtt_feature_pipeline.py
tests/test_phase4_cutover_repository.py
tests/test_mqtt_feature_builder_runtime.py
tests/test_phase4_detection_core.py
```

관련 테스트 통과 후 전체 `pytest`를 실행한다.

## 7. 운영 DB 보정 원칙

운영 DB 보정은 코드 수정과 자동 테스트가 병합되고 Pi에 반영된 뒤 별도 승인으로 수행한다.

### 7.1 대상 선정

- 실제 수동 Subscriber Smoke Test에서 생성됐다고 증명할 수 있는 Row만 대상으로 한다.
- 예상 Row 수, Device ID, Topic, Payload Validation Flag, 시간 범위를 모두 확인한다.
- 조건 하나라도 다르면 자동 보정을 중단한다.
- 전체 과거 `mqtt_logs`를 일괄 이동하지 않는다.

### 7.2 보정 방식

확인된 한국 로컬 Naive Timestamp만 9시간 차감해 UTC `Z` 문자열로 변환한다.

```text
2026-07-31 19:59:47
→ 2026-07-31T10:59:47Z
```

단순 문자열 치환이 아니라 Python `datetime` Parsing과 `timezone(timedelta(hours=9))`을 사용해 UTC로 변환한다.

### 7.3 안전 절차

1. 실제 DB Writer 식별
2. Writer 서비스 일시 중지
3. SQLite Backup API로 Snapshot 생성
4. Backup SHA256 기록
5. Backup `integrity_check=ok`, `foreign_key_check=0` 검증
6. 대상 Row 사전 조건 검증
7. 단일 Transaction에서 Timestamp 보정
8. `devices.last_seen_at`을 기기별 최신 `mqtt_logs.received_at`으로 재계산
9. 운영 DB `integrity_check`, `foreign_key_check`
10. Writer 서비스 원상복구
11. 변경 전후 Row, Backup Path, SHA256, Service State를 노션 실기기 기록에 저장

## 8. 독립 DB Smoke Test 재검증

UTC 코드 수정과 운영 DB 보정 후 Smoke Test를 다시 실행한다.

성공 기준:

- Source DB Snapshot 전후 SHA256 일치
- Source Table Row Count 전후 일치
- Smoke DB `integrity_check=ok`
- Smoke DB `foreign_key_check=0`
- Migration `001`, `002`, `003` 확인
- Detector Checkpoint 7개 생성
- 운영 DB Detector Checkpoint 0개 유지
- MQTT 완료 경계의 최대 ID와 MQTT 관련 두 Checkpoint 일치
- 기존 Writer 서비스 원상복구
- 신규 Runtime은 승인 전까지 inactive
- iptables Rules 불변

## 9. 문서 분리 원칙

이 문서는 재사용 가능한 시각 계약과 설계 기준을 다룬다.

- 계약·설계: `docs/phase4-mqtt-utc-contract.md`
- 구현 순서: `docs/plans/2026-07-31-phase4-mqtt-utc-contract.md`
- 일반 Cutover 운영 절차: `docs/phase4-cutover-runbook.md`
- 실기기 Row ID, Backup Path, SHA256, 실행 결과: 노션 `Phase 4 실기기 설정·검증 기록`

구현 계획 문서는 이 계약이 승인된 뒤 별도로 작성한다.

## 10. 완료 조건

- 신규 MQTT Row가 Host Timezone과 무관하게 UTC `Z` 형식으로 저장됨
- Naive `datetime` 입력이 거부됨
- `mqtt_logs.received_at`과 `devices.last_seen_at`이 같은 UTC 문자열을 사용함
- 파싱 불가능하거나 허용 범위를 넘는 미래 MQTT Row가 있으면 Cutover가 실패함
- 정상 DB에서 MQTT 관련 두 Checkpoint가 완료된 Cutover 경계의 최대 Source ID와 일치함
- 관련 테스트와 전체 회귀 테스트가 통과함
- 실기기 DB 보정은 검증된 Backup과 별도 승인 아래 수행됨
- 실제 Phase 4 Cutover는 별도 승인 전까지 실행하지 않음
