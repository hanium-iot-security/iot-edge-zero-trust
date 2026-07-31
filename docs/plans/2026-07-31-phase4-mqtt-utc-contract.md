# Phase 4 MQTT UTC 시각 계약 구현 계획

**목표:** MQTT Subscriber가 신규 수신 시각을 UTC `Z` 형식으로 저장하고, Cutover가 비정상 MQTT Timestamp를 사전에 차단하며, 기존 Legacy Row·Phase 4 Runtime·API·React Dashboard와의 정합성을 유지한다.

**구현 방식:** 입력 시점에서 aware datetime만 UTC로 정규화하고, Phase 4 공통 시간 Helper를 재사용한다. Cutover는 DB 변경 전에 MQTT Timestamp Preflight를 수행한다. Legacy Timestamp Parser는 기존 Row 호환을 위해 유지하고, API의 최근 로그 정렬만 `unixepoch()` 기반으로 보완한다.

**기술 스택:** Python 3.10, SQLite, SQLAlchemy, pytest, FastAPI, React

## 전체 제약

- 실제 운영 DB를 이 브랜치의 코드 변경 과정에서 수정하지 않는다.
- DB Migration을 추가하지 않는다. 현재 Migration 기준은 `001`, `002`, `003`이다.
- `edge.detection.phase4_time.parse_db_utc()`의 Naive DB 문자열을 UTC로 간주하는 Legacy 호환 동작은 변경하지 않는다.
- `edge.features.collect_feature_logs.collect_feature_windows()`의 MVP Legacy 출력 형식은 변경하지 않는다.
- Legacy Feature Collector와 Phase 4 MQTT Feature Producer를 동시에 실행하지 않는다.
- 신규 MQTT Timestamp는 `YYYY-MM-DDTHH:MM:SSZ` 형식으로 저장한다.
- `mqtt_logs.received_at`과 `devices.last_seen_at`은 동일한 문자열을 사용한다.
- Cutover는 `received_at >= cutover_at + 10초` 또는 파싱 불가능한 Row가 있으면 DB 변경 전에 실패한다.
- 실제 DB 보정과 실제 Cutover는 별도 승인 전까지 실행하지 않는다.

---

## 1. 영향도와 변경 경계

### 변경 대상

- `edge/mqtt/subscriber.py`
  - 신규 MQTT Timestamp를 UTC로 생성·정규화한다.
- `edge/detection/phase4_cutover_repository.py`
  - Cutover Transaction의 첫 단계로 MQTT Timestamp Preflight를 추가한다.
- `backend/app/services/mqtt_log_query_service.py`
  - Legacy 공백 형식과 신규 `Z` 형식이 섞여도 실제 시각순으로 조회되도록 정렬한다.
- `tests/test_mqtt_feature_pipeline.py`
  - Subscriber UTC 계약과 `last_seen_at` 저장 일치를 검증한다.
- `tests/test_phase4_cutover_repository.py`
  - Cutover Timestamp Preflight와 Rollback 불변성을 검증한다.
- `tests/test_mqtt_log_query_service.py`
  - 혼합 Timestamp 형식의 API 조회 순서를 검증한다.
- `docs/db-schema.md`
  - 신규 Subscriber의 UTC 저장 계약과 Legacy Row 호환 범위를 명시한다.
- `docs/phase4-cutover-runbook.md`
  - Cutover 전 MQTT Timestamp Preflight 판정 기준을 추가한다.

### 변경하지 않는 대상

- `edge/detection/phase4_time.py`
  - Phase 4 Runtime과 Legacy DB Row가 함께 존재하므로 Naive DB 문자열 Parser를 엄격하게 바꾸지 않는다.
- `edge/features/collect_feature_logs.py`의 Legacy `collect_feature_windows()`
  - 기존 MVP 테스트와 Legacy Feature 형식을 보존한다. Phase 4 전환 후에는 기존 CLI가 Checkpoint 존재를 보고 실행을 거부한다.
- `edge/detection/mqtt_adapters.py`
  - 이미 `unixepoch()`와 `parse_db_utc()`를 사용하므로 신규 UTC `Z` Row와 호환된다.
- Frontend `Logs.jsx`, `Devices.jsx`
  - `new Date(value)`로 ISO UTC를 파싱하고 `Asia/Seoul`로 표시하므로 코드 변경이 필요 없다.
- DB Migration
  - SQLite의 기존 DATETIME 컬럼은 UTC `Z` 문자열을 저장할 수 있고, `CURRENT_TIMESTAMP` 기반 Legacy UTC 문자열도 `unixepoch()`로 해석 가능하다.

---

## Task 1: Subscriber UTC 저장 계약

**파일:**
- 수정: `tests/test_mqtt_feature_pipeline.py`
- 수정: `edge/mqtt/subscriber.py`

**인터페이스:**
- 입력: `build_mqtt_log_row(topic, payload, received_at=None)`
- 출력: `received_at`이 UTC 정수 초 `YYYY-MM-DDTHH:MM:SSZ`인 Row Dictionary
- 오류: 외부에서 전달된 Naive `datetime`은 `ValueError`

- [ ] **1.1 UTC-aware 입력 테스트 추가**

```python
from datetime import datetime, timedelta, timezone


def test_build_mqtt_log_row_formats_utc_aware_timestamp() -> None:
    row = build_mqtt_log_row(
        "iot/esp32_01/sensor",
        '{"device_id":"esp32_01"}',
        received_at=datetime(2026, 7, 31, 10, 59, 47, tzinfo=timezone.utc),
    )

    assert row["received_at"] == "2026-07-31T10:59:47Z"
```

- [ ] **1.2 Asia/Seoul aware 입력 정규화 테스트 추가**

```python
def test_build_mqtt_log_row_normalizes_seoul_timestamp_to_utc() -> None:
    seoul = timezone(timedelta(hours=9))
    row = build_mqtt_log_row(
        "iot/esp32_01/sensor",
        '{"device_id":"esp32_01"}',
        received_at=datetime(2026, 7, 31, 19, 59, 47, tzinfo=seoul),
    )

    assert row["received_at"] == "2026-07-31T10:59:47Z"
```

- [ ] **1.3 Naive 입력 거부 테스트 추가**

```python
import pytest


def test_build_mqtt_log_row_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="received_at must be timezone-aware"):
        build_mqtt_log_row(
            "iot/esp32_01/sensor",
            '{"device_id":"esp32_01"}',
            received_at=datetime(2026, 7, 31, 19, 59, 47),
        )
```

- [ ] **1.4 테스트가 현재 로컬 공백 형식 때문에 실패하는지 확인**

실행:

```bash
python -m pytest \
  tests/test_mqtt_feature_pipeline.py::test_build_mqtt_log_row_formats_utc_aware_timestamp \
  tests/test_mqtt_feature_pipeline.py::test_build_mqtt_log_row_normalizes_seoul_timestamp_to_utc \
  tests/test_mqtt_feature_pipeline.py::test_build_mqtt_log_row_rejects_naive_timestamp \
  -q
```

예상: UTC 포맷과 Naive 거부 기능이 없어 실패한다.

- [ ] **1.5 최소 UTC 정규화 구현**

`edge/mqtt/subscriber.py`에 다음 비공개 Helper를 추가한다.

```python
from datetime import datetime, timezone

from edge.detection.phase4_time import format_db_utc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_received_at(value: datetime | None) -> datetime:
    timestamp = value if value is not None else _utc_now()
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("received_at must be timezone-aware")
    return timestamp.astimezone(timezone.utc).replace(microsecond=0)
```

`build_mqtt_log_row()`는 다음 값을 사용한다.

```python
"received_at": format_db_utc(_normalize_received_at(received_at)),
```

- [ ] **1.6 기존 Topic·Payload 테스트의 명시적 Naive Timestamp를 UTC-aware로 수정**

```python
received_at=datetime(2026, 5, 26, 14, 30, 1, tzinfo=timezone.utc)
```

테스트의 목적은 Topic·Payload 검증이므로 Timestamp 계약 변경으로 불필요하게 깨지지 않게 한다.

- [ ] **1.7 Subscriber 테스트 통과 확인**

```bash
python -m pytest tests/test_mqtt_feature_pipeline.py -q
```

예상: PASS.

---

## Task 2: DB 저장과 last_seen_at 정합성

**파일:**
- 수정: `tests/test_mqtt_feature_pipeline.py`
- 검증: `edge/mqtt/subscriber.py`

**인터페이스:**
- 입력: `insert_mqtt_log(db, row)`
- 출력: 한 메시지에 대해 `mqtt_logs.received_at == devices.last_seen_at`

- [ ] **2.1 DB 저장 정합성 실패 테스트 추가**

```python
def test_insert_mqtt_log_keeps_last_seen_equal_to_received_at(db_session) -> None:
    device_id = "test_mqtt_utc_device"
    cleanup_device(db_session, device_id)
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, '192.168.0.99', 'normal', 100)
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    row = build_mqtt_log_row(
        f"iot/{device_id}/sensor",
        f'{{"device_id":"{device_id}"}}',
        received_at=datetime(2026, 7, 31, 10, 59, 47, tzinfo=timezone.utc),
    )
    insert_mqtt_log(db_session, row)

    stored = db_session.execute(
        text(
            """
            SELECT m.received_at, d.last_seen_at
            FROM mqtt_logs AS m
            JOIN devices AS d ON d.device_id = m.device_id
            WHERE m.device_id = :device_id
            ORDER BY m.id DESC
            LIMIT 1
            """
        ),
        {"device_id": device_id},
    ).mappings().one()

    assert stored["received_at"] == "2026-07-31T10:59:47Z"
    assert stored["last_seen_at"] == stored["received_at"]
    cleanup_device(db_session, device_id)
```

- [ ] **2.2 테스트 실행**

```bash
python -m pytest \
  tests/test_mqtt_feature_pipeline.py::test_insert_mqtt_log_keeps_last_seen_equal_to_received_at \
  -q
```

예상: Task 1 구현 후 PASS. 실패하면 `insert_mqtt_log()`가 Row의 동일 Timestamp를 두 Query에 재사용하는지 수정한다.

---

## Task 3: Cutover MQTT Timestamp Preflight

**파일:**
- 수정: `tests/test_phase4_cutover_repository.py`
- 수정: `edge/detection/phase4_cutover_repository.py`

**인터페이스:**
- 입력: `initialize_phase4_cutover(database_path, phase4_cutover_at)`
- 출력: 정상 DB는 기존 7개 Checkpoint Summary
- 오류: 파싱 불가 또는 `cutover_at + 10초` 이상 미래 MQTT Row가 있으면 `ValueError`

- [ ] **3.1 현재 열린 Window 허용 테스트 추가**

```python
def test_initialize_phase4_cutover_allows_current_open_mqtt_window(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        included_id = _insert_mqtt_log(
            connection,
            received_at="2026-07-21T04:29:59Z",
        )
        _insert_mqtt_log(connection, received_at="2026-07-21T04:30:09Z")

    summary = initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    assert summary["checkpoints"]["mqtt_feature_builder+mqtt_logs"][
        "last_processed_id"
    ] == included_id
    assert summary["checkpoints"]["mqtt_message_rule+mqtt_logs"][
        "last_processed_id"
    ] == included_id
```

- [ ] **3.2 비정상 미래 Row 거부와 Rollback 테스트 추가**

```python
def test_initialize_phase4_cutover_rejects_mqtt_timestamp_beyond_open_window(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        event_id = _insert_detection_event(
            connection,
            event_type="ABNORMAL_TOPIC",
            score_delta=-20,
            applied_to_score=0,
            detected_at="2026-07-21T04:29:59Z",
        )
        future_id = _insert_mqtt_log(
            connection,
            received_at="2026-07-21T04:30:10Z",
        )

    with pytest.raises(
        ValueError,
        match=rf"mqtt_logs.*id={future_id}.*2026-07-21T04:30:10Z",
    ):
        initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    with connect_database(migrated_db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM detector_checkpoints"
        ).fetchone()[0] == 0
        event = connection.execute(
            "SELECT processed_at, processing_reason FROM detection_events WHERE id = ?",
            (event_id,),
        ).fetchone()
        assert event["processed_at"] is None
        assert event["processing_reason"] is None
```

- [ ] **3.3 파싱 불가능한 Timestamp 거부 테스트 추가**

```python
def test_initialize_phase4_cutover_rejects_unparseable_mqtt_timestamp(
    migrated_db: Path,
) -> None:
    with connect_database(migrated_db) as connection:
        mqtt_id = _insert_mqtt_log(connection, received_at="not-a-timestamp")

    with pytest.raises(
        ValueError,
        match=rf"mqtt_logs.*id={mqtt_id}.*not-a-timestamp",
    ):
        initialize_phase4_cutover(migrated_db, CUTOVER_AT)

    with connect_database(migrated_db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM detector_checkpoints"
        ).fetchone()[0] == 0
```

- [ ] **3.4 신규 테스트가 현재 조용히 성공하는지 확인**

```bash
python -m pytest \
  tests/test_phase4_cutover_repository.py::test_initialize_phase4_cutover_allows_current_open_mqtt_window \
  tests/test_phase4_cutover_repository.py::test_initialize_phase4_cutover_rejects_mqtt_timestamp_beyond_open_window \
  tests/test_phase4_cutover_repository.py::test_initialize_phase4_cutover_rejects_unparseable_mqtt_timestamp \
  -q
```

예상: 허용 테스트는 통과할 수 있지만, 두 거부 테스트는 Preflight가 없어 실패한다.

- [ ] **3.5 Preflight 구현**

`BEGIN IMMEDIATE` 직후 `_validate_mqtt_timestamps(connection, cutover_at)`를 호출한다.

```python
def _validate_mqtt_timestamps(
    connection: sqlite3.Connection,
    cutover_at: datetime,
) -> None:
    invalid = connection.execute(
        """
        SELECT id, received_at
        FROM mqtt_logs
        WHERE unixepoch(received_at) IS NULL
        ORDER BY id ASC
        LIMIT 1
        """
    ).fetchone()
    if invalid is not None:
        raise ValueError(
            "mqtt_logs contains an unparseable received_at: "
            f"id={invalid['id']} received_at={invalid['received_at']}"
        )

    allowed_before = cutover_at + timedelta(seconds=10)
    count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM mqtt_logs
        WHERE unixepoch(received_at) >= unixepoch(:allowed_before)
        """,
        {"allowed_before": format_utc_iso(allowed_before)},
    ).fetchone()["count"]
    if not count:
        return

    first = connection.execute(
        """
        SELECT id, received_at
        FROM mqtt_logs
        WHERE unixepoch(received_at) >= unixepoch(:allowed_before)
        ORDER BY unixepoch(received_at) ASC, id ASC
        LIMIT 1
        """,
        {"allowed_before": format_utc_iso(allowed_before)},
    ).fetchone()
    raise ValueError(
        "mqtt_logs contains timestamps beyond the allowed open window: "
        f"count={count} id={first['id']} received_at={first['received_at']} "
        f"allowed_before={format_utc_iso(allowed_before)}"
    )
```

- [ ] **3.6 Cutover 관련 테스트 통과 확인**

```bash
python -m pytest tests/test_phase4_cutover_repository.py -q
```

예상: PASS.

---

## Task 4: 혼합 Timestamp 형식 API 정렬

**파일:**
- 생성: `tests/test_mqtt_log_query_service.py`
- 수정: `backend/app/services/mqtt_log_query_service.py`

**인터페이스:**
- 입력: Legacy `YYYY-MM-DD HH:MM:SS`와 신규 `YYYY-MM-DDTHH:MM:SSZ`가 섞인 `mqtt_logs`
- 출력: `/api/mqtt-logs` 조회가 실제 Epoch 내림차순

- [ ] **4.1 문자열 정렬 결함을 재현하는 실패 테스트 작성**

```python
from sqlalchemy import text

from backend.app.services.mqtt_log_query_service import list_mqtt_logs
from tests.conftest import cleanup_device


def test_list_mqtt_logs_orders_mixed_timestamp_formats_by_actual_time(db_session) -> None:
    device_id = "test_mqtt_order"
    cleanup_device(db_session, device_id)
    db_session.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, '192.168.0.98', 'normal', 100)
            """
        ),
        {"device_id": device_id},
    )
    db_session.execute(
        text(
            """
            INSERT INTO mqtt_logs (
                device_id, topic, payload, payload_size,
                received_at, is_json_valid, is_topic_valid
            )
            VALUES
                (:device_id, 'iot/test_mqtt_order/sensor', '{}', 2,
                 '2026-07-31 10:00:09', 1, 1),
                (:device_id, 'iot/test_mqtt_order/sensor', '{}', 2,
                 '2026-07-31T10:00:01Z', 1, 1)
            """
        ),
        {"device_id": device_id},
    )
    db_session.commit()

    result = list_mqtt_logs(db_session, device_id=device_id)

    assert [row["received_at"] for row in result["items"]] == [
        "2026-07-31 10:00:09",
        "2026-07-31T10:00:01Z",
    ]
    cleanup_device(db_session, device_id)
```

- [ ] **4.2 현재 문자열 정렬로 실패하는지 확인**

```bash
python -m pytest tests/test_mqtt_log_query_service.py -q
```

예상: `T` 문자가 공백보다 뒤에서 정렬돼 실제 시각과 반대 순서로 실패한다.

- [ ] **4.3 최소 정렬 수정**

```sql
ORDER BY unixepoch(received_at) DESC, id DESC
```

응답 Timestamp 문자열 자체는 변환하지 않는다. 기존 API 계약과 Frontend 표시를 보존한다.

- [ ] **4.4 API Query 테스트 통과 확인**

```bash
python -m pytest tests/test_mqtt_log_query_service.py -q
```

예상: PASS.

---

## Task 5: Phase 4 Runtime 정합성 회귀

**파일:**
- 수정: `tests/test_phase4_detection_core.py`
- 검증: `edge/features/collect_feature_logs.py`
- 검증: `edge/detection/mqtt_adapters.py`

- [ ] **5.1 Legacy UTC 공백 형식과 신규 `Z` 형식 혼합 Source 테스트 추가**

```python
def test_mqtt_feature_producer_accepts_legacy_utc_and_canonical_z_rows(
    SessionLocal,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01")
        _insert_mqtt_log(db, "esp32_01", "2026-07-23 10:00:01", payload_size=100)
        _insert_mqtt_log(db, "esp32_01", "2026-07-23T10:00:06Z", payload_size=200)
        db.commit()

    with SessionLocal() as db:
        with db.begin():
            result = produce_mqtt_features_until(
                db,
                producer_cutoff=datetime(
                    2026, 7, 23, 10, 0, 10, tzinfo=timezone.utc
                ),
            )

        assert result.selected_count == 2
        row = db.execute(
            text(
                """
                SELECT publish_count, avg_message_interval, min_message_interval
                FROM feature_logs
                WHERE device_id = 'esp32_01'
                """
            )
        ).mappings().one()
        assert row["publish_count"] == 2
        assert row["avg_message_interval"] == 5.0
        assert row["min_message_interval"] == 5.0
```

- [ ] **5.2 회귀 테스트 실행**

```bash
python -m pytest \
  tests/test_phase4_detection_core.py \
  tests/test_mqtt_feature_builder_runtime.py \
  -q
```

예상: PASS. 실패하면 Subscriber 변경이 아니라 기존 Runtime의 Timestamp 해석 경계를 분석한 뒤 최소 수정한다.

---

## Task 6: 문서 정합성

**파일:**
- 수정: `docs/db-schema.md`
- 수정: `docs/phase4-cutover-runbook.md`
- 검증: `docs/phase4-mqtt-utc-contract.md`

- [ ] **6.1 DB Schema 문서 보완**

`mqtt_logs.received_at`에 다음을 명시한다.

- Subscriber 신규 Row: UTC 정수 초 `YYYY-MM-DDTHH:MM:SSZ`
- 기존 DB에는 SQLite `CURRENT_TIMESTAMP` 또는 Legacy 공백 형식이 남을 수 있음
- Phase 4 비교는 `unixepoch()` 기준

`devices.last_seen_at`에는 Subscriber가 `mqtt_logs.received_at`과 같은 UTC 문자열을 저장한다고 명시한다.

- [ ] **6.2 Cutover Runbook 보완**

실제 Cutover 전 확인 항목에 다음을 추가한다.

```sql
SELECT id, received_at
FROM mqtt_logs
WHERE unixepoch(received_at) IS NULL
   OR unixepoch(received_at) >= unixepoch(:cutover_at_plus_10_seconds)
ORDER BY id;
```

결과가 있으면 실제 Cutover를 중단하고 Timestamp 출처를 확인하도록 명시한다.

- [ ] **6.3 Legacy Collector 운영 경계 명시**

UTC Subscriber 코드 반영 후에도 실제 Phase 4 Cutover 전까지는 다음을 유지한다.

- Legacy Feature Collector 비활성
- 신규 `mqtt-feature-builder.service` 비활성
- Subscriber 수동 검증은 제한 시간으로만 수행
- 실제 Cutover에서 Checkpoint 초기화 후 Phase 4 Producer 시작

---

## Task 7: 최종 검증

- [ ] **7.1 관련 테스트 전체 실행**

```bash
python -m pytest \
  tests/test_mqtt_feature_pipeline.py \
  tests/test_mqtt_log_query_service.py \
  tests/test_phase4_cutover_repository.py \
  tests/test_phase4_detection_core.py \
  tests/test_mqtt_feature_builder_runtime.py \
  -q
```

- [ ] **7.2 전체 Python 회귀 테스트 실행**

```bash
python -m pytest -q
```

- [ ] **7.3 변경 파일 점검**

```bash
git diff --check
git status --short
git diff --stat develop...HEAD
```

- [ ] **7.4 실제 운영 단계 전 보류 확인**

다음 작업은 이 코드 PR 병합 후 별도 승인으로 수행한다.

1. Pi 코드 반영
2. 운영 DB Backup API Snapshot과 SHA256
3. 검증된 수동 Subscriber Smoke Row만 UTC로 보정
4. `devices.last_seen_at`을 `ORDER BY unixepoch(received_at) DESC, id DESC LIMIT 1` 기준으로 재계산
5. 독립 DB Smoke Test 재실행
6. MQTT Subscriber systemd Unit 별도 구현
7. 실제 Phase 4 Cutover

## 완료 판정

- Subscriber 신규 Row가 Host Timezone과 무관하게 UTC `Z` 형식으로 저장된다.
- Naive `datetime`은 저장 전에 거부된다.
- `mqtt_logs.received_at`과 `devices.last_seen_at`이 일치한다.
- Cutover가 비정상 미래·파싱 불가능 MQTT Row를 DB 변경 전에 차단한다.
- Phase 4 Producer와 MQTT Message Rule이 신규 `Z` Row를 기존과 동일하게 처리한다.
- API가 Legacy 공백 형식과 신규 `Z` 형식을 실제 시각순으로 반환한다.
- React Dashboard는 기존 KST 표시와 최근 통신 계산을 유지한다.
- 전체 Python 테스트가 통과한다.
- 운영 DB와 실제 Cutover는 별도 승인 전까지 변경되지 않는다.
