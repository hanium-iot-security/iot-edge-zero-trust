# Phase 9 그래프용 읽기 API

이 변경은 기존 MQTT·Packet Feature 조회에 페이지 기준 ID를 추가하고, Feature가 없는
Packet 구간의 Capture 기록을 별도로 제공한다. 그래프·집계·보간·자동 수집·학습을 수행하지 않는다.
Frontend는 소유 담당자의 후속 연결 범위다.

## Feature 페이지 기준

`GET /api/feature-logs`, `GET /api/packet-feature-logs`는 기존 `items`, `total`에
`snapshot_max_id`를 추가한다. 기존 필터·정렬(`window_start DESC,id DESC`)·limit/offset은 유지한다.

```json
{"items": [], "total": 0, "snapshot_max_id": 0}
```

첫 요청에서 `snapshot_max_id`를 생략하면 해당 Feature 테이블 전체의 현재 최대 ID를 고정한다.
이후 페이지는 같은 필터와 반환받은 `snapshot_max_id`를 전달한다. `total`과 `items` 모두
`id <= snapshot_max_id`를 적용하므로 이후 삽입된 행 때문에 offset이 밀리지 않는다.
빈 테이블의 기준은 `0`이며 이후 행이 생겨도 이 기준으로 조회한 결과는 비어 있다.

```text
/api/feature-logs?device_id=esp32_01&limit=100
/api/feature-logs?device_id=esp32_01&limit=100&offset=100&snapshot_max_id=1234
```

입력은 0부터 SQLite 정수 최댓값(9223372036854775807)까지다. 음수·범위 초과·잘못된 값 또는
현재 **전역** 최대 ID보다 큰 값은 422다. 기기·기간 필터 결과의 최대 ID와 비교하지 않는다.
서로 다른 테이블의 기준 ID를 공유하지 않는다. 새 행을 포함하려면 기준을 생략하고 첫 페이지부터
다시 조회한다.

한 HTTP 응답의 최대 ID·전체 건수·목록은 실제 SQLite 읽기 트랜잭션 하나에서 읽는다.
조회 서비스가 시작한 트랜잭션은 결과를 메모리에 담은 뒤 반환 전에 종료한다. 응답 직렬화·전송을
기다리는 동안 DB 읽기 트랜잭션을 유지하지 않으며 기존 호출자 트랜잭션의 종료는 호출자에게 맡긴다.
여러 HTTP 요청 사이에는 삽입 ID 상한만 보존한다. 기존 행 수정·삭제, Packet Segment의
READY→PROCESSED 변경을 동결하거나 과거 데이터를 복원하는 토큰이 아니다. 기준 ID보다 큰
기록이 모두 삭제된 경우에도 422가 가능하므로 목록을 새로 조회한다.

### 유지되는 기간 조건

| API | from | to |
| --- | --- | --- |
| MQTT Feature | `window_start >= from` | `window_end <= to` |
| Packet Feature | `window_start >= from` | `window_start <= to` |

MQTT는 완전히 포함된 Window를 반환한다. Packet은 기존 **Window 시작 시각** 기준을 유지하며,
`to`와 시작 시각이 같은 Packet Window도 포함한다. Packet의 기존 정수 초 UTC 변환도 유지한다.
두 API는 timezone이 필요하고 UTC 변환이 표현 범위를 벗어나면 422를 반환한다.

## Capture Window 관측

`GET /api/packet-capture-windows?session_id=<UUIDv4>&from=<시각>&to=<시각>`

- 세 인자는 모두 필수다. from/to는 timezone을 포함하고 UTC 10초 경계에 맞아야 한다.
- `[from,to)` 범위의 완전히 포함된 10초 Window만 반환한다. 같은 경계는 빈 결과다.
- 한 요청은 최대 1시간·360개 Window다. 이 상한은 조회량 제한이며 작업 실행 제한시간이 아니다.
- 정렬은 Window 시작 시각 오름차순이다. 기기·peer·direction 필터와 offset은 제공하지 않는다.
- 없는 Session은 404, 잘못된 범위는 422다. DB/스키마 또는 중복·비정렬 Capture 기록 오류는
  503 `detail.code=PACKET_CAPTURE_DATA_UNAVAILABLE`이다.

응답은 `session_id`, `session_status`, `first_window_start`, `ended_at`, `observed_at`,
`from`, `to`, `items`, `total`을 포함한다. Session과 Segment·Feature 건수는 같은 읽기 snapshot에서
관측한다. Session 메타데이터는 저장값이며 `observed_at`은 API 관측 시각이다.

| observation | segment_status | 의미 |
| --- | --- | --- |
| PROCESSED | PROCESSED | 추출 완료 기록 |
| EMPTY | EMPTY | 저장된 빈 추출 기록 |
| FAILED | FAILED | 저장된 실패 기록; `segment_error_code`로 확인 |
| PENDING | READY | Capture Segment는 있고 추출 완료 전 |
| MISSING | null | 해당 Session·Window의 Segment DB 기록 없음 |

각 항목은 `window_start/end`, `segment_id`, `segment_status`, `observation`,
`segment_error_code`, `packet_count`, `feature_row_count`, `start_delay_seconds`,
`captured_duration_seconds`, `capture_eligible`, `capture_exclusion_reason`을 포함한다.
파일 경로·파일명·원본 error_message는 노출하지 않는다.

`MISSING`은 실제 Capture 손실 판정이 아니다. Session 시작 전·종료 후·미래 구간도 DB 행이
없으면 MISSING이다. Session 경계와 관측 시각을 함께 봐야 한다. 누락 항목의 수치와 Capture
적격 여부는 `null`이며 0/정상으로 채우지 않는다. `feature_row_count`는 해당 Segment의
모든 기기·방향에 대한 개수다. 특정 기기의 Feature가 없는 것을 EMPTY로 변환하지 않는다.
`capture_eligible`은 기존 공통 Capture Policy에 따른 timing/status 판단이며 모델 실행이나
정상 트래픽 판정이 아니다. 이 조회는 Segment 상태·Feature·체크포인트를 변경하지 않는다.

## 검증 범위

`backend/tests/test_graph_read_api.py`는 실제 FastAPI와 읽기 전용 임시 SQLite에서
페이지 사이 삽입·동일 시각 정렬·0/미래 기준·조회 중 동시 수정의 snapshot 일관성,
Feature가 없는 Capture 상태, 범위·timezone·오류 응답을 검증한다. 기존 Feature·Packet API 및
Broker 저장 회귀를 함께 실행한다. Pi 성능·실제 수집 상태와 Frontend 표시는 별도 확인 대상이다.
