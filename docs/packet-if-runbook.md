# Packet Isolation Forest Core 가이드

본 문서는 Phase 4 Runtime과 분리해 먼저 병합하는 Packet IF Core의 사용 방법과
계약을 설명합니다.

## 현재 범위

포함 범위:

- 원본 Packet Feature 검증 및 10초 기준 정규화
- Session 단위 Train·Validation·Test 분리 검증
- Isolation Forest 학습
- 정상 Validation Session 기반 Threshold 결정
- Model Artifact·Metadata 생성
- Artifact 무결성 검증 및 Offline 추론

후속 Packet IF Runtime PR에서 구현할 범위:

- DB Export 단계의 Capture 적격성 필터
- `run_until(db, cycle_cutoff)` Detector Stage
- Detection Event·Checkpoint Transaction
- `AI_PACKET_ANOMALY` Trust Score 연동
- 최종 Raspberry Pi 모델 배포 및 E2E 검증

현재 모듈은 운영 DB를 조회하거나 변경하지 않습니다.

## Feature 계약

모델에 전달하는 Feature 순서는 아래와 같이 고정합니다.

```text
packet_count_10s
total_bytes_10s
avg_packet_size
max_packet_size
mean_inter_arrival_time
distinct_dest_port_count
```

원본 입력 Row에는 `captured_duration_seconds`도 반드시 포함되어야 합니다.
Count와 Byte Feature는 아래 식으로 10초 기준으로 환산합니다.

```text
packet_count_10s = packet_count * 10 / captured_duration_seconds
total_bytes_10s = total_bytes * 10 / captured_duration_seconds
```

필수값 누락, NULL, 비수치, NaN, Infinity, 음수, 0 이하 또는 10초 초과
Duration은 거부합니다. `packet_count`, `total_bytes`, `max_packet_size`,
`distinct_dest_port_count`는 0 이상의 정수만 허용합니다. 변환 함수는 입력
객체를 변경하지 않습니다.

## Dataset 계약

학습에는 변경되지 않는 CSV 1개와 JSON Session Manifest 1개를 사용합니다.
CSV에는 아래 컬럼이 필요합니다.

```text
packet_feature_log_id
session_id
device_id
peer_ip
direction
window_start
window_end
packet_count
total_bytes
avg_packet_size
max_packet_size
mean_inter_arrival_time
distinct_dest_port_count
captured_duration_seconds
```

`captured_duration_seconds`는 `packet_capture_segments`에 저장되므로, 향후 DB
Exporter는 아래 경로로 JOIN해야 합니다.

```text
packet_feature_logs.capture_segment_id
  -> packet_capture_segments.id
  -> packet_capture_segments.captured_duration_seconds
```

`session_id`는 아래와 같이 한 단계 더 JOIN해야 합니다.

```text
packet_feature_logs.capture_segment_id
  -> packet_capture_segments.capture_session_id
  -> packet_capture_sessions.session_id
```

Core Dataset Loader는 등록 기기에 매핑된 `INBOUND` Row와 유효한 IPv4
`peer_ip`만 허용합니다. Window 시각은 소수점 없는 UTC
`YYYY-MM-DDTHH:MM:SSZ` 형식이어야 하고, `window_start`는 10초 경계에
정렬되며 `window_end`는 정확히 10초 후여야 합니다. Capture
Status·Error·Delay·Duration 적격성은 향후 DB Exporter에서 공통
`is_capture_eligible()` 정책으로 판정해야 합니다.

### Session Manifest

`split`과 `traffic_label`은 Row 무작위 분리가 아니라 Session 단위로 지정합니다.

```json
{
  "dataset_version": "packet-if-dataset-v1",
  "capture_policy_version": "packet-capture-policy-v1",
  "dataset_sha256": "<전체 CSV의 소문자 SHA256>",
  "sessions": [
    {
      "session_id": "11111111-1111-4111-8111-111111111111",
      "split": "train",
      "traffic_label": "normal",
      "scenario": "normal_stable"
    },
    {
      "session_id": "22222222-2222-4222-8222-222222222222",
      "split": "validation",
      "traffic_label": "normal",
      "scenario": "normal_jitter"
    },
    {
      "session_id": "33333333-3333-4333-8333-333333333333",
      "split": "test",
      "traffic_label": "normal",
      "scenario": "normal_test"
    },
    {
      "session_id": "44444444-4444-4444-8444-444444444444",
      "split": "test",
      "traffic_label": "attack",
      "scenario": "packet_flood",
      "target_device_id": "esp32_02"
    }
  ]
}
```

검증 규칙:

- Train과 Validation Session은 정상 데이터만 허용
- Test에는 서로 다른 정상·공격 Session이 모두 필요
- 공격 Session은 `target_device_id`를 필수로 지정하고 해당 Device Row만 포함
- 정상 Session에는 `target_device_id`를 지정하지 않음
- 하나의 Session을 여러 Split에 배치하는 것 금지
- 모든 Manifest Session에 CSV Row가 한 개 이상 존재해야 함
- 모든 CSV Session이 Manifest에 선언되어야 함
- Session ID는 소문자 Canonical UUID4 형식 사용
- 전체 CSV SHA256이 `dataset_sha256`과 일치해야 함

## 학습

Repository Root에서 아래 명령을 실행합니다.

```bash
python -m ai.train_packet_isolation_forest \
  --dataset data/exports/packet_if_dataset.csv \
  --manifest data/exports/packet_if_manifest.json \
  --artifact-dir ai/models/packet_if/packet-if-v1 \
  --threshold-percentile 99.0 \
  --git-commit-sha "$SOURCE_COMMIT_SHA"
```

`SOURCE_COMMIT_SHA`에는 배포 Source의 소문자 40자리 Commit SHA를 지정해야
합니다. `--git-commit-sha`를 생략하면 `git rev-parse HEAD`를 실행하므로,
Git이 없는 환경에서는 반드시 명시해야 합니다.

기본 학습값:

```text
n_estimators=100
contamination=auto
random_state=42
n_jobs=1
scaler=None
```

Model은 Train Session으로만 학습합니다. Threshold는 정상 Validation Session의
Anomaly Score에서 지정한 Percentile로 계산합니다. Test 데이터는 결과 평가에만
사용하며 Threshold 결정에 영향을 주지 않습니다.

```text
raw_decision_score = model.decision_function(X)
anomaly_score = -raw_decision_score
is_anomaly = anomaly_score > threshold
```

Anomaly Score가 Threshold와 같으면 정상으로 판정합니다.

기존 Artifact Bundle은 덮어쓰지 않습니다. 같은 Directory에 Model, Metadata,
Training Report 중 하나라도 있으면 학습을 시작하지 않으므로 재학습할 때는
`packet-if-v2`처럼 새로운 Version Directory를 사용합니다. 최종 배포용
Artifact는 기록된 Git SHA가 정확한 구현을 식별할 수 있도록 변경사항을 Commit한
깨끗한 Source 상태에서 학습해야 합니다.

## Artifact Bundle

```text
ai/models/packet_if/
└── packet-if-v1/
    ├── model.joblib
    ├── metadata.json
    └── training_report.json
```

`.gitkeep`을 제외한 위 파일들은 Git에서 제외됩니다. `metadata.json`은 마지막에
기록하며 Artifact Bundle의 생성 완료 표식으로 사용합니다.

Model을 역직렬화하기 전에 아래 항목을 검증합니다.

- Artifact Schema와 Model Type
- Feature·Transform·Dataset Version의 정확한 일치
- Model·Capture Policy Version Metadata 존재 여부
- 정확한 Feature 순서
- Score 방향과 엄격한 Threshold 연산자
- 유한한 Threshold와 Validation Percentile
- Dataset·Manifest·Model SHA256
- 학습 Parameter, Session 목록, Row 수, Library Version, Git SHA, UTC 생성 시각
- 역직렬화한 Model Type과 Feature 개수

Model SHA는 파일 무결성을 확인하지만 Artifact의 출처까지 보장하지는 않습니다.
`joblib` Artifact는 Load 과정에서 코드를 실행할 수 있으므로, 프로젝트에서
생성하고 신뢰할 수 있는 경로로 전달한 Artifact만 사용해야 합니다.

Core Loader만으로는 현재 Runtime의 Capture Policy를 결정할 수 없습니다. 향후
Packet IF Runner는 Event 생성 또는 Checkpoint 전진 전에 Artifact의
`model_version`·`capture_policy_version`을 설정된 기대 Version과 비교해야 합니다.

## Offline 추론

입력 CSV에는 Feature 계약에 정의된 원본 Feature 컬럼을 사용합니다.

```bash
python -m ai.predict_packet_isolation_forest \
  --artifact-dir ai/models/packet_if/packet-if-v1 \
  --csv data/exports/packet_if_inference.csv
```

명령 실행 결과로 Row 수, 저장된 Threshold, Anomaly Score 범위를 출력합니다.
현재 Offline 추론은 Detection Event를 생성하거나 Checkpoint를 전진시키지 않습니다.

## 검증

```bash
python -m pytest -q \
  tests/test_packet_if_contract.py \
  tests/test_packet_if_dataset.py \
  tests/test_train_packet_isolation_forest.py \
  tests/test_predict_packet_isolation_forest.py

python -m pytest -q
python -m compileall -q ai edge backend tests
git diff --check
git status --short
```

## 운영 통합 전제조건

이 Core PR은 학습·Offline 추론 계약과 테스트가 통과하면 독립적으로 병합할 수
있습니다. 다만 아래 조건을 모두 충족하기 전에는 Packet IF를 운영 Runtime으로
활성화하지 않습니다.

- 공통 Capture 적격성 정책
- Runtime Model·Capture Policy Version 호환성 검사
- Detector `run_until()`·Checkpoint 계약
- Event Writer의 `packet_feature_log_id` 지원
- `AI_PACKET_ANOMALY`·`AI_ONLY`·`-15` Trust Score 정책
- 신규 정상 Packet Capture Session
- 최종 Model·Threshold·Metadata 생성
- Raspberry Pi E2E 및 전체 회귀 검증
