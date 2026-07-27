# Packet Isolation Forest 가이드

본 문서는 Packet IF Core, Dataset Export, Phase 4 Detector Stage의 사용 방법과
운영 계약을 설명합니다.

## 현재 범위

포함 범위:

- 원본 Packet Feature 검증 및 10초 기준 정규화
- Session 단위 Train·Validation·Test 분리 검증
- Isolation Forest 학습
- 정상 Validation Session 기반 Threshold 결정
- Model Artifact·Metadata 생성
- Artifact 무결성 검증 및 Offline 추론
- 공통 Capture Policy 기반 DB Dataset Export
- `run_until(db, cycle_range_start, cycle_cutoff)` Packet IF Detector Stage
- `AI_PACKET_ANOMALY` Event와 `packet_if+packet_feature_logs` Checkpoint의
  동일 Transaction 처리
- 수동 Smoke Test CLI

후속 통합 범위:

- 운영 Orchestrator Stage Registry 등록과 Required Barrier 연결
- 실제 정상 Packet Session 기반 최종 Model 학습·배포
- Raspberry Pi Packet Capture부터 Trust Score까지 E2E 검증

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

학습·Validation·Test·Offline 추론에는 Artifact에 기록된 Capture Policy의
최소 Duration을 만족하는 Row만 허용합니다. 기본 정책은 9.0초이며 0.01초
Epsilon을 동일하게 적용합니다. DB Export와 Runtime은 Status·Error·시작 지연까지
공통 `is_capture_eligible()` 함수로 함께 검증합니다.

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
segment_window_start
segment_window_end
segment_status
segment_error_code
start_delay_seconds
registered_device_id
registered_ip_address
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
`peer_ip`만 허용합니다. Feature와 부모 Segment의 Window가 정확히 같아야 하며,
CSV에 보존된 Status·Error·Delay·Duration을 공통 `is_capture_eligible()`로
다시 판정합니다. Window 시각은 소수점 없는 UTC
`YYYY-MM-DDTHH:MM:SSZ` 형식이어야 하고, `window_start`는 10초 경계에
정렬되며 `window_end`는 정확히 10초 후여야 합니다.

### DB Dataset Export

DB Exporter는 지정한 Capture Session만 조회하며 아래 조건을 모두 만족하는
Row만 변경 불가능한 새 CSV로 저장합니다.

- 부모 Capture Session이 `COMPLETED`
- Session의 모든 Segment가 연속 `PROCESSED/EMPTY` Prefix로 Feature 변환 완료
- Feature Window와 Segment Window가 정확히 일치
- `direction=INBOUND`
- `device_id`가 현재 `devices`에 등록됨
- `peer_ip`가 현재 `devices.ip_address`와 일치함
- 공통 `is_capture_eligible()` 판정 통과

부적격 Row는 CSV에 포함하지 않고 제외 이유별 개수를 결과에 기록합니다. 기존
CSV는 덮어쓰지 않으며 같은 Directory의 임시 파일을 `fsync()`한 뒤 원자적
hard-link로 게시하여 완성된 파일만 노출합니다. 동시 Export가 같은 경로를
선점해도 먼저 생성된 파일을 보존하고 후속 실행은 실패합니다.

Export Spec에는 Split·Label·Scenario, 공격 대상, 실제 Capture Filter와 Capture
실행 Source Commit SHA를 기록합니다.

```json
{
  "capture_filter": "tcp or udp",
  "source_commit_sha": "<Capture 실행 Source의 소문자 40자리 Commit SHA>",
  "sessions": [
    {
      "session_id": "11111111-1111-4111-8111-111111111111",
      "split": "train",
      "traffic_label": "normal",
      "scenario": "normal_stable"
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

```bash
python -m ai.export_packet_if_dataset \
  --output data/exports/packet_if_dataset-v1.csv \
  --manifest-output data/exports/packet_if_manifest-v1.json \
  --spec data/exports/packet_if_export_spec-v1.json
```

Exporter는 CSV와 Session Manifest를 함께 생성합니다. Manifest에는 전체 CSV
SHA256, Session별 데이터 SHA256, Capture Policy 전체 수치, Session 시간·Gap,
Interface·Filter·Commit SHA와 Device/IP 매핑을 기록합니다. 공격 Session은
`target_device_id`와 다른 기기의 혼합 트래픽을 제외합니다. 요청한 Session 중
적격 Row가 하나도 없거나 아직 Feature 변환이 끝나지 않은 Session이 있으면
Dataset을 게시하지 않고 실패합니다.

### Session Manifest

`split`과 `traffic_label`은 Row 무작위 분리가 아니라 Session 단위로 지정합니다.

```json
{
  "dataset_version": "packet-if-dataset-v1",
  "capture_policy_version": "packet-capture-policy-v1",
  "capture_policy": {
    "version": "packet-capture-policy-v1",
    "nominal_window_seconds": 10.0,
    "max_start_delay_seconds": 1.0,
    "minimum_duration_seconds": 9.0,
    "epsilon_seconds": 0.01,
    "minimum_coverage_ratio": 0.9
  },
  "dataset_sha256": "<전체 CSV의 소문자 SHA256>",
  "sessions": [
    {
      "session_id": "11111111-1111-4111-8111-111111111111",
      "split": "train",
      "traffic_label": "normal",
      "scenario": "normal_stable",
      "target_device_id": null,
      "status": "COMPLETED",
      "capture_interface": "eth0",
      "capture_filter": "tcp or udp",
      "source_commit_sha": "<소문자 40자리 Commit SHA>",
      "started_at": "2026-07-26T09:59:58Z",
      "first_window_start": "2026-07-26T10:00:00Z",
      "ended_at": "2026-07-26T10:10:00Z",
      "capture_gap_start": null,
      "capture_gap_end": null,
      "devices": [
        {
          "device_id": "esp32_01",
          "peer_ip": "192.168.0.4"
        }
      ],
      "data_sha256": "<해당 Session CSV Row의 소문자 SHA256>"
    }
  ]
}
```

위 블록은 Session 항목의 전체 구조를 보여주는 예시입니다. 실제 학습 Manifest는
Train·Validation·정상 Test·공격 Test Session을 모두 포함해야 하며, 모든
Session 항목에 같은 Provenance 필드를 기록합니다.

검증 규칙:

- Train과 Validation Session은 정상 데이터만 허용
- `normal_management_traffic`은 Rule Allowlist·오탐 평가용이므로 Train과
  Validation에서 제외
- Test에는 서로 다른 정상·공격 Session이 모두 필요
- 공격 Session은 `target_device_id`를 필수로 지정하고 해당 Device Row만 포함
- 정상 Session에는 `target_device_id`를 지정하지 않음
- 하나의 Session을 여러 Split에 배치하는 것 금지
- 모든 Manifest Session에 CSV Row가 한 개 이상 존재해야 함
- 모든 CSV Session이 Manifest에 선언되어야 함
- Session ID는 소문자 Canonical UUID4 형식 사용
- 전체 CSV SHA256이 `dataset_sha256`과 일치해야 함
- 각 Session Row SHA256이 `data_sha256`과 일치해야 함
- Manifest Capture Policy 전체 수치가 학습 환경과 정확히 일치해야 함

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
최종 배포 모델은 모든 Packet IF 변경을 커밋한 clean worktree에서만 학습하고,
`SOURCE_COMMIT_SHA`에는 그 학습 코드를 포함한 Commit을 사용합니다.

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
Training Report 중 하나라도 있으면 학습을 시작하지 않으며, Directory 이름은
`model_version`과 정확히 같아야 합니다. 재학습할 때는 `packet-if-v2`처럼 새
Version과 Directory를 함께 사용합니다. 학습 중에는 Version별 Build Lock을
획득하고 임시 Directory에서 Bundle 전체를 완성한 뒤 원자적으로 게시합니다.
실패한 학습은 최종 Directory를 남기지 않습니다. 최종 배포용 Artifact는 기록된
Git SHA가 정확한 구현을 식별할 수 있도록 변경사항을 Commit한 깨끗한 Source
상태에서 학습해야 합니다.

## Artifact Bundle

```text
ai/models/packet_if/
└── packet-if-v1/
    ├── model.joblib
    ├── metadata.json
    └── training_report.json
```

`.gitkeep`을 제외한 위 파일들은 Git에서 제외됩니다. 학습 명령이 출력한
`bundle_sha256`은 Bundle 내부에 넣지 않고 배포 설정에 별도로 고정합니다.

Model을 역직렬화하기 전에 아래 항목을 검증합니다.

- 운영 설정에 고정된 외부 Bundle SHA256
- Artifact Schema와 Model Type
- Feature·Transform·Dataset Version의 정확한 일치
- Model Version과 Capture Policy Version·수치의 정확한 일치
- 명목 10초 Window, 최소 Coverage와 Count·Bytes 정규화식
- 정확한 Feature 순서
- Score 방향과 엄격한 Threshold 연산자
- 유한한 Threshold와 Validation Percentile
- Dataset·Manifest·Model·Training Report SHA256
- 학습 Parameter, Session 목록, Row 수, 정확한 Runtime Library Version,
  Git SHA, UTC 생성 시각
- 역직렬화한 Model Type, Feature 개수와 실제 Model Parameter

Loader는 Model·Metadata·Training Report의 실제 바이트로 외부 Bundle SHA를
먼저 확인하고, 검증한 같은 Model 바이트를 `joblib`에 전달합니다. `joblib`
Artifact는 Load 과정에서 코드를 실행할 수 있으므로 Pi 배포 경로와 외부 SHA
설정은 배포 관리자만 변경할 수 있게 하고 Artifact Directory는 읽기 전용으로
운영합니다.

Artifact에는 Capture Policy의 Version, 최대 시작 지연, 최소 Duration, Epsilon,
최소 Coverage와 Count·Bytes 정규화식을 함께 기록합니다. Offline 추론은 이
수치로 최소 Coverage를 검증하고, Runtime은 Event 생성 또는 Checkpoint 전진 전에
Artifact의 전체 Capture Policy가 현재 설정과 일치하는지 확인합니다.

## Offline 추론

Offline 추론도 임의 Feature CSV를 받지 않고 Exporter가 생성한 Dataset CSV와
Session Manifest를 함께 검증합니다.

```bash
python -m ai.predict_packet_isolation_forest \
  --artifact-dir ai/models/packet_if/packet-if-v1 \
  --csv data/exports/packet_if_dataset-v1.csv \
  --manifest data/exports/packet_if_manifest-v1.json \
  --expected-model-version packet-if-v1 \
  --expected-bundle-sha256 "$PACKET_IF_EXPECTED_BUNDLE_SHA256"
```

명령 실행 결과로 Row 수, 저장된 Threshold, Anomaly Score 범위를 출력합니다.
현재 Offline 추론은 Detection Event를 생성하거나 Checkpoint를 전진시키지 않습니다.

## Phase 4 Runtime

### 환경변수

```dotenv
PACKET_IF_ARTIFACT_DIR=ai/models/packet_if/packet-if-v1
PACKET_IF_EXPECTED_MODEL_VERSION=packet-if-v1
PACKET_IF_EXPECTED_BUNDLE_SHA256=<학습 CLI가 출력한 SHA256>
```

Stage 생성 시 Artifact의 SHA256·Metadata를 검증하고 아래 Version이 모두
일치해야만 DB 처리를 시작합니다.

- 외부 `PACKET_IF_EXPECTED_BUNDLE_SHA256`과 실제 Bundle SHA256
- Metadata `model_version`과 `PACKET_IF_EXPECTED_MODEL_VERSION`
- Metadata의 Capture Policy Version·수치와 현재 Capture Policy 전체
- 학습·Runtime Python `major.minor`와 고정된 ML Library Version

설정이 없거나 SHA·Version이 다르면 Model 역직렬화, Event 생성과 Checkpoint
전진 없이 실패합니다.
FastAPI는 Packet IF Stage를 생성하지 않으므로 최종 모델이 없는 개발 환경에서도
독립적으로 실행할 수 있습니다.

### 입력 선택과 적격성

`PacketIsolationForestStage`는 Orchestrator가 전달한
`[cycle_range_start, cycle_cutoff)` 범위의 `packet_feature_logs`를 Window
기준으로 선택합니다. 한 Cycle에서 서로 다른 Capture Session의 Row가 함께
조회되면 Session Gap 경계 위반으로 간주해 Event와 Checkpoint를 저장하지 않고
실패합니다. `last_processed_id`만으로 Source를 필터링하지 않으므로 낮은 ID의
미래 Window도 건너뛰지 않습니다.

아래 Row는 추론과 Event 생성에서는 제외하지만 처리된 Source로 소비하여
Checkpoint 진행을 막지 않습니다.

- `OUTBOUND`
- 미등록 Device 또는 현재 Device IP와 `peer_ip`가 다른 Row
- 공통 Capture Policy에서 부적격으로 판정된 Segment

격리 상태의 등록 Device는 Packet Feature 수집·탐지 대상에서 제외하지 않습니다.

### Event와 Checkpoint

이상 판정은 Core와 동일하게 아래 엄격한 비교를 사용합니다.

```text
anomaly_score = -raw_decision_score
is_anomaly = anomaly_score > threshold
```

이상 Row는 다음 계약으로 저장합니다.

```text
detector_name=packet_if
source_table=packet_feature_logs
detector_type=AI
event_type=AI_PACKET_ANOMALY
incident_family=AI_ONLY
score_delta=-15
packet_feature_log_id=<source id>
subject_ip=<peer_ip>
```

Evidence에는 원본·정규화 Feature, Session·Segment 식별자, Coverage, Model
Version·Bundle SHA256, Raw·Anomaly Score, Threshold, Feature·Transform
Version, Capture Policy 값과 Cycle 범위를 저장합니다. Payload나 인증정보는
저장하지 않습니다.

Event와 `packet_if+packet_feature_logs` Checkpoint는 호출자가 소유한 동일
Transaction에 참여하며 Stage는 `commit()`이나 `rollback()`을 직접 호출하지
않습니다. 재실행 시 DB `dedupe_key` Unique 제약으로 Event 중복 생성을 막고,
Checkpoint는 역행하지 않습니다. 입력 Row가 없는 완료 범위도 검증된 Cutoff까지
`last_completed_window_end`를 전진시킬 수 있습니다.

### 수동 Smoke Test

운영 Runtime은 Orchestrator를 통해 Stage를 호출해야 합니다. 아래 명령은 배포
전 Smoke Test와 복구 확인 용도로만 사용합니다.

```bash
python -m edge.detection.run_packet_ai_detector \
  --session-id 11111111-1111-4111-8111-111111111111 \
  --range-start 2026-07-26T10:00:00Z \
  --cutoff 2026-07-26T10:00:10Z
```

기본 실행은 결과를 출력한 뒤 Transaction을 Rollback하는 Dry-run입니다. 실제로
Event와 Checkpoint를 저장하려면 `--commit`을 명시해야 합니다. Commit 실행은
단일 프로세스 Lock을 획득하고, 지정 Session의 연속 `PROCESSED/EMPTY` Packet
Feature 준비 구간과 현재 Checkpoint 연속성을 확인합니다. 준비 구간보다 미래인
Cutoff, Checkpoint를 건너뛰는 범위, 이전 Checkpoint와 새 Session 시작 사이의
Capture Gap을 포함하는 범위는 거부합니다.

```bash
python -m edge.detection.run_packet_ai_detector \
  --session-id 11111111-1111-4111-8111-111111111111 \
  --range-start 2026-07-26T10:00:00Z \
  --cutoff 2026-07-26T10:00:10Z \
  --commit
```

CLI가 Transaction을 소유하므로 추론·Event·Checkpoint 처리 중 오류가 발생하면
해당 실행의 변경사항이 함께 Rollback되고 프로세스는 비정상 종료합니다. 운영
Orchestrator도 같은 Detection Cycle Lock 경로를 사용해야 합니다.

## 검증

```bash
python -m pytest -q \
  tests/test_packet_if_contract.py \
  tests/test_packet_if_dataset.py \
  tests/test_train_packet_isolation_forest.py \
  tests/test_predict_packet_isolation_forest.py \
  tests/test_export_packet_if_dataset.py \
  tests/test_packet_ai_detector.py \
  tests/test_run_packet_ai_detector.py

python -m pytest -q
python -m compileall -q ai edge backend tests
python -m pip check
python -m ai.export_packet_if_dataset --help
python -m edge.detection.run_packet_ai_detector --help
git diff --check
git status --short
```

## 운영 통합 전제조건

아래 조건을 모두 충족하기 전에는 Packet IF를 운영 Runtime으로 활성화하지
않습니다.

- 신규 정상 Packet Capture Session
- 최종 Model·Threshold·Metadata 생성
- Artifact Directory와 기대 Model Version 운영 환경 설정
- Orchestrator Stage Registry 및 Required Barrier 연결
- Raspberry Pi E2E 및 전체 회귀 검증
