# Phase 5 Verified Collection Import 설계

## 1. 목적

Phase 5에서 이미 수집·QC가 완료된 ESP32 Packet Capture Session을 다시 수집하지 않고, 보존된 DB Snapshot·PCAP·Packet Feature·QC·Split·Firmware·Commit 증적을 읽기 전용으로 검증해 `packet-if-dataset-v2`의 공식 Provenance로 이관한다.

이 설계는 자동 Scenario Runner가 생성한 적 없는 과거 Run을 실행된 것처럼 꾸미지 않는다. 수동 실기기 수집 사실을 `phase5-verified-collection-v1` Manifest로 명시하고, 기존 `phase5-run-manifest-v1`의 `session_manifest_ref`를 통해 Dataset v2 계약에 연결한다.

핵심 목표는 다음과 같다.

- 정상 16개 Session과 공격 Session 53을 재수집하지 않는다.
- 과거 수집 사실과 사후 검증 사실을 분리해 기록한다.
- Dataset v2의 기존 Split·Run Manifest·SHA256·Capture Policy 계약을 유지한다.
- 세션별 실제 수집 Commit과 Firmware·Payload 계약을 정확히 보존한다.
- 운영 DB·PCAP·Trust·Firewall 상태를 변경하지 않는다.
- 부분 생성 없이 하나의 불변 Dataset 패키지로 게시한다.

## 2. 확정된 프로젝트 기준

### 2.1 Phase 5 장비 구성

- Raspberry Pi #1: Gateway/Broker, Packet Capture, Packet Feature, Packet Rule, Packet IF, Trust, Firewall
- ESP32 #2: 등록 IoT 공격 송신 기기
- 관리 노트북: Firmware 업로드, Serial 명령, 로그·증적 관리, GitHub·Dataset·모델 작업
- Raspberry Pi #2: Phase 5에서 사용하지 않는다. Python 공격 자동화와 Scenario Runner 반복 평가는 Phase 6 선택 고도화로 이관한다.

### 2.2 공식 Dataset 재사용 대상

- `esp32_01` 정상 Train 8 Sessions
- `esp32_01` 정상 Validation 4 Sessions
- `esp32_01` 정상 Test 4 Sessions
- `esp32_02` 공격 Offline Test Session 53
  - Session ID: `23d5dc5b-1e73-44e4-80ed-1d0c12bda7f9`
  - Source IP: `192.168.0.5`
  - Scenario ID: `packet_rate_flood`
  - Firmware: `phase5-packet-rate-sender-v2`

Dataset 외부에 보존한다.

- `esp32_02` 정상 Holdout 2 Sessions
- Session 51: 2-Burst Packet Rule·Event Commit 통합 검증
- Session 52: 10초 Tumbling Window 경계 False Negative 분석
- Artifact 배포 후 새로 수집할 공식 E2E 공격 Holdout

### 2.3 현재 구현과의 호환 기준

현재 Dataset v2는 다음을 강제한다.

- 모든 Session에 검증 가능한 `run_manifest_ref`가 있어야 한다.
- Train·Validation은 정상 Session만 허용한다.
- Test에는 정상과 공격 Session이 각각 있어야 한다.
- 정상 Session의 Dataset Annotation에는 `target_device_id`와 `target_source_ip`를 지정하지 않는다.
- 공격 Session에는 `target_device_id`와 `target_source_ip`를 지정한다.
- Run Manifest의 Run·Session·Scenario·Device·IP와 Dataset Manifest가 일치해야 한다.
- Run Manifest Canonical SHA256과 `.sha256` Sidecar를 검증한다.
- `run_manifest_ref.relative_path`는 Dataset Manifest Directory 아래의 상대 경로여야 한다.
- Dataset 전체에서 `normal_policy_version`은 하나만 사용한다.
- `collection_slot_id`와 Run ID는 Dataset 안에서 중복될 수 없다.
- 같은 `source_capture_group_id`는 여러 Split에 걸칠 수 없다.
- 등록 기기의 Capture Policy 적격 `INBOUND` Row만 Dataset에 포함한다.

현재 Run Manifest 계약은 `session_manifest_ref`의 필드 형식만 검증하고 참조 파일의 내용과 SHA256을 자동으로 검증하지 않는다. 따라서 Verified Collection을 공식 연결하려면 Dataset v2 검증 경로에 Collection Manifest 연쇄 검증을 추가해야 한다.

## 3. 문제 정의

공식 정상 Session과 Session 53은 Dataset v2 계약 병합 전에 수집되어 Session-bound Run Manifest가 없다. 현재 Scenario Runner는 Python 공격 모듈을 직접 실행하는 구조이며 ESP32 Serial 공격을 직접 실행하거나 대기하지 않는다. 따라서 과거 ESP32 Session을 Scenario Runner 실행 결과로 사후 생성하면 실제 Provenance와 불일치한다.

또한 정상 Session과 Session 53은 서로 다른 수집 Commit과 Firmware를 사용했다. 현재 Export Spec의 최상위 `source_commit_sha` 하나만 사용하면 모든 Session에 같은 Commit이 기록되어 일부 Session의 Capture Source가 부정확해진다.

Session 53의 Packet Rate Firmware에는 `FIRMWARE_VERSION`은 있지만 별도 `PAYLOAD_SCHEMA_VERSION` 로그가 없다. 실제 UDP Payload는 Source와 PCAP으로 검증할 수 있으나, 수집 당시 Firmware가 Payload Schema Version을 출력했다고 기록해서는 안 된다.

## 4. 선택한 구조

```text
보존된 DB Snapshot·PCAP·QC·Split·Source 증적
        ↓ 전체 Batch 읽기 전용 검증
phase5-verified-collection-v1
        ↓ session_manifest_ref + Canonical SHA256 검증
phase5-run-manifest-v1 (DATA_ONLY)
        ↓ run_manifest_ref + Canonical SHA256 검증
packet-if-dataset-v2 Export Spec
        ↓ 동일 DB Snapshot에서 읽기 전용 Export
packet-if-dataset-v2 CSV + Manifest
```

새 Importer는 Verified Collection Manifest, DATA_ONLY Run Manifest, Evidence 파일, Dataset v2 Export Spec을 생성한다. Dataset CSV Export와 모델 학습은 자동 실행하지 않는다.

## 5. 변경 범위

### 5.1 새 구성 요소

예상 파일은 다음과 같다. 실제 구현 계획에서 저장소 명명 규칙과 테스트 구조를 다시 확인한 뒤 확정한다.

```text
edge/phase5/verified_collection_contract.py
edge/phase5/import_verified_collection.py
tests/test_verified_collection_contract.py
tests/test_import_verified_collection.py
docs/phase5-verified-collection-import.md
```

### 5.2 기존 코드의 최소 확장

다음 기존 모듈은 Dataset v2의 현재 계약을 깨지 않는 하위 호환 확장만 수행한다.

```text
ai/export_packet_if_dataset.py
ai/packet_if_phase5_manifest.py
ai/packet_if_dataset.py
```

필요한 확장은 다음 두 가지다.

1. Session별 `source_commit_sha` 지원
   - Session Annotation의 값이 있으면 해당 값을 Dataset Manifest에 기록한다.
   - 값이 없으면 기존 최상위 `source_commit_sha`를 fallback으로 사용한다.
   - 기존 Export Spec과 테스트 Fixture는 계속 동작해야 한다.

2. Verified Collection Manifest 연쇄 검증
   - Run Manifest에 `session_manifest_ref`가 있으면 참조 파일과 Sidecar를 검증한다.
   - Collection Manifest의 Session·Scenario·Device·IP가 Dataset/Run Manifest와 일치하는지 검증한다.
   - `session_manifest_ref=null`인 기존 Scenario Runner Run은 기존 동작을 유지한다.

공식 Verified Collection Export에서는 동일 DB Snapshot을 명시적으로 읽을 수 있도록 Exporter에 선택적 read-only DB 경로를 추가한다. 기존 인자 미지정 경로는 `SessionLocal`을 사용하는 현재 동작을 유지한다.

### 5.3 변경하지 않는 범위

- DB Schema·Migration
- Packet Capture Runtime
- Packet Feature 계산식
- Packet Rule·Packet IF Feature 순서·학습 알고리즘
- Threshold 계산 방식
- Trust Score·Firewall 정책
- API·Dashboard
- 기존 Scenario Runner 실행 방식
- 기존 정상·공격 Packet 원본

## 6. 불변 Dataset 패키지

17개 Session을 개별적으로 바로 게시하지 않는다. 전체 Batch가 성공한 경우에만 하나의 Package Directory를 원자적으로 게시한다.

```text
data/exports/<dataset_package_id>/
├── import-summary.json
├── import-summary.json.sha256
├── db-snapshot.db
├── db-snapshot-metadata.json
├── packet-if-export-spec-v2.json
├── runs/
│   ├── <run_id>/
│   │   ├── verified-collection-manifest.json
│   │   ├── verified-collection-manifest.json.sha256
│   │   ├── run-manifest.json
│   │   ├── run-manifest.json.sha256
│   │   └── evidence/
│   │       ├── session-snapshot.json
│   │       ├── feature-qc.json
│   │       ├── pcap-inventory.json
│   │       └── source-evidence.json
│   └── ...
└── Dataset Export 후 생성
    ├── packet-if-dataset-v2.csv
    └── packet-if-dataset-v2-manifest.json
```

`run_manifest_ref.relative_path`는 Package Root의 Dataset Manifest 위치를 기준으로 `runs/<run_id>/run-manifest.json`을 사용한다.

PCAP 원본은 용량과 중복 저장 위험 때문에 이 Importer가 복사·이동·삭제하지 않는다. `pcap-inventory.json`에 프로젝트 상대경로·크기·SHA256·Segment 식별자를 기록하고 Import 시 실제 파일을 검증한다. 원본 PCAP 보존 정책은 기존 `data/pcap/processed` 보관 절차를 따른다.

DB는 승인된 SQLite Backup 절차로 생성한 일관 Snapshot을 입력으로 사용한다. Importer는 Snapshot을 Package에 복사하고 SHA256·`PRAGMA integrity_check`·`PRAGMA foreign_key_check` 결과를 기록한다. Dataset Export도 같은 Package의 Snapshot을 read-only로 조회한다.

## 7. Verified Collection Manifest 계약

### 7.1 기본 식별자

```text
schema_version = phase5-verified-collection-v1
provenance_mode = VERIFIED_RETROSPECTIVE_IMPORT
collection_method = MANUAL_HARDWARE
```

의미는 다음과 같다.

> 수집 당시 자동 Run Manifest는 생성되지 않았지만, 보존된 DB Snapshot·PCAP·QC·Split·Firmware·Source 증적을 이후 읽기 전용으로 검증해 Dataset Provenance로 이관했다.

이 Manifest는 Scenario Runner 실행, 자동 공격 실행, 당시 자동 Manifest 생성을 주장하지 않는다.

### 7.2 핵심 필드

- `run_id`
- `session_id`
- `collection_slot_id`
- `source_capture_group_id`
- `split`
- `traffic_label`
- `scenario`
- `collection_device_id`
- `target_device_id`
- `target_source_ip`
- `included_device_ids`
- `background_traffic_present`
- `firmware_version`
- `payload_schema_version`
- `payload_schema_provenance`
- `normal_policy_version`
- `capture_source_commit_sha`
- `verification_commit_sha`
- `capture_interface`
- `capture_filter`
- `started_at`
- `first_window_start`
- `ended_at`
- `verified_at`
- Segment·Feature·Packet 집계
- Evidence 파일 참조와 SHA256
- DB Snapshot SHA256

Manifest는 알 수 없는 필드를 거부하고 Canonical JSON으로 직렬화한다. Sidecar는 Canonical JSON SHA256 한 줄을 저장한다.

### 7.3 Evidence Hash 계약

- Collection Manifest SHA256은 Canonical JSON 기준이다.
- Run Manifest SHA256은 기존 `run_manifest_sha256()` 기준을 그대로 사용한다.
- Evidence 파일의 SHA256은 정확한 파일 Byte 기준이다.
- `pcap-inventory.json`은 각 PCAP의 정확한 Byte SHA256을 포함한다.
- Run Manifest의 `artifacts`에는 모든 Evidence 파일의 상대경로·크기·SHA256을 기록한다.

## 8. Import Spec

Import Spec은 사용자가 임의로 계산 가능한 값을 최소화하고, 노션의 공식 Split·QC 인계 자료에서 확정해야 하는 값만 입력받는다.

```json
{
  "schema_version": "phase5-verified-collection-import-spec-v1",
  "dataset_package_id": "packet-if-v2-verified-001",
  "normal_policy_version": "phase5-normal-policy-v1.1",
  "capture_filter": "tcp or udp",
  "sessions": [
    {
      "session_id": "11111111-1111-4111-8111-111111111111",
      "collection_slot_id": "normal-stable-train-01",
      "split": "train",
      "traffic_label": "normal",
      "scenario": "normal_stable",
      "collection_device_id": "esp32_01",
      "firmware_version": "phase5-normal-pilot-v1",
      "payload_schema_version": "phase5-normal-payload-v1",
      "payload_schema_provenance": "FIRMWARE_REPORTED",
      "capture_source_commit_sha": "<실제 수집 Commit 40자리 SHA1>"
    },
    {
      "session_id": "23d5dc5b-1e73-44e4-80ed-1d0c12bda7f9",
      "collection_slot_id": "packet-rate-flood-test-01",
      "split": "test",
      "traffic_label": "attack",
      "scenario": "packet_rate_flood",
      "collection_device_id": "esp32_02",
      "target_device_id": "esp32_02",
      "target_source_ip": "192.168.0.5",
      "firmware_version": "phase5-packet-rate-sender-v2",
      "payload_schema_version": "phase5-packet-rate-udp-payload-v1",
      "payload_schema_provenance": "RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION",
      "capture_source_commit_sha": "a4b0be29a8353f3b516808e2ed945b6cb251ac61"
    }
  ]
}
```

`run_id`, `included_device_ids`, `background_traffic_present`, `source_capture_group_id`, 시간, Segment·Feature 집계는 Importer가 검증 결과로 결정한다.

- 기본 Run ID: `verified-<collection_slot_id>`
- 기본 `source_capture_group_id`: 해당 `session_id`
- 동일 원본 Capture에서 여러 Session이 파생됐다는 증적이 있는 경우에만 명시적 공통 UUID Override를 허용한다.
- Override에는 해당 Group을 입증하는 Evidence 참조가 필요하다.

소스·노션·인계 패키지에서 확인되지 않는 필수값은 임의 생성하지 않고 해당 Batch 전체를 HOLD한다.

## 9. Scenario·Firmware·Payload 계약

### 9.1 허용 Collection Scenario

정상 Profile은 Scenario Runner Registry 대상이 아니므로 Importer가 모든 Scenario를 Registry로 조회해서는 안 된다. Verified Collection 전용 허용 목록을 사용한다.

```text
normal_stable
normal_interval_jitter
normal_payload_variation
normal_combined_variation
packet_rate_flood
```

`packet_rate_flood`는 기존 Scenario Registry의 동일 ID·Version과 추가로 대조한다.

### 9.2 정상 Firmware

정상 Session은 실제 Firmware 계약을 사용한다.

```text
firmware_version = phase5-normal-pilot-v1
payload_schema_version = phase5-normal-payload-v1
payload_schema_provenance = FIRMWARE_REPORTED
```

### 9.3 Session 53 Payload Schema

Session 53 수집 당시 Firmware는 Payload Schema Version을 Serial에 출력하지 않았다. 따라서 `phase5-packet-rate-udp-payload-v1`은 실제 Source와 PCAP Byte 구조를 사후 검증해 이름을 부여한 계약이다.

```text
Protocol: UDP
Source device: esp32_02
Expected source IP: 192.168.0.5
Local UDP port: 42100
Target: 192.168.0.20:19999
Payload length: START 명령의 payload_bytes
Prefix: ASCII "esp32_02_packet_rate"
Remaining bytes: ASCII 'P'
```

Manifest에는 다음을 명시한다.

```text
payload_schema_version = phase5-packet-rate-udp-payload-v1
payload_schema_provenance = RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION
firmware_reported_payload_schema_version = null
```

과거 Firmware가 이 Version 문자열을 출력했다고 기록하지 않는다. 향후 공식 E2E 전에 동일 Version을 Firmware Boot/Status 로그에 추가하는 작업은 별도 후속 변경으로 처리할 수 있다.

## 10. DATA_ONLY Run Manifest 매핑

Importer는 기존 `RunManifest` 클래스를 직접 사용한다.

```text
evaluation_scope = DATA_ONLY
is_active = false
scenario_status = SUCCESS
data_status = SUCCESS
detection_status = NOT_APPLICABLE
trust_status = NOT_APPLICABLE
firewall_status = NOT_APPLICABLE
block_status = NOT_APPLICABLE
final_status = SUCCESS
```

Expected Outcome은 다음으로 고정한다.

```text
expected_event_types = []
detection_expected = false
trust_score_change_expected = false
firewall_expected = false
block_expected = false
evaluation_scope = DATA_ONLY
```

### 10.1 정상 Session

Dataset Annotation과 Run Manifest의 Target 의미를 구분한다.

```text
Dataset Annotation:
  target_device_id = null
  target_source_ip = null

Run Manifest:
  target_device_id = esp32_01
  source_ip = 192.168.0.4
  execution_node.node_id = esp32_01
  execution_node.registered = true
```

이는 현재 Dataset v2의 정상 Run 검증이 Run Manifest의 Device가 실제 Export된 등록 Device를 식별하도록 요구하기 때문이다.

### 10.2 Session 53

```text
Dataset Annotation 및 Run Manifest:
  scenario = packet_rate_flood
  target_device_id = esp32_02
  target_source_ip/source_ip = 192.168.0.5
  execution_node.node_id = esp32_02
  execution_node.registered = true
```

### 10.3 Run 시각 의미

Run Manifest는 사후 Import 실행 시각이 아니라 원래 Capture 실행을 나타낸다.

```text
started_at = packet_capture_sessions.started_at
observation_deadline_at = packet_capture_sessions.ended_at
ended_at = packet_capture_sessions.ended_at
```

정상 Session의 `attack_started_at`은 `null`이다.

Session 53의 ESP32 `started_at_ms`는 부팅 후 경과시간이므로 절대 UTC로 변환하지 않는다. 절대 UTC 공격 시작 증거가 확정되지 않으면 `attack_started_at=null`로 둔다. Gateway에서 확인한 첫 공격 Packet 시각은 `external_observations.gateway_first_attack_packet_at`과 Collection Evidence에 별도로 기록한다.

사후 검증 시각은 Collection Manifest의 `verified_at`에 기록한다.

## 11. 읽기 전용 검증

### 11.1 DB Snapshot

- 절대경로의 SQLite Snapshot만 허용한다.
- Snapshot은 승인된 SQLite Backup 방식으로 생성한다.
- `PRAGMA integrity_check = ok`
- `PRAGMA foreign_key_check` 결과 0건
- Importer 연결은 SQLite `mode=ro`와 `PRAGMA query_only=ON`을 사용한다.
- Source Snapshot과 Package에 복사된 Snapshot의 SHA256이 일치해야 한다.

### 11.2 Capture Session

- Canonical 소문자 UUID4
- DB에 Session 존재
- `status=COMPLETED`
- `started_at`, `first_window_start`, `ended_at` 존재
- Segment 1개 이상
- `READY=0`
- `FAILED=0`
- 모든 Segment가 `PROCESSED` 또는 `EMPTY`
- `PROCESSED` Segment는 Feature Row가 1개 이상
- `EMPTY` Segment는 Feature Row가 0개
- Feature Ready Through가 마지막 Segment `window_end`와 일치
- Session 내부 Window가 정확히 연속
- 각 Window는 정확히 10초
- Session 사이 Capture Gap은 감사 정보로만 기록

`Feature Ready Through`는 Session의 `ended_at` 문자열과 직접 비교하지 않는다. 마지막 Segment `window_end`와 UTC datetime으로 비교한다.

### 11.3 Feature·Device

- Feature Window와 부모 Segment Window 정확히 일치
- `direction=INBOUND`
- 등록 Device ID 존재
- `peer_ip == devices.ip_address`
- 공통 Capture Policy 적격
- 요청 Session마다 적격 Row 1개 이상
- 정상 Session은 `collection_device_id=esp32_01` Row를 Export
- 공격 Session은 `target_device_id=esp32_02`, `target_source_ip=192.168.0.5` Row만 Export

### 11.4 Included Device와 Background Traffic

`included_device_ids`는 수동 입력하지 않고 실제 Export 대상 적격 Row에서 결정한다.

```text
정상 단일 기기 Session → ["esp32_01"]
Session 53 공격 → ["esp32_02"]
```

`background_traffic_present`는 Target 필터 적용 전 같은 Session에 대상 외 다른 등록 Device의 Capture Policy 적격 `INBOUND` Row가 존재할 때만 `true`로 계산한다. OUTBOUND Row와 미등록 Peer는 이 판정에 포함하지 않는다.

### 11.5 PCAP

- Segment `file_name`과 `processed` PCAP Directory를 결합한다.
- 모든 `PROCESSED`·`EMPTY` Segment의 PCAP 파일 존재를 확인한다.
- 파일 크기와 SHA256을 기록한다.
- DB Segment Window와 PCAP Filename의 Session·Interface·Window 식별자를 대조한다.
- 원본 PCAP은 수정·이동·삭제하지 않는다.

Importer CLI는 다음 경로를 명시적으로 받는다.

```text
--project-root
--db-snapshot
--processed-pcap-dir
--spec
--output-root
```

CWD나 환경변수만으로 PCAP 위치를 추측하지 않는다.

### 11.6 Split·누수

- 하나의 Session은 하나의 Split에만 포함
- `collection_slot_id` 중복 금지
- Run ID 중복 금지
- 같은 `source_capture_group_id`는 하나의 Split에만 존재
- Train·Validation은 정상만 허용
- Test에는 정상과 공격이 모두 존재
- Session 53은 Test 전용
- Holdout Session은 Export Spec에 포함 금지
- Dataset 전체에 `phase5-normal-policy-v1.1` 하나만 사용

## 12. Session 53 특수 증적

Session 53의 실제 증적은 다음과 같이 기록한다.

```text
sender_reported_packets = 960
gateway_observed_packets = 880
feature_packet_count = 880
observation_gap_packets = 80
observation_gap_cause = UNRESOLVED
raw_feature_consistency = PASS
```

ESP32의 `udp.endPacket()==1`은 수신 ACK가 아니다. 960과 880의 차이를 Wi-Fi 손실, ESP32 실패, Raspberry Pi Drop 등으로 단정하지 않는다. Dataset Ground Truth는 Gateway가 실제 관측하고 Feature와 일치한 880개다.

Session 53의 공격 Test Row 수가 적으므로 결과는 실제 ESP32 공격 Offline Pipeline 검증으로 표현한다. 이 한 Session만으로 일반화된 공격 탐지율을 주장하지 않는다.

## 13. Dataset v2 연동

Importer는 검증 결과로 `packet-if-export-spec-v2.json`을 직접 생성한다. 사용자가 같은 값을 다시 수동 입력하지 않는다.

생성 Spec에는 각 Session의 다음 값이 들어간다.

- Session·Split·Label·Scenario
- Target Device·Source IP
- Collection Slot·Source Capture Group
- Run Manifest Path·Reference·SHA256
- Normal Policy·Firmware·Payload Schema Version
- Included Device IDs
- Background Traffic 여부
- 세션별 `source_commit_sha`

Exporter의 Row 필터링·Capture Policy·Split·학습 Feature 계약은 변경하지 않는다. 세션별 Commit과 Collection Manifest 연쇄 검증만 하위 호환 방식으로 추가한다.

공식 Export는 Package의 `db-snapshot.db`를 read-only로 조회한다. 기존 Exporter 호출은 계속 지원하지만 Verified Collection 공식 경로에서는 Snapshot 경로가 필수다.

## 14. Collection Manifest 연쇄 검증

Dataset Export와 Dataset Load에서 다음 순서를 적용한다.

1. `run_manifest_ref.relative_path` 안전성 확인
2. Run Manifest 파일 로드
3. Run Manifest Canonical SHA256 검증
4. Run Manifest Sidecar 검증
5. Run·Session·Scenario·Device·IP 일치 검증
6. `session_manifest_ref` 존재 확인
7. Run Manifest Directory 기준으로 Collection Manifest 상대경로 해석
8. Collection Manifest Canonical SHA256 검증
9. Collection Manifest Sidecar 검증
10. Collection·Run·Dataset의 Session·Scenario·Device·IP 일치 검증
11. Collection Manifest가 참조하는 Evidence 파일의 크기·SHA256 검증

기존 Scenario Runner Run처럼 `session_manifest_ref=null`인 Run은 현재 Dataset v2 사용 여부를 그대로 유지한다. Verified Collection으로 생성된 Run은 `session_manifest_ref`가 반드시 있어야 한다.

## 15. Batch 원자성·재실행 안전성

### 15.1 Check-only

`--check-only`는 다음만 출력한다.

- Session별 적격·부적격 판정
- Segment·Feature·Packet 집계
- 계산될 Run ID·Split·Scenario
- 계산될 Included Device·Background Traffic
- PCAP 파일 수·총 크기·누락 수
- HOLD 또는 실패 사유

DB와 원본 파일을 변경하지 않고 최종 Package 파일도 생성하지 않는다.

### 15.2 Write

`--write`는 다음 순서로 동작한다.

1. 전체 17개 Session Preflight
2. 전체 Split·ID·Source Group 교차 검증
3. Output Root 아래 동일 파일시스템의 임시 Batch Directory 생성
4. DB Snapshot 복사·검증
5. 모든 Manifest·Evidence·Export Spec 생성
6. 모든 SHA256과 참조 경로 재검증
7. 임시 Directory `fsync`
8. 최종 `<dataset_package_id>` Directory로 원자적 Rename

하나라도 실패하면 임시 Directory를 정리하고 최종 Package를 게시하지 않는다. 기존 최종 Directory가 있으면 덮어쓰지 않고 실패한다.

## 16. 오류 처리와 안전 경계

다음 경우 전체 Import를 실패 또는 HOLD한다.

- 필수 Provenance 값 미확인
- Session·Device·IP·Scenario 불일치
- Session 미완료
- READY·FAILED Segment 존재
- Feature Ready Through 불일치
- Session 내부 Window Gap·중복
- 적격 INBOUND Row 없음
- Feature·Segment Window 불일치
- PCAP 누락·Hash 불일치
- Split·Source Group 누수
- 중복 Slot·Run ID
- Evidence·Manifest·Sidecar 불일치
- 기존 Output Package 존재
- 알 수 없는 Schema·Split·Label·Collection Scenario

Importer는 다음을 수행하지 않는다.

- 운영 DB INSERT·UPDATE·DELETE
- Detection Checkpoint 변경
- PCAP 수정·이동·삭제
- Trust Score·Device 상태 변경
- Firewall·iptables 변경
- Capture·Extractor·Detector 실행
- Dataset CSV 자동 Export
- 모델 학습·Artifact 배포

## 17. 테스트 전략

### 17.1 Contract 테스트

- Canonical JSON·SHA256 안정성
- 알 수 없는 필드 거부
- UUID·Commit SHA·IPv4·Identifier 검증
- Portable Relative Path 검증
- Collection Manifest Sidecar 검증
- Evidence 크기·SHA256 검증
- Collection·Run Identity 일치 검증
- Session Manifest 경로 탈출 차단

### 17.2 Importer 단위 테스트

- 정상 COMPLETED Session 성공
- Session 53 형태 공격 Session 성공
- 정상·공격 Scenario 허용 목록 검증
- READY·FAILED·미완료 Session 거부
- PROCESSED/EMPTY Feature 불변식 검증
- Device·IP 불일치 거부
- OUTBOUND·미등록·부적격 Row 제외
- 적격 Row 0개 실패
- Window Gap·중복·불일치 거부
- PCAP 누락·Hash 오류 거부
- `background_traffic_present` 자동 계산
- `included_device_ids` 자동 계산
- 기본 `source_capture_group_id=session_id`
- DB Query-only 보장
- `--check-only` 무출력 파일 보장
- Batch 중간 실패 시 최종 Package 미게시
- 기존 Package 덮어쓰기 거부

### 17.3 Dataset v2 통합 테스트

- 생성 Run Manifest를 Exporter와 Loader가 승인
- 정상 Run의 Dataset Target null·Run Target Device 계약 통과
- 공격 Run Target Device·Source IP 통과
- Session별 Source Commit이 Dataset Manifest에 보존됨
- 최상위 Source Commit fallback 하위 호환
- Collection Manifest 변조 감지
- Collection Sidecar 변조 감지
- Evidence 변조 감지
- 동일 Session·Source Group Split 누수 차단
- 기존 Dataset v2 테스트 회귀 없음

### 17.4 Snapshot Export 테스트

- 명시 Snapshot read-only 조회
- Snapshot 경로 누락·상대경로 거부
- Export 후 Snapshot 내용 불변
- 기존 SessionLocal 호출 하위 호환

### 17.5 회귀 검증

- Verified Collection 집중 테스트
- Packet IF Dataset v2 Export·Loader 테스트
- Run Manifest 계약 테스트
- Packet IF 학습·평가 테스트
- Scenario Runner 인접 테스트
- 가능한 범위의 전체 `pytest`
- `compileall`
- `git diff --check`

## 18. Raspberry Pi 적용 순서

코드 병합 후 Raspberry Pi #1에서 다음 순서로 진행한다.

1. Git·Worktree·서비스·Capture 상태 Preflight
2. 승인된 SQLite Backup API로 DB Snapshot 생성
3. Snapshot Integrity·FK·SHA256 확인
4. 노션 공식 Split·QC·인계 패키지와 17개 Session Import Spec 대조
5. `--check-only` 전체 Batch 검증
6. 결과에서 Session별 Commit·Firmware·Payload·Row·PCAP 수 확인
7. 사용자 승인 후 `--write`
8. Package Manifest·Sidecar·Evidence 재검증
9. 생성된 Export Spec 검토
10. Package DB Snapshot에서 Dataset v2 Export
11. Dataset Split·Row·Session Hash Audit
12. Packet IF 학습·Validation Threshold 산출
13. 정상 Test와 Session 53 공격 Test 평가
14. Artifact를 Raspberry Pi #1에 배포
15. 별도 새 ESP32 공격 E2E Holdout 실행

## 19. 성공 기준

- 정상 16개와 Session 53을 재수집하지 않는다.
- 과거 Scenario Runner 실행을 허위로 생성하지 않는다.
- 각 Session의 실제 Capture Source Commit을 보존한다.
- Session 53 Payload 계약이 사후 검증 계약임을 명시한다.
- Collection Manifest까지 SHA256 연쇄 검증한다.
- 전체 17개가 성공한 경우에만 Package를 게시한다.
- 운영 DB·PCAP·Trust·Firewall을 변경하지 않는다.
- 동일 Package Snapshot·Spec으로 Dataset Export와 학습을 재현할 수 있다.
- Packet IF Artifact 생성 후 별도의 신규 ESP32 E2E Holdout을 유지한다.

## 20. 제외 범위

- Raspberry Pi #2 설정·사용
- Scenario Runner ESP32 Serial 자동 제어
- 정상·공격 Session 신규 수집
- Session 51·52 Dataset 포함
- 정상 Holdout Dataset 포함
- Packet IF 모델 학습·Threshold 산정 자체
- Artifact 배포
- Trust·Firewall FULL_E2E 실행
- Dashboard 변경
- DB Migration
- Phase 6 Threshold 최종 보정
