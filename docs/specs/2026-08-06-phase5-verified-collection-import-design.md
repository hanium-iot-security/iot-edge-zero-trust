# Phase 5 Verified Collection Import 설계

## 1. 목적

Phase 5에서 이미 수집·QC가 완료된 ESP32 Packet Capture Session을 다시 수집하지 않고, 보존된 DB·PCAP·QC·Split·Firmware·Commit 증적을 읽기 전용으로 검증해 `packet-if-dataset-v2`의 공식 Provenance로 이관한다.

이 설계는 자동 Scenario Runner가 생성한 적 없는 과거 Run을 실행된 것처럼 꾸미지 않는다. 대신 수동 실기기 수집 사실을 별도의 검증 Manifest로 명시하고, 기존 공통 `phase5-run-manifest-v1`의 `session_manifest_ref`를 통해 Dataset v2 계약에 연결한다.

## 2. 프로젝트 기준과 결정 사항

### 2.1 Phase 5 장비 구성

- Raspberry Pi #1: Gateway/Broker, Packet Capture, Packet Feature, Packet Rule, Packet IF, Trust, Firewall
- ESP32 #2: 등록 IoT 공격 송신 기기
- 관리 노트북: Firmware 업로드, Serial 명령, 로그·증적 관리, Dataset·모델 작업
- Raspberry Pi #2: Phase 5 미사용. Python 공격 자동화와 Scenario Runner 반복 평가는 Phase 6 후보

### 2.2 재사용 대상

공식 Packet IF Dataset 후보:

- `esp32_01` 정상 Train 8 Sessions
- `esp32_01` 정상 Validation 4 Sessions
- `esp32_01` 정상 Test 4 Sessions
- `esp32_02` 공격 Offline Test Session 53
  - Session ID: `23d5dc5b-1e73-44e4-80ed-1d0c12bda7f9`
  - Source IP: `192.168.0.5`
  - Firmware: `phase5-packet-rate-sender-v2`

Dataset 외부 보존:

- `esp32_02` 정상 Holdout 2 Sessions
- Session 51: Packet Rule·Event Commit 통합 검증
- Session 52: 10초 Tumbling Window 경계 False Negative 분석
- Artifact 배포 후 새로 수집할 공식 E2E 공격 Holdout

## 3. 현재 문제

`packet-if-dataset-v2`는 모든 Session에 검증 가능한 `run_manifest_ref`를 요구한다. 그러나 공식 정상 Session과 ESP32 공격 Session 53은 Dataset v2 계약 병합 전에 수집되어 Session-bound Run Manifest가 없다.

현재 Scenario Runner는 Python 공격 모듈을 직접 실행하는 구조이며, ESP32 Serial 공격을 직접 실행하거나 기다리는 기능은 없다. 따라서 과거 ESP32 Session을 Scenario Runner 실행 결과로 사후 생성하면 실제 Provenance와 불일치한다.

정상 16개 Session을 다시 수집하는 것은 시간·장비·재현 비용이 크며, 이미 완료된 QC·PCAP·Session 증적을 불필요하게 폐기하게 된다.

## 4. 선택한 접근

### 4.1 이중 Manifest 연결

다음 구조를 사용한다.

```text
보존된 Session·DB·PCAP·QC 증적
        ↓ 읽기 전용 검증
verified-collection-manifest.json
        ↓ session_manifest_ref
phase5-run-manifest-v1
        ↓ run_manifest_ref
packet-if-dataset-v2
```

`packet-if-dataset-v2`의 기존 Run Manifest 검증 경로는 유지한다. 새 Importer가 검증된 Collection Manifest와 이를 참조하는 DATA_ONLY Run Manifest를 생성한다.

### 4.2 Provenance 의미

Verified Collection Manifest에는 다음 값을 명시한다.

- `schema_version = phase5-verified-collection-v1`
- `provenance_mode = VERIFIED_RETROSPECTIVE_IMPORT`
- `collection_method = MANUAL_HARDWARE`

의미:

> 수집 당시 자동 Run Manifest는 생성되지 않았지만, 보존된 운영 DB·PCAP·QC·Split·Firmware·Commit 증적을 이후 읽기 전용으로 검증해 공식 Dataset Provenance로 이관했다.

이 Manifest는 Scenario Runner 실행, 자동 공격 실행, 당시 자동 Manifest 생성을 주장하지 않는다.

## 5. 구성 요소

### 5.1 Verified Collection 계약

예상 위치:

```text
edge/phase5/verified_collection_contract.py
```

주요 모델:

- `VerifiedCollectionManifest`
- `VerifiedCollectionEvidence`
- `VerifiedCollectionDevice`
- `VerifiedCollectionSplit`
- `VerifiedCollectionValidationResult`

핵심 필드:

- Schema·Provenance Version
- Import Run ID
- Session ID
- Collection Slot ID
- Source Capture Group ID
- Split
- Traffic Label
- Scenario
- Device ID·Source IP
- Included Device IDs
- Firmware Version
- Payload Schema Version
- Normal Policy Version
- Source Commit SHA
- Verification Commit SHA
- Capture Interface·시간 범위
- Segment·Feature 집계
- PCAP Inventory SHA256
- QC Evidence SHA256
- 생성 시각

Manifest는 Canonical JSON과 SHA256 Sidecar를 지원한다.

### 5.2 Importer

예상 위치:

```text
edge/phase5/import_verified_collection.py
```

입력:

- 운영 DB 절대경로
- Import Spec JSON
- 출력 Root
- 현재 Commit SHA

출력:

```text
data/exports/runs/<run_id>/
├── verified-collection-manifest.json
├── verified-collection-manifest.json.sha256
├── run-manifest.json
├── run-manifest.json.sha256
└── evidence/
    ├── session-snapshot.json
    ├── feature-qc.json
    └── pcap-inventory.json
```

출력은 기존 경로를 덮어쓰지 않는다.

### 5.3 DATA_ONLY Run Manifest 변환

Importer는 기존 `RunManifest` 계약을 사용해 다음 상태를 생성한다.

```text
evaluation_scope = DATA_ONLY
scenario_status = SUCCESS
data_status = SUCCESS
detection_status = NOT_APPLICABLE
trust_status = NOT_APPLICABLE
firewall_status = NOT_APPLICABLE
block_status = NOT_APPLICABLE
final_status = SUCCESS
```

`session_manifest_ref`는 `verified-collection-manifest.json`의 Schema Version과 SHA256을 참조한다.

정상 Session:

- `target_device_id = esp32_01`
- `source_ip = 192.168.0.4`
- `execution_node.node_id = esp32_01`
- Scenario는 수집 Profile을 나타내는 데이터 수집 Scenario ID 사용

공격 Session 53:

- `target_device_id = esp32_02`
- `source_ip = 192.168.0.5`
- `execution_node.node_id = esp32_02`
- `scenario_id = packet_rate_flood`
- 실제 공격 실행이 Scenario Runner에 의해 수행되지 않았다는 사실은 Verified Collection Manifest의 Provenance 필드에 명시

## 6. 읽기 전용 검증

### 6.1 Session 검증

- Session ID가 Canonical UUID4
- DB에 Session 존재
- `status = COMPLETED`
- `ended_at` 존재
- Segment 수가 1개 이상
- `READY = 0`
- `FAILED = 0`
- Feature Ready Through가 Session 종료와 일치
- Session 내부 Window가 연속
- Segment Window 범위가 Session 범위를 벗어나지 않음

Session 사이 Capture Gap은 감사 정보로 기록하되, Session 내부 Window 연속성과 적격 Segment가 충족되면 실패 사유로 사용하지 않는다.

### 6.2 Feature·Device 검증

- 등록 Device의 `INBOUND` Row만 대상
- `peer_ip == devices.ip_address`
- Feature Window와 Segment Window 일치
- 공통 Capture Policy 적격 판정 통과
- Included Device 목록과 Row Device 일치
- 적격 Row가 1개 이상
- 공격 Session은 `target_device_id`·`target_source_ip`와 일치하는 Row만 공격 Label 대상

### 6.3 Split·누수 검증

- Session 하나는 하나의 Split에만 포함
- 같은 `source_capture_group_id`는 하나의 Split에만 존재
- `collection_slot_id` 중복 금지
- Import Run ID 중복 금지
- 정상 Train·Validation·Test 사전 배정 유지
- Holdout은 Dataset Export Spec에 포함 금지
- Session 53은 Test 전용이며 Threshold 산정에 사용 금지

### 6.4 증적 검증

- 수집 당시 Source Commit 기록
- Import 실행 당시 Verification Commit 기록
- Session Snapshot SHA256
- Feature QC SHA256
- PCAP Inventory SHA256
- 필요한 경우 기존 인계 패키지·Split CSV·QC 요약 SHA256
- 모든 Sidecar와 Manifest SHA256 일치

실제 PCAP Payload를 변경하거나 재작성하지 않는다.

## 7. Import Spec

별도의 입력 Spec으로 Session별 고정 정보를 전달한다.

예상 필드:

```json
{
  "schema_version": "phase5-verified-collection-import-spec-v1",
  "normal_policy_version": "phase5-normal-policy-v1.1",
  "payload_schema_version": "phase5-canonical-payload-v1",
  "sessions": [
    {
      "run_id": "...",
      "session_id": "...",
      "collection_slot_id": "...",
      "source_capture_group_id": "...",
      "split": "train",
      "traffic_label": "normal",
      "scenario": "normal_stable",
      "target_device_id": null,
      "target_source_ip": null,
      "included_device_ids": ["esp32_01"],
      "firmware_version": "...",
      "source_commit_sha": "..."
    }
  ]
}
```

실제 값은 노션의 공식 QC 결과, 정상 사전 인계 패키지, 운영 DB를 대조해 확정한다. 소스에서 확인되지 않는 값은 임의 생성하지 않고 Import를 HOLD한다.

## 8. Dataset v2 연동

Importer 결과의 `run-manifest.json`과 Sidecar는 `data/exports/runs/` 아래에 생성한다. Dataset v2 Export Spec은 기존과 동일하게 이 Run Manifest를 상대 경로로 참조한다.

Dataset Exporter는 기존 검증을 그대로 수행한다.

- Run ID·Session ID·Scenario 일치
- 정상 Session의 Device·Source IP가 Included Device와 일치
- 공격 Session의 Target Device·Source IP 일치
- Run Manifest SHA256·Sidecar 검증
- Session·Source Capture Group Split 누수 차단

Exporter의 핵심 Row 필터링·학습·평가 계약은 변경하지 않는다.

## 9. 오류 처리와 안전 경계

다음 경우 Import를 실패시킨다.

- Session·Device·IP 불일치
- Session 미완료
- READY 또는 FAILED Segment 존재
- Feature Ready Through 불일치
- 적격 INBOUND Row 없음
- Feature·Segment Window 불일치
- Split·Source Capture Group 누수
- 증적 파일 누락 또는 SHA256 불일치
- 기존 출력 Directory 존재
- 알 수 없는 Schema·Scenario·Split·Label
- 과거 데이터에서 필수 Provenance 값을 확인할 수 없음

Importer는 다음을 수행하지 않는다.

- DB INSERT·UPDATE·DELETE
- Checkpoint 변경
- PCAP 수정·이동·삭제
- Trust Score·Device 상태 변경
- Firewall·iptables 변경
- Capture·Extractor·Detector 실행
- 자동 Dataset Export·모델 학습

## 10. 테스트 전략

### 10.1 계약 테스트

- Canonical JSON·SHA256 안정성
- 알 수 없는 필드 거부
- UUID·Commit SHA·IP·Split·Label 검증
- Portable Relative Path 검증
- Manifest Sidecar 검증

### 10.2 Importer 단위 테스트

- 정상 COMPLETED Session Import 성공
- 공격 Session 53 형태 Import 성공
- READY·FAILED·미완료 Session 거부
- Device·IP 불일치 거부
- OUTBOUND·미등록·부적격 Row 제외
- 적격 Row 0개 시 실패
- Window 불일치 거부
- 출력 덮어쓰기 거부
- DB Query-only 보장

### 10.3 Dataset v2 통합 테스트

- 생성된 Run Manifest를 Dataset v2 Loader가 승인
- 정상 Run Device·IP 검증 통과
- 공격 Run Target Device·Source IP 검증 통과
- Run Manifest·Collection Manifest SHA256 변조 감지
- 동일 Session·Source Capture Group Split 누수 차단
- 기존 Dataset v2 테스트 회귀 없음

### 10.4 회귀 검증

- Verified Collection 집중 테스트
- Packet IF Dataset v2 테스트
- Run Manifest 계약 테스트
- Packet IF Export·학습·평가 테스트
- 전체 `pytest` 가능한 범위
- `compileall`
- `git diff --check`

## 11. 실제 Pi 적용 순서

코드 병합 후 Raspberry Pi #1에서 다음 순서로 진행한다.

1. Git·서비스·DB·Worktree Preflight
2. 운영 DB 백업과 SHA256 생성
3. Import Spec 값과 노션·인계 패키지·DB 대조
4. `--check-only` 읽기 전용 검증
5. 결과 검토 후 Manifest 파일 생성 승인
6. 정상 16개 Session Import
7. Session 53 공격 Offline Test Import
8. 생성 Manifest·Sidecar 재검증
9. Dataset v2 Export
10. Dataset Split·Row·SHA256 Audit
11. Packet IF 학습·Validation Threshold·Test 평가

`--check-only`는 DB와 원본 데이터를 변경하지 않고 예상 출력·제외 사유·적격 Row 수만 표시해야 한다.

## 12. 성공 기준

- 정상 16개 Session을 재수집하지 않는다.
- Session 53을 공격 Test로 정직하게 이관한다.
- Scenario Runner가 과거 공격을 실행한 것처럼 기록하지 않는다.
- Dataset v2의 기존 Run Manifest·Split·SHA256 계약을 유지한다.
- DB·PCAP·Trust·Firewall 상태를 변경하지 않는다.
- 동일 Dataset·Manifest·명령으로 Export와 학습을 재현할 수 있다.
- Packet IF Artifact 생성 후 별도의 새 ESP32 공격 E2E Holdout을 보존한다.

## 13. 제외 범위

- Raspberry Pi #2 설정·사용
- Scenario Runner ESP32 Serial 자동 제어
- 정상·공격 Session 신규 수집
- Packet IF 모델 학습·Threshold 산정
- Artifact 배포
- Trust·Firewall FULL_E2E
- Dashboard 변경
- DB Migration
- Phase 6 Threshold 최종 보정
