# Packet IF Dataset Manifest v2 계약

## 목적

`packet-if-dataset-v2`는 Phase 5의 실제 Capture Session을 Packet IF 학습과
평가에 사용하기 전에 Split, 수집 출처, Run Manifest와 정상 정책 Version을
고정하는 계약입니다. Dataset Manifest는 하나의 JSON 파일이며 Session 정보는
`sessions[]`에 Inline으로 기록합니다. Session별 별도 Packet IF Manifest는
만들지 않습니다.

공통 Phase 5 Run Manifest와 Packet IF Dataset Manifest는 역할이 다릅니다.

- Run Manifest: 실행 1회의 대상·시각·기대 결과·단계별 상태 증적
- Dataset Manifest: 학습용 Session·Split·Label·수집 출처와 CSV 무결성

Dataset Manifest는 Run Manifest를 `run_manifest_ref`로 참조하며 공통 필드를
재정의하지 않습니다.

## Version과 호환성

- 공식 Phase 5 Export·학습·평가: `packet-if-dataset-v2`
- 기존 Local Fixture 읽기: `packet-if-dataset-v1`
- Exporter 신규 출력: 항상 v2
- Phase 5 Holdout: Dataset Split에 포함하지 않고 외부 수집 계획에서 별도 보존
- Phase 6-B `packet-if-v2-calib-002` 정상 Holdout: 호환 가능한 `test` Split으로
  명시하되 Model fitting·Threshold 선택에서는 제외

## Session 필수 항목

v2의 모든 Session은 기존 Capture·Device·SHA256 항목과 함께 아래 값을
포함해야 합니다.

- `collection_slot_id`: 사전 배정한 수집 Slot 식별자
- `source_capture_group_id`: 동일 PCAP·동시 수집 원본을 묶는 Canonical UUID4
- `run_manifest_ref`: Run ID·상대 경로·Schema Version·Canonical JSON SHA256
- `normal_policy_version`: Dataset 전체에 적용한 정상 정책 Version
- `firmware_version`: 수집 또는 공격 Firmware Version
- `payload_schema_version`: Payload Schema Version
- `included_device_ids`: 수집에 포함된 등록 Device 목록
- `background_traffic_present`: 배경 트래픽 포함 여부
- `target_source_ip`: 공격 Session의 실제 등록 Device IPv4

정상 Dataset Session의 `target_device_id`와 `target_source_ip`는 `null`입니다.
다만 공통 Run Manifest는 실제 수집 실행 주체를 식별해야 하므로 정상 Run에도
등록된 `target_device_id`와 `source_ip`가 존재하며, 둘은 Dataset Session의
`included_device_ids`와 Export된 Device/IP 중 하나와 일치해야 합니다.

공격 Session은 Dataset과 Run Manifest의 `target_device_id`·`target_source_ip`가
모두 일치해야 하며 Exporter는 해당 대상 Row만 공격 Label로 포함합니다.

## Run Manifest 검증

Run Manifest 파일과 `<run-manifest-path>.sha256` Sidecar는 Dataset Manifest가
있는 Directory 아래에 보관합니다. `run_manifest_ref.relative_path`는 이
Directory 기준 상대 경로이며 절대 경로와 `..` 경로 이탈을 허용하지 않습니다.
경로의 마지막 파일명은 `run-manifest.json`으로 고정하고, 모든 경로 구성요소는
Windows·macOS·Linux에서 공통으로 사용할 수 있는 영문자·숫자·점·밑줄·하이픈만
허용합니다. Windows 예약 장치명과 NTFS Alternate Data Stream 형태도 거부합니다.

Loader와 Exporter는 다음을 게시 또는 학습 전에 검증합니다.

- Canonical JSON SHA256과 참조 SHA256 일치
- Sidecar SHA256 일치
- Run Manifest Schema Version 지원 여부
- `run_id`, `session_id`, `scenario_id` 일치
- 공격 대상 Device·Source IP 일치
- 정상 수집 Run의 Device·Source IP가 포함 Device와 일치

공식 Export Directory를 `data/exports/`로 사용할 때 Scenario Runner도 같은
Directory 아래에 증적을 만들도록 실행합니다. 기본 경로인 `data/phase5/runs/`를
그대로 사용하면 `data/exports/packet_if_manifest-v2.json`에서 `../` 참조가
필요해져 계약상 거부됩니다.

```bash
python -m edge.scenarios.run_scenario --runs-root data/exports/runs --help
```

정상 수집은 Capture Runtime이 새 Canonical UUIDv4 `session_id`를 생성한 뒤 해당
값을 Run Manifest와 Dataset Export Spec에 기록합니다. 공격 FULL_E2E는 같은
Capture Session을 확인한 뒤 그 `session_id`를 Scenario Runner의 `--session-id`에
전달합니다.

## Split과 누수 방지

- Session 하나는 하나의 Split에만 포함합니다.
- 동일 `source_capture_group_id`의 모든 Session은 같은 Split에 둡니다.
- `collection_slot_id`와 Run ID는 Dataset 안에서 중복할 수 없습니다.
- Train·Validation은 서로 다른 정상 Session만 사용합니다.
- Test에는 정상·공격 Session을 모두 포함합니다.
- Test는 Threshold 산정에 사용하지 않습니다.
- Phase 5에서 외부 보존하기로 한 Holdout은 Train·Validation·Test CSV와
  Manifest에 포함하지 않습니다.
- `packet-if-v2-calib-002`의 명시적으로 승인된 정상 Holdout 2 Session은
  Dataset 형식상 `test`에 포함합니다. Train만 Model fitting에 사용하고 정상
  Validation만 Threshold 선택에 사용합니다. Model과 Threshold를 고정한 뒤에만
  이 Holdout을 평가하며, 결과를 보고 같은 Artifact의 Threshold를 다시 조정하지
  않습니다.
- 부적격 Session은 같은 Slot의 새 Session·Run ID로 재수집하며 기존 결과를
  다른 Split으로 이동하지 않습니다.

## Row 포함 기준

- Capture Session 상태가 `COMPLETED`
- 등록 Device의 `INBOUND` Row
- `peer_ip == devices.ip_address`
- 공통 Capture Policy 적격 판정 통과
- Packet Feature Window와 Capture Segment Window 일치
- Row Device가 `included_device_ids`에 포함
- 공격 Session은 대상 Device·Source IP와 일치

제외 Row는 사유별로 집계하고, 요청한 Session에서 적격 Row가 하나도 없으면
Dataset 전체 게시를 실패시킵니다.

## 불변성과 인계

CSV와 Dataset Manifest는 기존 파일을 덮어쓰지 않고 원자적으로 게시합니다.
Manifest JSON은 운영체제와 무관하게 UTF-8·LF로 기록하며, Export Directory는
원자적 무덮어쓰기 게시에 필요한 하드링크를 지원해야 합니다.
학습 Artifact에는 Dataset Version·CSV SHA256·Manifest SHA256·Capture Policy와
Normal Policy Version을 기록합니다. 인계 시 다음 값을 함께 고정합니다.

- Dataset CSV·Manifest 경로와 SHA256
- Session·Split·Source Capture Group 목록
- Run Manifest와 Sidecar 목록
- Capture Policy·Normal Policy·Firmware·Payload Schema Version
- 학습 Commit SHA, Model Version과 Artifact Bundle SHA256
