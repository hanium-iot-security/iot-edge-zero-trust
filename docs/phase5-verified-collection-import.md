# Phase 5 Verified Collection Import 운영 가이드

이미 수집·QC가 끝난 Packet Capture Session을 **다시 수집하지 않고** 읽기 전용으로
검증해 `packet-if-dataset-v2` 입력 Package로 이관하는 절차다.

## 1. 이 도구가 주장하는 것과 주장하지 않는 것

정상 16 Session과 공격 Session 53은 Dataset v2 Run Manifest 계약이 생기기 전에
ESP32로 수동 수집됐다. 그 시점에 Scenario Runner는 실행되지 않았고 Run Manifest도
만들어지지 않았다.

이 도구는 그 사실을 그대로 기록한다.

```text
provenance_mode   = VERIFIED_RETROSPECTIVE_IMPORT
collection_method = MANUAL_HARDWARE
```

> 수집 당시 자동 Run Manifest는 생성되지 않았지만, 보존된 DB Snapshot·PCAP·QC·
> Split·Firmware·Source 증적을 이후 읽기 전용으로 검증해 Dataset Provenance로
> 이관했다.

**주장하지 않는 것**: Scenario Runner 실행, 자동 공격 실행, 수집 당시의 자동
Manifest 생성. 생성되는 Run Manifest는 `evaluation_scope=DATA_ONLY`이며
Detection·Trust·Firewall·Block이 모두 `NOT_APPLICABLE`이다. 그런 평가는 실제로
수행된 적이 없기 때문이다.

## 2. 장비 구성 (Phase 5)

| 장비 | 역할 |
| --- | --- |
| Raspberry Pi #1 | Gateway·Broker·Capture·Feature·Rule·IF·Trust·Firewall |
| ESP32 #2 | 등록 IoT 공격 송신 기기 |
| 관리 노트북 | Firmware 업로드, Serial 명령, 증적·Dataset·모델 작업 |

Raspberry Pi #2는 Phase 5에서 사용하지 않는다. Python 공격 자동화와 Scenario
Runner 반복 평가는 Phase 6 선택 고도화로 이관한다.

## 3. 대상 Session

**포함**

- `esp32_01` 정상 Train 8 / Validation 4 / Test 4
- `esp32_02` 공격 Offline Test Session 53
  (`23d5dc5b-1e73-44e4-80ed-1d0c12bda7f9`, `192.168.0.5`, `packet_rate_flood`)

**제외 (Dataset 외부 보존)**

- `esp32_02` 정상 Holdout 2 Session
- Session 51 (2-Burst Packet Rule·Event 통합 검증)
- Session 52 (10초 Tumbling Window 경계 False Negative 분석)
- Artifact 배포 후 새로 수집할 공식 E2E 공격 Holdout

Import Spec에 실수로 넣어도 도구가 거부한다. 정상 Session은
`collection_device_id=esp32_01`만 허용하고, 공격 Session은 검증 완료된 Session 53
ID만 허용한다.

## 4. 사전 준비 — DB Snapshot

**운영 DB 파일을 그대로 복사하지 않는다.** 운영 DB는 WAL 모드로 동작하므로 본
파일이 몇 KB뿐이고 실제 내용이 `<db>-wal`에 있을 수 있다. 그대로 복사하면
**검증은 통과하는데 내용이 비어 있는 Package**가 만들어진다.

승인된 SQLite Backup API로 일관 Snapshot을 만든다.

```bash
cd /home/pi/iot-edge-zero-trust

python - <<'PY'
import sqlite3
source = sqlite3.connect("backend/data/iot_security.db")
destination = sqlite3.connect("/home/pi/snapshots/iot_security.snapshot.db")
with destination:
    source.backup(destination)
destination.close()
source.close()
PY

sqlite3 /home/pi/snapshots/iot_security.snapshot.db \
  "PRAGMA integrity_check; PRAGMA foreign_key_check;"
sha256sum /home/pi/snapshots/iot_security.snapshot.db
```

`integrity_check`가 `ok`이고 `foreign_key_check` 결과가 비어 있어야 한다. Importer는
`<snapshot>-wal`이 남아 있으면 실행을 거부한다.

Writer Service를 안전하게 중지한 뒤 복사하거나 검증된 Cutover Backup 기능을
사용해도 된다. 셋 중 하나만 쓴다.

## 5. Import Spec

노션의 공식 Split·QC 인계 자료에서 **확정된 값만** 적는다. 계산 가능한 값은 적지
않는다. `run_id`, `included_device_ids`, `background_traffic_present`, 시간,
Segment·Feature 집계는 Importer가 검증 결과로 결정한다.

```json
{
  "schema_version": "phase5-verified-collection-import-spec-v1",
  "dataset_package_id": "packet-if-v2-verified-001",
  "normal_policy_version": "phase5-normal-policy-v1.1",
  "capture_filter": "tcp or udp",
  "sessions": [
    {
      "session_id": "<정상 Session UUID4>",
      "collection_slot_id": "normal-stable-train-01",
      "split": "train",
      "traffic_label": "normal",
      "scenario": "normal_stable",
      "collection_device_id": "esp32_01",
      "firmware_version": "phase5-normal-pilot-v1",
      "payload_schema_version": "phase5-normal-payload-v1",
      "payload_schema_provenance": "FIRMWARE_REPORTED",
      "capture_source_commit_sha": "<해당 Session 수집 Commit 40자리>"
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
      "payload_schema_provenance": "RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY",
      "capture_source_commit_sha": "a4b0be29a8353f3b516808e2ed945b6cb251ac61",
      "sender_reported_packets": 960
    }
  ]
}
```

### 선택 항목

| 필드 | 언제 쓰나 |
| --- | --- |
| `source_capture_group_id` | 같은 원본 Capture에서 여러 Session이 파생된 증적이 있을 때만. 생략하면 `session_id` |
| `sender_reported_packets` | ESP32 Serial 로그의 송신 성공 수. DB에서 유도할 수 없다. **Session 53은 `960` 필수** |
| `observation_gap_cause` | 생략하면 `UNRESOLVED`. Session 53은 `UNRESOLVED` 외의 값을 거부한다 |
| `gateway_first_attack_packet_at` | Gateway에서 확인한 첫 공격 Packet 절대 UTC 시각 |

### 고정된 값

아래는 Import Spec에서 바꿀 수 없다. 다른 값을 쓰면 Batch 전체가 거부된다.

| 항목 | 고정값 |
| --- | --- |
| `normal_policy_version` | `phase5-normal-policy-v1.1` |
| `capture_filter` | `tcp or udp` |
| Session 53 `sender_reported_packets` | `960` |
| Session 53 Gateway 관측·Feature Packet 수 | `880` (Snapshot에서 계산) |
| Session 53 `observation_gap_packets` | `80` |
| Session 53 `observation_gap_cause` | `UNRESOLVED` |

**소스·노션·인계 패키지에서 확인되지 않는 필수값은 임의로 만들지 않는다. 해당
Batch 전체를 HOLD한다.**

### 세션별 수집 Commit

정상 Session과 Session 53은 서로 다른 Commit·Firmware에서 수집됐다. 최상위 Commit
하나만 쓰면 일부 Session의 Capture Source가 부정확해지므로 각 Session이 자기
`capture_source_commit_sha`를 갖는다.

## 6. 실행

### 6.1 검증만 (`--check-only`)

DB와 원본 파일을 변경하지 않고 최종 Package 파일도 만들지 않는다.

```bash
python -m edge.phase5.import_verified_collection \
  --project-root /home/pi/iot-edge-zero-trust \
  --db-snapshot /home/pi/snapshots/iot_security.snapshot.db \
  --processed-pcap-dir /home/pi/iot-edge-zero-trust/data/pcap/processed \
  --spec /home/pi/snapshots/import-spec.json \
  --output-root /home/pi/iot-edge-zero-trust/data/exports \
  --verification-commit-sha "$(git rev-parse HEAD)" \
  --check-only
```

출력 JSON에서 Session별 Split·Scenario·적격 Row 수·Segment 수·PCAP 수·수집
Commit·`included_device_ids`·`background_traffic_present`를 노션 인계 자료와
대조한다.

### 6.2 게시 (`--write`)

`--check-only` 결과를 승인한 뒤에만 실행한다.

```bash
python -m edge.phase5.import_verified_collection \
  ... 동일 인자 ... \
  --write
```

### 6.3 종료 코드

| 코드 | 의미 |
| --- | --- |
| `0` | PASS |
| `2` | 검증·입력 오류 (FAIL 또는 HOLD). 최종 Package 없음 |
| 그 외 | 예기치 못한 런타임 오류 |

## 7. 생성물

```text
data/exports/<dataset_package_id>/
├── import-summary.json
├── import-summary.json.sha256
├── db-snapshot.db
├── db-snapshot-metadata.json
├── packet-if-export-spec-v2.json
└── runs/<run_id>/
    ├── verified-collection-manifest.json
    ├── verified-collection-manifest.json.sha256
    ├── run-manifest.json
    ├── run-manifest.json.sha256
    └── evidence/
        ├── session-snapshot.json
        ├── feature-qc.json
        ├── pcap-inventory.json
        └── source-evidence.json
```

**PCAP 원본은 복사·이동·삭제하지 않는다.** `pcap-inventory.json`에 파일명·크기·
SHA256·Segment 식별자만 기록하고 원본은 `data/pcap/processed`의 기존 보관 절차를
따른다.

## 8. Dataset v2 Export

생성된 Export Spec을 그대로 쓰고 **같은 Package의 Snapshot을 `--db-snapshot`으로
직접 지정한다.** 같은 값을 다시 손으로 입력하지 않는다.

```bash
PACKAGE=/home/pi/iot-edge-zero-trust/data/exports/packet-if-v2-verified-001

python -m ai.export_packet_if_dataset \
  --output "$PACKAGE/packet-if-dataset-v2.csv" \
  --manifest-output "$PACKAGE/packet-if-dataset-v2-manifest.json" \
  --spec "$PACKAGE/packet-if-export-spec-v2.json" \
  --db-snapshot "$PACKAGE/db-snapshot.db"
```

Dataset Manifest는 **Package Root에 둔다.** `run_manifest_ref.relative_path`가
Manifest Directory 기준 상대경로이므로 다른 위치에 쓰면 참조가 풀리지 않는다.

`--db-snapshot`은 환경변수 편의 기능이 아니라 계약이다.

- 절대경로만 받는다. 상대경로는 `resolve` 전에 거부한다.
- `mode=ro` + `PRAGMA query_only=ON`으로 열어 Export가 DB에 쓸 수 없다.
- 실제 파일 SHA256을 계산해 Export Spec의 `db_snapshot_sha256`과 대조한다.
- 각 Session의 Collection Manifest에 기록된 `db_snapshot_sha256`과도 대조한다.
- 결과 Dataset Manifest 최상위에 `db_snapshot_sha256`을 보존한다.

Export Spec에 `db_snapshot_sha256`이 있는데 `--db-snapshot`을 생략하면 Export가
거부된다. 어떤 DB를 읽었는지 증명하지 못한 Dataset은 만들지 않는다.

Dataset Load 시 `Dataset → Run Manifest → Collection Manifest → Evidence` SHA256
연쇄와 아래 Session 필드 일치가 자동 검증된다. 어느 한 단계라도 어긋나면 Load가
실패한다.

```text
split, traffic_label, collection_slot_id, source_capture_group_id,
normal_policy_version, firmware_version, payload_schema_version,
background_traffic_present, source_commit_sha, capture_filter
```

## 9. PASS / HOLD / FAIL 판정

| 결과 | 의미 | 조치 |
| --- | --- | --- |
| PASS | 17개 전부 검증 통과 | `--write` 진행 |
| HOLD | 필수 Provenance 값 미확인 | 노션·소스에서 값 확정 후 재실행. 추정값 입력 금지 |
| FAIL | Session·PCAP·Split 검증 실패 | 원인 해소 전 진행 금지 |

FAIL 사유 예: Session 미완료, `READY`·`FAILED` Segment 존재, Window Gap·중복,
Feature와 Segment Window 불일치, 적격 INBOUND Row 없음, PCAP 누락·이름 불일치,
Slot·Run ID 중복, Split 누수, 기존 Package 존재.

## 10. Session 53 한계

```text
sender_reported_packets  = 960
gateway_observed_packets = 880
feature_packet_count     = 880
observation_gap_packets  = 80
observation_gap_cause    = UNRESOLVED
```

ESP32의 `udp.endPacket()==1`은 **수신 ACK가 아니다.** 960과 880의 차이를 Wi-Fi
손실, ESP32 실패, Raspberry Pi Drop 중 무엇으로도 단정하지 않는다. Dataset Ground
Truth는 Gateway가 실제 관측하고 Feature와 일치한 **880개**다.

공격 Test Row 수가 적으므로 결과는 **실제 ESP32 공격 Offline Pipeline 검증**으로
표현한다. 이 한 Session만으로 일반화된 공격 탐지율을 주장하지 않는다.

Session 53 수집 당시 Firmware는 Payload Schema Version을 Serial에 출력하지 않았다.
`phase5-packet-rate-udp-payload-v1`은 운영자가 Firmware Source를 읽고 사후에 부여한
이름이며, Manifest의 `firmware_reported_payload_schema_version`은 `null`이다.

```text
payload_schema_provenance = RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY
```

**이 Importer는 PCAP Payload Byte를 파싱하지 않는다.** PCAP에 대해 수행하는 것은
존재 확인, 크기, SHA256, 파일명 Metadata 대조까지다. 어떤 Packet이 선언된 Schema와
일치하는지는 검사하지 않는다. 따라서 이 값은 **파일 Inventory로 뒷받침된 운영자
진술**이지 Payload 내용의 자동 검증 결과가 아니다.

보고서나 발표 자료에 "Payload 구조를 자동 검증했다"고 쓰지 않는다. 실제 Payload
구조 검증이 필요하면 별도 작업으로 구현한 뒤 Provenance 값을 다시 올린다.

## 11. Rollback

- 게시되지 않은 임시 Directory는 실패 시 자동 삭제된다.
- 이미 게시된 Package를 지우려면 **명시적 승인 후** 해당 Directory만 삭제한다.
- **운영 DB와 PCAP 원본은 어떤 경우에도 수정·삭제하지 않는다.**
- 기존 Package는 덮어쓰지 않는다. 재실행은 새 `dataset_package_id`를 쓴다.

## 12. 이 도구가 하지 않는 것

- 운영 DB `INSERT`·`UPDATE`·`DELETE`
- Detection Checkpoint 변경
- PCAP 수정·이동·삭제
- Trust Score·Device 상태·Firewall·iptables 변경
- Capture·Extractor·Detector 실행
- Dataset CSV 자동 Export
- 모델 학습·Threshold 산정·Artifact 배포

## 관련 문서

- `docs/specs/2026-08-06-phase5-verified-collection-import-design.md`
- `docs/packet-if-runbook.md`
- `docs/packet-if-phase5-evaluation.md`
