# Packet 손실 구간 승인 복구

같은 RUNNING Capture Session 안의 10초 `FAILED/PARTIAL_CAPTURE` 구간 때문에 필수
Packet Stage와 Trust가 대기하는 경우에 사용한다. 자동으로 실패 구간을 건너뛰지
않으며, 관리자가 해당 손실 구간을 확인하고 명시적으로 승인한다.

기존 Session 간 `gap-recovery`·`live-resume`과 별개의 명령이다. Migration 005와
기존 감사 기록은 수정하지 않는다. 먼저 Migration 008을 적용한다.

## 적용 조건

- Packet Rule·Packet IF가 같은 실패 구간 시작 경계에서 대기한다.
- 대상은 실제 PCAP가 보존된 정확히 10초의 `FAILED/PARTIAL_CAPTURE` 한 구간이다.
- 실패 구간의 Packet Feature, 다른 Session의 겹치는 구간 또는 중복 Window가 없다.
- 기존 연속 Prefix와 바로 다음 정상 `PROCESSED/EMPTY` 구간을 검증할 수 있다.
- 이전 손실 구간은 유효한 승인 감사 기록이 있어야 한다. 뒤쪽의 다른 실패 구간은
  별도로 승인하며, 사이의 정상 데이터는 먼저 처리한다.

명령은 두 Packet Checkpoint의 완료 경계만 실패 구간 끝으로 함께 옮긴다.
`last_processed_id`, 실패 상태·원본 PCAP·오류·Feature·기존 탐지/Trust/Firewall 이력은
보존한다. Orchestrator는 MQTT·Trust를 승인 경계까지 먼저 처리한 다음 정상 Tail을
이어 처리한다. 이는 패킷 손실 동안의 탐지가 완료됐다는 의미가 아니다.

승인된 손실을 포함한 Session을 종료한 뒤에도 기존 Session 간 `live-resume`은 같은
감사 검증으로 Source의 처리 경계를 확인한다. 재시작 시 미승인 구간은 계속 HOLD한다.

탐지 재개를 위한 준비 경계와 학습 자료의 수집 품질은 별도로 검증한다. Packet IF
Dataset 내보내기는 모든 Segment가 오류 없는 `PROCESSED/EMPTY`인 Session만
허용한다. 복구를 승인해도 `FAILED`를 포함한 Session은 학습용으로 내보내지 않는다.
유지보수 중 수신을 일시 정지했다면 메시지 순서·재연결·저장 오류를 확인하고,
기록 시각이 지연될 수 있는 해당 Session을 정상 학습·성능 평가 자료에서 제외한다.

## 작업 순서

1. API·MQTT 수집·Capture는 유지하고 Detection Orchestrator와 Packet Extractor
   timer/service를 중지한다. 수동 Packet Detector 실행도 중지한다. 실제 배포의
   lock 경로와 서비스 이름을 확인한다.
2. SQLite 일관된 백업과 원본 PCAP/sidecar를 보존한다. `output/` 등의 Git-ignored
   디렉터리에 작업 자료를 저장한다. PCAP에는 자격증명이 포함될 수 있어 원격 Git에
   올리지 않는다.
3. 복사 DB에서 Migration 재실행, Plan/Execute, MQTT·Trust Catch-up, 정상 Tail 처리와
   다음 미승인 실패에서의 대기를 검증한다. 복사 DB에 운영 Firewall Worker를 연결하지
   않는다.
4. 운영 DB의 정확한 Session UUID·실패 Segment ID·원본 파일로 새 Plan을 만든다.
   코드 Commit과 작업 트리는 고정하고, Plan의 승인자·사유·경계·두 Checkpoint·증거
   SHA256을 검토한다. Dry-run은 DB를 변경하지 않고 비공개 Plan과 증거 사본만 생성한다.
5. 승인한 Plan으로 Execute한다. 공유 Runtime Lock → 검증된 SQLite 백업 →
   `BEGIN IMMEDIATE` 재검증 → 두 Checkpoint·단일 Audit 원자적 Commit 순서다.
6. Extractor timer와 Orchestrator를 재개한다. Checkpoint 전진, 필요한 Event의 처리,
   점수·차단 이력, 승인되지 않은 다음 공백의 대기를 확인한다.

```bash
mkdir -p output/packet-gap-recovery
chmod 700 output/packet-gap-recovery

venv/bin/python -m edge.detection.run_packet_segment_gap_recovery dry-run \
  --db-path backend/data/iot_security.db \
  --repository-root . \
  --capture-session-id '<실제 Session UUID>' \
  --failed-segment-id '<실제 Segment ID>' \
  --pcap-path 'data/pcap/failed/<해당 PCAP 파일>' \
  --approved-by '<관리자>' --reason '<손실 증거 확인 및 재개 사유>' \
  --artifact-dir output/packet-gap-recovery \
  --plan-output output/packet-gap-recovery/plan.json

venv/bin/python -m edge.detection.run_packet_segment_gap_recovery execute \
  --db-path backend/data/iot_security.db \
  --plan-file output/packet-gap-recovery/plan.json \
  --confirm APPLY-PACKET-SEGMENT-GAP
```

Execute는 실제 POSIX Runtime Lock이 필요하므로 Pi/Linux에서 실행한다. 새 실행은
새 Plan 파일과 작업 디렉터리를 사용한다. 같은 Segment는 중복 승인할 수 없다.
코드·증거·Checkpoint가 변경됐거나 백업 검증이 실패하면 DB 변경 없이 중단한다.
`database changed during backup`이면 백업과 운영 Writer가 겹친 것이다. MQTT 원본
수집과 Capture를 유지하면서 Feature Producer·Metrics 등 재개 가능한 Writer를 잠시
중지하고, 실제 기록 간격을 확인한 뒤 새 Plan으로 실행한다. 충분한 간격이 없으면
HOLD를 유지한다. 별도 승인 없이 수신을 중지하거나 `data_version` 검사를 해제하지 않는다.
Commit 후 결과 파일 기록/검증에 실패하면 종료 코드 3, `database_committed=true`,
`hold_required=true`를 반환한다. 서비스는 중지 상태로 유지하고 Audit·백업·현재 DB를
대조한다. **자동 백업 복원이나 실패 구간 EMPTY 변경으로 진행하지 않는다.**

## 재발 관측

`PCAP_BUFFER_SIZE_KIB`는 tcpdump 캡처 버퍼 크기이며 기본 4096 KiB, 허용 범위
64~65536 KiB다. 기존 Capture Filter·10초 Window·손실 검증은 유지한다. 버퍼를
늘려도 모든 손실이 해결된다고 가정하지 않는다. Window별 Drop·시작 지연·수집
시간과 CPU/I/O·디스크 상태를 함께 확인하고, 변경 후 정상 Soak 결과를 기록한다.
