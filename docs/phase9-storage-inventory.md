# Phase 9 저장 공간 목록과 정리 미리보기

`edge.maintenance.storage_inventory`는 명시한 경로의 용량·원본 참조·보존 사유를 JSON으로 출력한다. 수집 중지, 파일 이동·삭제, DB 행 변경, 자동 retention은 수행하지 않는다. DB Migration이나 새 서비스도 없다.

```powershell
python -m edge.maintenance.storage_inventory inventory --database backend/data/iot_security.db --reference-root data/collections --backup-root data/backups
python -m edge.maintenance.storage_inventory cleanup-dry-run --database backend/data/iot_security.db --reference-root data/collections --backup-root data/backups
```

예시의 경로는 실제 존재하는 수집/백업 위치로 바꾼다. 인자는 현재 작업 디렉터리 기준이며 PCAP 기본 위치는 `--project-root`(기본 현재 디렉터리)의 `data/pcap`이다. 사용자 지정 PCAP 위치는 `--pcap-root`, Snapshot 위치는 `--snapshot-root`로 지정한다. 기본 Snapshot 위치는 `data/runtime`이다. `--reference-root`, `--backup-root`, `--snapshot-root`는 여러 번 줄 수 있다. 중첩 루트는 먼저 방문한 종류로 한 번만 집계되므로 구분된 루트를 사용한다.

두 명령은 같은 읽기 전용 관측 결과를 낸다. `cleanup-dry-run`도 삭제 계획이나 승인 파일을 만들지 않는다. 모든 항목의 `cleanup_status=HOLD`, `reference_protection_complete=false`, `deletion_supported=false`를 유지한다. 정상 스캔의 종료 코드는 0, 누락·읽기 실패·미지원 참조·개수 제한으로 부분 조회되면 2다. 종료 코드 0은 삭제나 학습 승인이 아니다.

## 관측 범위

- DB, WAL/SHM, PCAP, 수집 진단 sidecar, Snapshot, 백업, 참조 문서 크기를 구분한다. WAL/SHM과 선택적인 기본 runtime 폴더가 없는 경우는 정상이다.
- PCAP은 processed로 이동해도 sidecar가 ready에 남을 수 있다. 전체 지정 PCAP 루트에서 원래 파일명으로 `paired_paths`를 연결한다. 각 실제 경로를 별도로 기록하고 ready 폴더 전체를 삭제 대상으로 취급하지 않는다.
- DB를 `mode=ro`, `query_only`의 짧은 트랜잭션으로 읽는다. 목록에 있는 파일의 Capture Session/Segment만 파일명 인덱스로 조회하고, 기존 Trust 보상·Packet 복구·계획 정비 감사의 경로·해시·Session 참조를 연결한다. 파일 해시 계산 중에는 DB 트랜잭션을 유지하지 않는다. 일반 SQLite 읽기 잠금/SHM 조정은 가능하며 `immutable=1`로 WAL을 무시하지 않는다.
- 명시한 참조 루트의 8MiB 이하 JSON에서 경로·파일명·SHA·Session UUID 문자열을 보수적으로 대조한다. 후보가 HOLD 또는 `training_approved=false`여도 참조를 보호한다. 참조 문서의 본문·센서 payload는 출력하지 않는다. 비JSON·과대 JSON은 내용/해시를 읽지 않고 미지원으로 남긴다.
- RUNNING/FAILED Session, READY/FAILED Segment, incoming/ready/failed/samples, 임시 파일, DB/백업/참조 파일은 보존 사유에 표시한다. Session 미상·참조 검사 실패도 HOLD다. 완료된 Session의 processed 파일도 DB 참조가 있으면 명시한다.
- 정상 일반 파일은 전체 SHA256을 계산하고 전후 파일 식별자·크기·수정 시각을 확인한다. DB/WAL·incoming·임시 파일은 살아 있는 파일로 취급해 해시를 생략한다. `verified_copy_paths`는 지정 백업 루트에서 전체 해시가 같은 별도 일반 파일이며 hardlink를 사본으로 세지 않는다. 사본의 별도 디스크 보관이나 백업 정책 충족까지 인증하지는 않는다.
- symlink/Windows junction과 그 하위 경로를 따라가지 않는다. 기본 최대 파일 수는 10,000이며 초과하면 부분 목록임을 표시한다. 해시 읽기 자체가 저장장치 부하를 만들므로 자동 polling용이 아니다.

JSON 값 대조만으로 모든 Manifest 형식·간접 참조·동시 참조 추가를 완전히 증명할 수는 없다. 따라서 미참조처럼 보이는 파일도 삭제 가능으로 분류하지 않는다. 실제 삭제 기능을 추가하려면 참조 변경과 정리가 공유하는 배타성 및 삭제 직전 재검사가 먼저 필요하다.

## 용량과 증가량

`--planned-bytes`, `--snapshot-bytes`, `--reserve-bytes` 세 값을 모두 지정하면 예정 수집 + 동시 Snapshot/백업 + 예비 용량을 합산해 현재 여유 공간과 비교한다. 부족하면 `capacity.status=HOLD`, 값이 빠지면 UNKNOWN이다. 이는 **project-root가 있는 볼륨만의 관측**이며 다른 볼륨의 PCAP/백업 공간이나 신규 수집 시작을 승인하지 않는다. 기존 수집 preflight의 보호 조건은 유지한다.

이전 JSON을 `--previous`로 넘기면 동일 경로·종류의 완전한 관측 두 개에 대해서만 `growth_bytes`를 계산한다. 증가량이 음수일 수도 있으며 이것을 자동 정리나 데이터 손실로 단정하지 않는다. 모든 파일이 한 시점에 고정된 원자 스냅샷은 아니다.

## 로컬 검증과 운영 잔여

임시 DB/파일에서 다른 폴더의 PCAP·sidecar 연결, 활성 Session 보호, Manifest·정비 감사 참조, 별도 사본 SHA, 원본 DB/PCAP 보존, WAL 최신 커밋 조회, 잘못된 참조·누락·스캔 제한을 확인한다.

```powershell
python -m pytest tests/test_storage_inventory.py -q
```

Pi 운영 디스크에서는 아직 실행하지 않았다. 실제 참조/백업 경로와 해시 읽기 시간·수집 부하는 배포 전 확인한다. Journal에만 있는 Capture timing은 이 도구로 보관되지 않으므로 기존 증거 보존 절차를 유지한다.
