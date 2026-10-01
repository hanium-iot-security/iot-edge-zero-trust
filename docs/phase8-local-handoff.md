# Phase 8 — 10/1 로컬 작업과 10/2 장비 확인

개발 출발점: PR #82 / develop `c8ea2bc`.
10/1은 PC에서 계약·반례·수정·검증을 진행하며 실제 Pi 접속·배포·센서 조립은 하지 않는다.

## 1. 오늘의 작업 범위

| 작업 | 산출물 | 다음 확인 |
| --- | --- | --- |
| P8-02 공유 계약 | [기기 정책 v1](contracts/device-policy-v1.md), [가상 응답](contracts/device-policy-v1.examples.json) | 현수·종민·소유 검토 후 담당 구현에 적용 |
| P8-S02 Recovery | 마지막 시도 이후 Runtime 증거, 공용 Lock과 쓰기 Transaction 안 재검증 | Pi의 실제 Rule·DB·Snapshot·API 경로 대조 |
| P8-S03 Capture | 오류 종료·진단 근거·자원 중복 실행 보호 | Pi의 실제 tcpdump·권한·systemd 종료/재시작 확인 |
| P8-01/09 기준선 | 로컬 모델·데이터 인계 묶음의 위치·해시 확인 | Pi 실제 배포 Commit·설정·모델 활성 여부와 비교 |

PR #82에서 추가한 `--immediate-mode`와 승인형 무수집 실패 tail Checkpoint Recovery는
이미 기준 코드에 포함된다. 오늘의 Baseline Recovery는 기기 Trust 상태/점수 복구이며,
Packet Checkpoint 이동과 다른 절차다. P8-S02/03의 로컬 통과를 실장비 완료로 기록하지 않는다.

## 2. 로컬 모델·데이터 기준선

2026-10-01 로컬 파일 10개(모델 3개·Packet metadata/report 4개·인계 archive 3개)의
SHA256을 기록했다. Packet 모델 2개의 model/report 해시가 각각 metadata와 일치하는지
4건을 대조했다. 파일의 존재·무결성 확인이며 새 학습·성능 평가·현재 Pi 실행 확인이 아니다.

| 파일/묶음 | 10/1 확인 | 10/2 이후 확인 |
| --- | --- | --- |
| `ai/models/isolation_forest.joblib` | 기존 로컬 IF 파일과 SHA256 | 실행 경로·버전·Feature·Threshold 및 학습 근거. 동반 metadata가 없어 추정하지 않음 |
| `packet-if-v2-verified-001-p99-py310` | 보관 model/report와 metadata 해시 일치 | 현재 사용/미사용 여부 |
| `packet-if-v2-calib-002-p99-py310` | 보관 model/report와 metadata 해시 일치 | 실제 Pi 모델과 bundle·Threshold·설정 대조 |
| `packet-if-v2-calib-002` 수집 package 및 두 모델 인계 묶음 | archive 파일 해시 기록 | 기존 검증/manifest와 연결, 공식 자료 원본 보존 |

상세 manifest와 테스트 로그는 우민 PC의 로컬 산출물 폴더에 보관한다. 원격 Git에는
모델·DB·PCAP·운영 설정을 포함하지 않는다. 팀 공유 증적 보관 위치는 담당자끼리 정하고,
필요한 자료는 검토 후 별도 전달한다. 로컬 보관만으로 팀원이 자료를 받은 것으로 기록하지 않는다.

## 3. 10/2 장비 점검 순서

1. **관측:** Pi의 Commit·미커밋 변경 유무·실행 중 서비스·활성 탐지 단계·실제 모델 경로와
   해시·tcpdump 버전을 기록한다. 로컬 develop과 같다고 가정하지 않는다. 설정 기록에서
   비밀번호·관리자 키는 제외한다.
2. **보존:** 운영 변경 전에 SQLite Backup API 등의 일관된 방식으로 DB를 백업하고
   integrity/FK·파일 해시 및 복사본 열기를 확인한다. 쓰기 중 DB 파일 하나만 복사하지 않는다.
   코드·설정·Broker ACL·서비스 상태·현재 방화벽 규칙도 함께 보존한다.
3. **최신성:** 새 MQTT 수신 → Feature → 활성 Detector → Trust 완료 시각을 두 번 이상
   비교한다. 비활성 IF의 오래된 checkpoint는 장애로 취급하지 않는다. API 성공만으로 통과하지 않는다.
4. **복구 판단:** 실제 DROP·DB Rule·해제 요청·Snapshot 시각을 대조한다. 마지막 시도 이전
   또는 같은 초의 Snapshot, 관측 불가·잔존 규칙은 HOLD다. Baseline 복구는
   [전용 Runbook](baseline-recovery-runbook.md), Packet 공백은
   [Checkpoint Runbook](packet-checkpoint-gap-recovery-runbook.md)을 각각 따른다.
5. **후보 적용·재검증:** 검토된 Commit과 백업을 확보한 후에만 적용한다. API·Observer·Worker의
   Firewall Lock 경로가 동일한지 확인한다. 실제 tcpdump 옵션·오류 로그·drop 통계·Capture
   중복 시작 거부·systemd 종료/자식 정리·재시작을 점검한다. 로컬 모의 검증으로 대신하지 않는다.
6. **Pico 준비:** USB 인식 → MicroPython 등 선택한 펌웨어 준비 → 핀 표기/전압 확인 →
   BME280 I²C 배선 → 직렬 센서 측정을 진행한다. 운영 MQTT 송신은 등록/PENDING 감점 제외와
   수집용 후보 배포가 검증된 뒤 시작한다. 센서 측정 오류와 통신 오류를 구분한다.

각 단계의 기록은 `확인 시각 / 대상 Commit·설정 / 기대값 / 실제값 / PASS·HOLD / 근거`
형식으로 남긴다. 저장공간·활성/미처리/공식 PCAP를 확인하고 보존 자료를 자동 삭제하지 않는다.
실제 처리 재개나 안전 조건이 불확실하면 새 공식 정상 수집을 HOLD하고 로컬 개발은 계속한다.

## 4. 팀 병렬 작업과 완료 구분

현수는 P8-S01 구형 Trust 차단, 종민은 P8-S04 MQTT 원본/해석과 Migration 설계,
소유는 P8-S05 기존 화면 수정에 독립 착수할 수 있다. 공유 계약의 새 등록 API·정책 엔진·
UI는 P8-03~07에서 구현하며 이 PR의 신규 동작으로 설명하지 않는다.

10/1 PR에는 실행한 테스트 명령과 결과·기존 실패 반례·Windows/POSIX 검증 범위를 기록한다.
실장비 미실행은 그대로 남기고, P8-01/09 전체 및 P8-S02/03 실장비 완료 체크는 10/2 이후
실제 증거가 확보된 항목에만 적용한다.
