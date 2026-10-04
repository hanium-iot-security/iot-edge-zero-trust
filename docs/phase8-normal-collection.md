# Phase 8 정상 통신 후보 수집

이 도구는 실행 중인 세 기기를 유지하면서 지정한 미래 시간 구간의 MQTT 원본,
Feature, PCAP, Capture 진단과 DB Snapshot을 보존한다. 서비스·기기·정책·모델·
Checkpoint를 변경하지 않는다. 결과는 정상 기준선과 품질 검토를 위한 후보이며,
공식 Verified Collection이나 학습 승인 Package가 아니다.

## 준비와 실행

Pi에서 검토된 수집 도구를 사용하고 운영 Checkout을 작업 Directory로 둔다.
Migration 009, 정상 수신, ACTIVE 등록·정책, 10초 Feature Window, Packet 탐지 단계와
`TRUST_AI_MODE=observe`를 먼저 확인한다. 보존 Directory는 기존 내용이 없는
프로젝트의 `output/` 아래로 지정하며 최소 1 GiB 여유 공간을 확보한다.

```bash
cd /home/pi/iot-edge-zero-trust
venv/bin/python -m edge.features.collect_normal_candidate \
  --output output/normal-collection-20261004 \
  --phase8-sequence
```

다른 Checkout에서 검토한 도구를 실행할 때는 해당 파일의 절대 경로로 실행하고
`--project-root /home/pi/iot-edge-zero-trust`를 지정한다. 운영 Checkout의 `.env`를
읽도록 실행 Directory를 위와 같이 유지한다. 운영 코드·설정이 실행 중 변경되면
수집은 HOLD로 종료하므로 수집 중 배포하거나 정책을 수정하지 않는다.

| 순서 | 대상 | 시간 |
| --- | --- | --- |
| 1 | Pico WH + BME280 | 30분 |
| 2 | ESP32 #1 | 30분 |
| 3 | ESP32 #2 | 30분 |
| 4 | 세 기기 | 60분 |

각 구간은 시작 시 미리 고정하는 겹치지 않는 `[start_utc,end_utc)`이며 UTC 10초
경계에 맞춘다. 모든 기기는 계속 송신한다. 처음 세 구간도 해당 기기를 대상으로
선택한 **동시 환경의 관측**이며 단독 기기 실험으로 표현하지 않는다.

짧은 사전 검증은 별도 새 Directory에 다음처럼 실행한다.

```bash
venv/bin/python -m edge.features.collect_normal_candidate \
  --output output/normal-collection-smoke \
  --device esp32_01 --device esp32_02 --device pico_01 \
  --duration-seconds 60
```

`seq`·`sequence`와 가동시간은 모델의 직접 입력이 아니다. 수집 첫 순번이 1일
필요는 없으며 구간 내 연속 증가·재부팅 여부를 확인한다. 자릿수에 따른 메시지
크기 증가도 원본 그대로 보존한다. 센서 측정값을 고정하거나 Payload를 줄이지
않는다.

## 보존과 품질 확인

PCAP와 `.capture.json`은 기본 15초 간격으로 별도 복사한다. 봉인된 파일만 읽고
원본은 이동·삭제하지 않는다. READY에서 PROCESSED로 이동 중인 파일은 재조회한다.
기존 증적을 덮어쓰거나 `.tmp` 파일을 정상 PCAP으로 채택하지 않는다.

각 구간 종료 후 활성 Producer·Detector·Trust가 종료 경계를 처리했는지 확인하고,
SQLite Backup API로 일관된 `after.db`를 만든다. Manifest에는 대상·시간·Capture
Group·운영 Commit·수집 도구 Commit/해시·등록 및 정책 Revision·Capture Policy·
펌웨어 출처 확인 상태·파일 해시를 함께 기록한다. 비밀번호·관리자 키는 포함하지
않는다. 물리 기기의 펌웨어와 Gateway 소스가 같다는 사실은 소스 해시만으로
확정하지 않는다.

후보 Export는 원본·완전한 MQTT Window·해당 Capture PK와 시간 범위의 Packet만
선택한다. 기존 MQTT Export의 20~100바이트 조건을 적용하지 않아 Pico의 실제
센서 메시지도 포함한다. AI 경고가 발생했다는 이유로 정상 관측 행을 제거하지
않으며 경고와 실제 점수 반영 수를 별도로 기록한다.

검증 대상은 원본 바이트·길이·JSON·Identity·Topic, 순번·가동시간·수신 주기,
원본과 Feature 건수, 등록 IP와 Packet 귀속, 연속 10초 Capture/Feature Window,
공통 Capture 적격 판정, 실제 Drop 진단, 정책 변경 여부와 파일 무결성이다.
손실·누락·Session 전환·정책/코드/Trust 변경이 생기면 후보를 HOLD로 남기고
불완전 Snapshot과 이미 보존한 파일을 유지한다. 재시도는 새 Run ID와 Directory를
사용한다. Checkpoint 복구는 수집 적격성을 소급 승인하는 수단이 아니다.

`plan.json`과 `progress.json`은 전체 진행 상태, Run별 `manifest.json`과
`qc-report.json`은 개별 결과다. `training_approved=false`와
`whole_capture_session_approved=false`는 품질 검증 통과 후에도 유지한다.

## Phase 9 인계

현재 Capture를 유지해 얻은 네 Run은 동일한 `source_capture_group_id`를 공유한다.
이 Run들을 나눠 Train·Validation·Test로 배정하거나 행을 무작위 분할하지 않는다.
전체 후보 Group은 하나의 용도로 다루고, 독립 평가가 필요하면 별도 수집 Group을
추가한다. 동시 60분 결과를 보고 같은 모델의 Threshold를 사후 변경하지 않는다.

현재 공식 Packet v2 Export/Importer의 완료된 Session·펌웨어·Payload 계약은
그대로 유지한다. Pico를 포함한 공식 Dataset 입장, 물리 펌웨어 출처 확인,
독립 Split·Holdout 계획과 수집 다양성 검토가 끝난 뒤에만 학습자료 승인을 한다.
후보 CSV가 생성되었다는 사실만으로 모델을 재학습하거나 운영 모델을 교체하지 않는다.

DB·PCAP·후보 CSV·진단·운영 설정은 Git 제외 `output/`에 보관한다. 정상 후보
수집 도구와 테스트·문서만 기능 브랜치의 PR로 공유한다.
