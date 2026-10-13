# 정상 후보의 범위 편입 계약

2026/10/9 제안, 2026/10/12 심사 도구(`ai/normal_admission.py`) 구현. 원본의 학습·전체 Session 승인 false, 미배정 Split과 출처 상태를 보존한다. 별도 사전 결재를 기다리는 절차를 추가하지 않는다.

## 구현된 심사 도구

```
python -m ai.normal_admission --packages-dir <압축 해제 폴더> --request request.json --output-dir <새 폴더>
```

각 Run의 후보 QC(`ai.export_normal_collection`)를 새 폴더에 재실행하고, 아래 표의 계약 중 후보 QC가 판단하지 않는 항목을
검사해 `admission-report.json`을 쓴다. **이 도구는 어떤 승인도 발급하지 않는다.** `training_approved`와
`whole_capture_session_approved`는 항상 false다. 입력 폴더는 읽기 전용이고 출력 폴더는 새 폴더여야 한다.
종료 코드는 `BOUNDED_ELIGIBLE` 0, `HOLD`·입력 오류 2다.

요청(`normal-admission-request-v1`, 알 수 없는 필드는 거부): `runs`(`run_dir`, `manifest_sha256`),
`final_snapshot`(`path`, `sha256`, 입력 폴더 안의 COMPLETED 사본), `device_specs`(기기별 `firmware_id`,
`payload_schema`(`esp32-telemetry-v1`/`pico-bme280-v1`), `profile`, `effective_from`, 증거 `kind`·`sha256`·`observed_at`),
`slots`(`collection_slot_id`, `run_id`, `split`).

검사: 후보 QC 재현과 원본 불변, 단일 원본 그룹·Run 비중복, 그룹의 Split 교차 금지와 slot↔Run 일대일 대응, 기기 규격 집합의
Run 일치와 실제 payload 키 대조, 규격 효력·증거 시각이 Run 시작 이전일 것(후속 증거의 소급 거부), 최종 Snapshot의 SHA·
COMPLETED·그룹 일치, Run 구간 안 실패는 HOLD, 구간 밖 실패는 `whole_session_eligible=false`로 공개하고 구간 편입은 유지,
후보와 최종 Snapshot의 선택 구간 행 동일성. 증거 해시는 형식만 검사하며 증거 파일의 내용은 승인 단계에서 확인한다. 150분 자료처럼 설치 증거가 없으면 `HOLD`가 정상 결과다.

범위 밖: Profile별 QC 정책과 100B 필터 교체, Packet 외부 평가 경로, 승인 기록 발급.

## 먼저 구분할 범위

기존 150분은 Session 90(`781ff358-b227-45c5-94c8-472eb1e4c73e`)의 2026/10/4 UTC `[12:15:40,14:45:40)` 선택 구간이다. 네 Run의 후보 QC는 통과했으며 봉인 `after.db`는 당시 RUNNING 상태를 보존한다. 네 Run을 네 독립 그룹으로 세지 않는다.

후속 개발 사본에서 Session 90은 COMPLETED지만 전체 범위에는 실패 Segment ID 35478이 있다. 실패 Window는 같은 날 UTC `[15:13:20,15:13:30)`, 사유는 `PARTIAL_CAPTURE`이며 선택한 150분 밖에 있다. 최종 종료 사본을 연결해도 실패가 사라지는 것은 아니다. 현 공식 Importer/Packet Exporter의 전체 Session 검사는 이런 실패를 거부한다.

따라서 선택 구간의 후보 QC와 전체 Session 적격성을 별도로 기록해야 한다. 실패 행을 삭제하거나 Session 상태를 바꾸어 전체 정상으로 편입하지 않는다.
최종 사본의 SHA256과 WAL/SHM 없는 독립 사본 상태는 읽기 전·읽은 후·심사 보고서 작성 직전에 확인한다. 검사 도중 사본이 바뀌면 HOLD를 기록한다.
이 심사 도구는 PR 119의 Profile별 QC API(`qc_profiles`)가 먼저 있어야 한다. 각 Run에 포함된 기기의 선언 Profile을 그대로 재검사에 전달하며,
지원하지 않는 Profile은 HOLD로 처리한다. P1 주기 허용이 다른 payload 규격의 허용이나 학습 승인을 뜻하지 않는다.

## 첫 구현에 필요한 입력과 검사

| 항목 | 필요한 계약 |
| --- | --- |
| 원본 | Run ID, Manifest·MQTT 원본/CSV·Packet CSV·봉인 DB의 경로와 기대 SHA256, 실제 Capture PK·UUID |
| 선택 | UTC `[start,end)`와 대상 기기. Raw는 Gateway 수신 시각, Feature/Packet은 완전한 10초 Window로 선택 |
| 기기 | 본문 ID·Topic·등록 기기·효력 시점 IP/정책과 ESP32/Pico별 형식·단위·설치 증거 대조 |
| 품질 | 순번·uptime·원본 길이/바이트·선택 건수·Capture 진단·INBOUND 귀속·경계 제외 사유 보존 |
| 종료 | Run의 봉인 사본과 최종 COMPLETED 사본·계획 종료 감사 분리. 구간 밖 실패도 공개 |
| 그룹 | 같은 Session의 다른 Run·기기·MQTT/Packet은 한 실제 그룹. Train/Validation 슬롯은 독립 실제 그룹에 연결 |
| 판정 | 운영 사전점검, 후보 QC, 공식 편입, 학습 승인, 전체 Session 승인 각각 기록 |

기존 봉인 자료나 격리된 시험 사본에서 이 선택·검사 경로를 확인한 뒤 긴 P0 후보를 준비한다. P1/P2는 Profile별 공식 QC가 준비되기 전 본 Train에 포함하지 않는다. 모델 생성이나 최종 공격 Test 전체 완료를 첫 후보의 선행 조건으로 늘리지 않는다.

## 기존 자료에서 확인된 호환 문제

P0/P1/P2 예비 수집은 각각 180초이며 모두 Session 108의 한 개발 그룹이다. 세 Run을 서로 다른 학습·검증 그룹으로 나누지 않는다. 기기별 공개 파일을 나중에 확인한 결과를 과거 설치 상태의 인증으로 소급하지 않는다.

기존 MQTT Export의 숫자/유효성 필터를 재현하면 Pico의 150분 선택 540행과 예비 세 Run 54행, 총 594행이 평균 크기 20~100B 및 최대 크기 100B 조건에서 제외된다. 이는 현재 운영 상태·유지보수 제외까지 실행한 공식 Export 결과는 아니다. 고정 100B 학습 필터 제거 방향, 펌웨어 전송 안전 상한, Rule 경곗값을 각각 검토한다.

INBOUND Packet 후보는 실제 Capture 시간으로 정규화한 6특징 변환을 통과했다. 네 150분 Run은 180×6·180×6·180×6·1080×6, 예비 세 Run은 각각 54×6이다. 숫자 변환 성공은 공식 Dataset 검증이나 모델 학습 승인을 뜻하지 않는다.

## 반례 시험

범위의 시작 포함·종료 제외, 부분 Window 거부, ID/Topic 불일치, 내부 순번 손실·중복·uptime 역전, SHA/바이트/길이 변조, 잘못된 JSON/숫자는 기존 후보 QC 시험(`tests/test_normal_collection_export.py`)이 다룬다. 같은 그룹의 Split 교차, 종료 증거와 구간 밖 실패, 후속 설치 증거의 소급 사용, 기기 규격 바꿔치기는 `tests/test_normal_admission.py`가 합성 3기기 사본으로 검증한다. 실제 압축본·COMPLETED 최종 사본에 대한 확인은 수령 후 별도로 기록한다.

이 검토에서 일곱 Run의 원본 42파일 전후 SHA는 모두 동일했다. 상세 파일 목록·건수·해시 근거와 원본 압축본은 우민의 보관 자료 및 종민 인수인계 페이지에서 연결한다. 원본·정책·공식 승인·Dataset·모델을 변경하지 않았다.
