# Phase 9 Pi 없는 후속 작업

기준은 #118·#127 병합 후 develop `0925f35`다. 우민 담당의 남은 작업을 디스크 관측 → 방화벽 대조 → 그래프 조회 API → 실제 학습 준비 확인 순으로 진행했다.

| 작업 | 이번 변경 | 남은 연결/검증 |
| --- | --- | --- |
| 디스크 목록·정리 미리보기 | [읽기 전용 CLI](phase9-storage-inventory.md), 참조·사본·보존 사유 | Pi 실제 경로·조회 부하 확인. 실제 삭제는 제공하지 않음 |
| 방화벽 주기 대조 | [기존 5초 관측 확장](phase9-firewall-consistency.md), 현재 DB와 실제 규칙 비교·경고 | Pi timer·실제 규칙과 API 대조, 부하 확인 |
| 그래프 API | [페이지 기준 ID와 Capture Window 조회](phase9-graph-read-api.md) | 소유의 화면 연결과 세 기기 실제 응답 대조 |
| 실제 학습·모델 비교 | 기존 trainer·입력 계약 유지, 로컬 후보 준비 여부 확인 | 독립 정상 그룹·공식 편입/QC 근거 준비 후 실행 |

이번 변경에는 Migration, 운영 DB/모델 교체, Pi 접속·서비스 재시작, 실제 차단/해제, 프론트엔드 변경이 없다. 로컬 검증은 임시 DB·파일·가짜 방화벽 관측으로 수행하며 운영 검증의 대체 증거로 쓰지 않는다.

## 학습 준비 확인

2026/10/13 로컬에 보관된 Phase 9 preflight/P1/P2 후보 Manifest를 확인했다. 세 후보 모두 180초, QC PASS지만 **같은 `source_capture_group_id`**이고 `split=UNASSIGNED`, `training_approved=false`다. 서로 다른 Profile이나 Run이라는 이유로 Train·calibration·validation의 독립 그룹으로 재해석하지 않는다. 기존 150분 후보도 별도 공식 편입 근거 없이 승인 자료로 바꾸지 않는다.

이 확인은 알려진 후보 디렉터리의 제한적 조사이며 다른 위치의 적격 데이터가 전혀 없다는 선언은 아니다. 실제 trainer 실행이나 Threshold 선택·모델 비교는 수행하지 않았다. 기존 [학습 입력 계약](phase9-mqtt-if-training.md)에 따라 독립 Train·calibration·validation 그룹, admission request/report, Run Manifest, QC report, Feature CSV와 고정 해시가 준비되면 PC에서 진행할 수 있다. 추가 정상 수집은 Pi가 필요하다.

## 로컬 검증 결과

Windows / Python 3.10.11에서 저장 공간 15 passed·1 skipped(호스트 symlink 권한), 그래프 관련 5파일 86 passed, 방화벽·기존 복구/해제 관련 9파일 176 passed를 확인했다. 새 라우터를 함께 등록한 Backend 전체 및 Worker runner 회귀는 299 passed였다. 각 범위에 중복 테스트가 있으므로 수량을 합산하지 않는다. 전체 저장소 회귀는 이번에 다시 실행하지 않았다.

#128 병합 전 검토에서 명시한 Snapshot 경로 누락을 부분 조회로 보고하고, 파일 수 제한에 도달하면 디렉터리 전체를 미리 정렬하지 않고 순회를 중단하도록 수정했다. 저장 공간 회귀에 두 사례를 추가했고, 방화벽·관측 Snapshot·Recovery 안전성 3파일도 다시 실행해 83 passed를 확인했다.

## 이후 순서

1. 이번 변경을 develop 기준으로 검토한다. 프론트 담당은 새 조회 계약으로 연결하되 선택 변경 시 요청 취소·ID 중복 제거·부분 조회/오류 표시를 유지한다.
2. Pi 사용이 가능해지면 #123 정비 복구의 운영 검증을 이어간다. 기존 승인·Session·Boot·체크포인트를 현재 상태로 간주하지 않고 다시 확인한다.
3. 현재 스키마/설정을 확인해 필요한 Migration, Broker 대상, 모델 pin과 OFF/OBSERVE 활성화를 순서대로 검증한다.
4. 실제 격리·해제·재부팅 복원 및 수집과 API/관측 동시 부하를 검증한다. 독립 정상 수집은 이 운영 점검 구간과 분리한다.
