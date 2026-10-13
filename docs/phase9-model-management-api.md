# Phase 9 모델 정보·복구 관리 API

모델 원본의 계약을 조회하고, Packet Rule·IF 통합 복구 계획과 실제 감사 기록을
확인하는 첫 API다. 모델 활성화·재학습·기기별 OFF/OBSERVE 저장이나 적용,
HTTP 복구 실행은 포함하지 않는다. P9-06 전체 완료를 의미하지 않는다.

## 모델 정보

`GET /api/models`는 공개 조회다. 서버에 설정된 Artifact만 검사하고 내부 경로,
임의 Metadata 확장 필드, Report 원문·평가 수치는 반환하지 않는다.

Packet IF와 설정된 MQTT IF Bundle은 세 파일을 각각 한 번 읽어 외부 설정의 Bundle SHA, 모델 Version,
개별 모델·Report SHA, Metadata 계약과 Report의 UTF-8 JSON 객체 형태를 확인한다.
API 검사 크기 제한은 파일당 64 MiB이며 센서 Payload·정상 허용 범위 제한과는
관계없다. 기존 추론 Loader도 동일한 역직렬화 이전 검증 Helper를 재사용한다.

`BUNDLE_METADATA_VERIFIED`는 저장된 바이트와 Metadata 계약을 확인했다는 뜻이다.
API는 `joblib.load`, 추론 또는 모델 활성화를 호출하지 않는다.
`report_semantics_verified`, `model_deserialized`, `inference_verified`는 모두 false다.
Report 내부 평가 수치·Metadata와의 수치 일치, 학습 품질·학습 승인,
현재 Orchestrator의 라이브러리 호환성·모델 로딩을 인증하지 않는다.

설정이 일부라도 없으면 `UNCONFIGURED`, 읽을 수 없는 파일은 `UNAVAILABLE`,
계약·Hash 불일치 등은 `INVALID`다. MQTT의 `MQTT_IF_ARTIFACT_DIR`,
`MQTT_IF_EXPECTED_MODEL_VERSION`, `MQTT_IF_EXPECTED_BUNDLE_SHA256`이 모두 비어 있으면
기존 단일 Joblib 경로에 해당하므로 `LEGACY_CONTRACT_UNAVAILABLE`로 반환한다.
세 설정이 있으면 MQTT의 5개 Feature 순서·낮을수록 이상인 점수·엄격한 `<` Threshold와
한 건 Window의 5.0초 대체 간격 의미도 공개 Metadata로 반환한다.
MQTT 정책 Version을 모델 Artifact Version으로 바꾸어 표시하지 않는다.

모든 모델의 `runtime.status`는 `UNKNOWN`이다. API 프로세스의 설정과 최근 이상
이벤트는 실행 중 Orchestrator의 현재 모델 로딩을 대신할 수 없다. 모델은 현재
공유 Detector 단위이며 이 조회가 기기별 모델을 생성했다는 뜻도 아니다.

## 관리자 복구 API

세 경로 모두 기존 `X-Recovery-Admin-Key` 인증을 사용한다. 키 미설정은 503,
누락·불일치는 401이다. 승인 Principal은 서버 설정에서 결정한다.

| 경로 | 동작 |
| --- | --- |
| `POST /api/recovery/packet-pair/plans` | 두 Session의 통합 복구 계획을 신규 파일로 보관하고 검토 가능한 경계·Checkpoint·건너뛸 Session을 반환한다. |
| `GET /api/recovery/packet-pair/{plan_id}` | 계획에 연결된 실제 DB 감사 존재와 Checkpoint를 조회한다. Backup 검증이나 Progress 갱신을 하지 않는다. |
| `POST /api/recovery/packet-pair/{plan_id}/verify` | Root Intent·실제 감사·Checkpoint·Backup 및 기존 Root 진행 기록을 읽기 전용으로 대조한다. |

HTTP 계획 생성은 기존 live-resume 경로만 지원한다. Root CLI의 bounded-replay 및
FAILED 정상 구간 재생 계획은 서버의 계획 경로에 원본 그대로 등록된 경우 GET과
verify로 조회할 수 있다. HTTP에 mode 또는 FAILED 승인 옵션을 보내면 422이며,
조회가 손실 구간 승인이나 새 복구 실행을 대신하지 않는다.

계획 요청은 다음 세 문자열만 허용한다. Session은 소문자 표준 UUID이며 서로
달라야 한다. 사유는 공백만으로 구성할 수 없고 제어 문자 없이 1~1000자다.
Principal, DB·Artifact·저장 경로, Child ID, 적용 옵션을 보내면 422다.

```json
{
  "source_session_id": "11111111-1111-4111-8111-111111111111",
  "target_session_id": "22222222-2222-4222-8222-222222222222",
  "reason": "완료된 수집 Session에서 현재 정상 수집 Session으로 처리를 재개"
}
```

계획 생성 성공은 201이다. `plan_id`는 Pair UUID이고 `plan_sha256`는 Root CLI가
소비할 원본 계획의 SHA다. `can_execute`는 기존 Pair 계획의 사전 조건 결과이며
실행·완료를 의미하지 않는다. 건너뛸 처리 가능 Session이 있으면 기존 CLI의
SHA에 연결된 별도 승인 절차가 그대로 필요하다. 이 HTTP 요청은 그것을 실행하지 않는다.

서버는 다음 설정으로만 경로를 결정한다. 상대 경로는 Repository Root 기준이다.

| 설정 | 기본값 |
| --- | --- |
| `PACKET_PAIR_REPOSITORY_ROOT` | API 패키지가 있는 Repository Root |
| `DATABASE_URL` | 기존 SQLite DB 설정 |
| `PACKET_PAIR_PLAN_DIR` | `output/phase9-packet-pair-api/plans` |
| `PACKET_PAIR_ARTIFACT_DIR` | `data/recovery/packet-pair` |
| `PACKET_PAIR_MANAGER_PLAN_DIR` | `output/phase9-packet-pair-api/manager-plans` |

계획은 `<plan_id>.json`에 신규 공개하며 기존 파일을 덮어쓰지 않는다. 설정·파일의
Symlink/Junction을 거부한다. DB는 기존 파일을 `mode=ro`·`query_only`·단일 읽기
Transaction으로 관측하며 Migration·감사·Checkpoint·Trust를 쓰지 않는다.
GET과 verify 모두 Root `progress.json`, Lock, Journal, Backup을 갱신하지 않는다.

GET의 `COMMITTED_UNVERIFIED`는 해당 Child 감사가 DB에 존재한다는 뜻이다.
정확한 계획·Before/After·Backup·실제 Source ID 소비까지 검증됐다는 뜻은 아니다.
verify는 기존 Pair 감사 검증을 재사용한다. 응답 파일의 `COMPLETE` 문자열만으로
DB Commit이나 복구 성공을 판정하지 않는다.

## Root CLI와 과거 진행 증거

적용·Resume·서비스 중단 및 원상복귀는 기존 Root 관리자 CLI로 수행한다.
`iot-edge-api.service`의 `NoNewPrivileges=true`를 유지하고 API에서 sudo,
서비스 제어 또는 Root 관리자 프로세스를 시작하지 않는다. HTTP apply 경로는 없다.

Root CLI에는 HTTP 계획 원본과 동일한 Pair UUID·Plan SHA, DB·Artifact Root를
사용해야 한다. 선택적으로 Manager Plan을 설정된 Manager Plan Directory의
`<pair_id>.manager.json`에 생성하면 verify가 해당 Manager 승인 SHA·Journal과
Pair 계획의 연결을 확인할 수 있다. 기존 Root CLI 자체의 파일명 규약은 바꾸지 않는다.
다른 위치에 생성한 Manager Plan은 이 API에서 완료 증거를 확인할 수 없다.

`root_progress_verified`는 기존 Root 진행 문서의 SHA·승인·Checkpoint 연결을
읽어 확인했다는 뜻이다. 원래 관측 시각, 경과 초, 45초 기준의 `fresh`도 함께
반환한다. `root_completion_recorded`는 연결된 Manager Journal에 과거 완료가
기록됐다는 뜻이며 현재 완료·서비스 실행을 인증하지 않는다.

따라서 이 API는 과거 완료 기록이 있어도 `APPLIED_VERIFY_REQUIRED`와
`runtime=UNKNOWN`으로 반환하고 `COMPLETE`를 반환하지 않는다. 전체 감사는 검증됐지만
진행 파일이 없으면 `VERIFIED_AUDITS`를 유지하고 Root 진행 미확인을 별도로 표시한다.
Root Intent가 없으면 UNKNOWN/HOLD, 증거가 바뀌면 HOLD다. 비공개 Artifact의
읽기 권한이 없으면 503/UNKNOWN으로 반환하며 권한을 완화하거나 증거를 재생성하지 않는다.
오류 응답에는 내부 경로와 상세 OS 오류를 포함하지 않는다.

계획·상태 응답의 `mode`는 `live-resume` 또는 `bounded-replay`이며,
`replay_end`는 bounded-replay의 보존 데이터 처리 종점을 나타낸다.
`REPLAY_COMPLETE`는 이 종점까지의 재생이 완료됐다는 기록이다. 이후 Session의
실시간 처리 재개나 FAILED 마지막 구간의 건너뛰기 승인을 의미하지 않는다.

| 검증 필드 | 의미 |
| --- | --- |
| `historical_completion_status` | 검증된 과거 관측의 `COMPLETE` 또는 `REPLAY_COMPLETE`. 근거가 없거나 검증이 실패하면 null이다. |
| `historical_completion_source` | 직접 Root CLI의 진행 문서는 `ROOT_PROGRESS`, 연결된 Manager Journal은 `ROOT_MANAGER`다. |
| `historical_completion_recorded_at` | 진행 문서의 관측 시각 또는 완료 Journal을 보관한 시각이다. 현재 런타임 관측 시각과 다르다. |

직접 Root CLI가 남긴 진행 문서는 Manager Journal이 없어도 승인 SHA, 당시의
실행 조건·처리 경계·실제 감사가 일치하고 eligible=true·advances=2이면 과거
`COMPLETE`를 확인할 수 있다. 이 경우 `root_completion_recorded`는 false로
유지해 Manager 기록과 구분한다. 진행 문서의 현재 fresh 여부는 과거 완료와
별도다. 현재 런타임은 계속 UNKNOWN으로 표시한다.

Bounded-replay는 `progress.json`을 만들지 않으므로
`root_progress_status=NOT_APPLICABLE`이다. 연결된 Manager의 REPLAY_COMPLETE
기록을 확인할 때는 계획의 재생 종점, Rule·IF·Trust 및 필수 MQTT 처리 경계,
서비스 복귀 실패 유무를 함께 대조한다. 완료 문서가 없으면 원본 감사가
확인돼도 과거 완료 필드는 null이며, 누락된 live 진행 문서로 오인하지 않는다.

과거 계획 이후 다른 복구가 적용됐거나 현재 계획의 대상·감사·Checkpoint가
원본 Pair 검증 조건을 만족하지 않으면 HOLD를 유지한다. 과거 완료 문서가
있다는 이유로 이 검사를 우회하지 않는다. 후속 복구 이후에도 독립적인
과거 완료를 확인하는 별도 봉인 계약은 이 API에 포함하지 않는다.

이후 실제 Runtime 발행·Freshness 계약, 기기별 모드 Migration 및 적용,
모델 활성화·중단·후보 평가 API는 담당 기능과 연결해 추가해야 한다.

## 검증 기록 — 2026/10/9

Pi Python 3.10.11의 별도 output 시험 디렉토리에서 새 API 64개와 기존 모델 로딩·탐지·계약·API·배포 문서 회귀를 함께 실행해 **167개가 통과했다(20.56초)**. 임시 SQLite DB와 가상 서비스·진행 증거를 사용했다. 저장된 모델 바이트·Backup·Root 진행/Journal·DB의 불변, 잘못된 승인·오래된 완료 기록·부분 적용·경로와 권한 거부를 검증했다. 복사한 시험 코드의 TAR SHA를 로컬과 Pi에서 대조한 뒤 실행했다.

운영 API 서비스 배포·재시작, 운영 DB Migration·복구 적용·모델 활성화는 하지 않았다. 운영 Pi의 Commit `53ec270`과 기존 Boot, 관련 서비스 여섯 개의 활성 상태를 별도 읽기 조회에서 확인했다. 이 결과는 실제 운영 복구나 현재 실행 모델의 인증을 대신하지 않는다.

같은 날 새 모델 정보 Service를 운영 Pi의 기존 설정·모델 파일에 읽기 전용으로 실행했다. Packet Bundle은 `packet-if-v2-calib-002-p99-py310`의 `BUNDLE_METADATA_VERIFIED`로 확인됐고 검사 전후 Bundle SHA가 같았다. MQTT는 `LEGACY_CONTRACT_UNAVAILABLE`, 두 모델의 실제 실행 증거는 `UNKNOWN`으로 유지했다. 이는 운영 Artifact 조회 확인이며 운영 HTTP 서비스 배포나 실행 모델 인증은 아니다.

## 검증 기록 — 2026/10/11

최신 PR108과 PCAP 이동 경합 수정을 합친 관리 API 소스에서 로컬 API 66개와
모델 정보·배포 계약 32개가 통과했다. 강화한 Trust 경계 위조 사례도 재확인했다.

SHA256 `93bd417611b7fe05670e49323b5463f0f49c70acaece7e37b5f6a489d7de054b`의
소스 사본을 Pi의 별도 output 경로에 전송하고 Python 3.10.11에서 복구·Pair·Manager·
Segment gap·API·모델 Loader·Orchestrator·배포 계약 635개를 실행해 모두 통과했다
(185.50초, skip 없음). 이어 Linux CLI·프로세스·flock 안전 검사 44개도 통과했다
(12.47초). 이 시험은 임시 DB·가상 host 근거이며 운영 복구 재실행이 아니다.

같은 Pi의 pi 계정·NoNewPrivileges=1·loopback HTTP로 새 라우트를 별도 실행했다.
실제 모델 파일의 Packet Bundle은 BUNDLE_METADATA_VERIFIED, MQTT는
LEGACY_CONTRACT_UNAVAILABLE, 두 실행 상태는 UNKNOWN이었다. 키 누락·불일치는
401, 잘못된 요청은 422였다. 기존 root-private 복구 경로의 접근 거부는 GET·verify
모두 503/UNKNOWN으로 반환했다. 권한을 완화하지 않았다. 모델·검사 계획·실제 감사
원본과 운영 서비스 PID의 불변, 시험 프로세스 회수·포트 종료까지 17개 검사를
통과했다. 실제 복구 성공 응답은 앞의 fixture 시험으로 검증한 범위다.

이 loopback 시험은 운영 API 서비스 배포와 구별한다. 당시 운영 Pi는 542455f였고,
시험 뒤 다섯 처리 경계가 2026-10-11T05:49:20Z로 전진했으며 세 기기의 수신이
지속됐다. 새 FAILED 구간은 없었다. 운영 DB Migration·모델 활성화·학습은 실행하지 않았다.

## 운영 API 적용 확인 — 2026/10/11

15:03:23~15:03:27 KST에 검증한 코드 `ffa82c00b31ebdfcd621b83aa13d1597bd02b26c`를
Pi에 적용했다. 기존 복구 Commit `542455f`와 PCAP 이동 경합 수정 `d87bfd4`를
포함하는 전진 적용이며 API 서비스만 약 2.74초 재시작했다. Capture·Subscriber·
Broker·Orchestrator·MQTT Builder·Firewall Worker의 PID와 기동 시각은 같았다.
Writer·Subscriber 대기는 각각 0회이며 기존 복구 대기 승인을 재사용하지 않았다.
독립 systemd 작업으로 실행했고 실패 시 Git 자식 회수 확인 후 이전 코드·API를
복원하도록 준비했다. 이번 적용은 성공해 rollback은 실행하지 않았다.

운영 HTTP의 `/api/models`는 200, Packet은 BUNDLE_METADATA_VERIFIED,
MQTT는 LEGACY_CONTRACT_UNAVAILABLE, 두 runtime은 UNKNOWN이었다. 관리자 키
누락·불일치는 401, 올바른 키의 존재하지 않는 계획은 404/UNKNOWN이었다.
기존 root-private 복구 자료의 503/UNKNOWN은 위 별도 loopback 시험 결과이며,
운영에 복구 계획 별칭을 만들거나 자료 권한을 완화하지 않았다.

15:04:52 KST의 읽기 조회에서 다섯 필수 처리 경계가 모두 15:04:40으로 전진했고
ESP32 두 대·Pico의 수신은 각각 5초 이내였다. Session111 RUNNING, 신규 FAILED 0,
복구 감사 69개·기존 설정/Packet 모델 바이트·Boot가 보존됐다. DB Migration,
복구 재적용, 모델 학습·활성화와 방화벽 차단은 하지 않았다. 이 문서의 이후 수정은
배포한 `ffa82c0` 코드의 검증 기록이며 운영 코드 SHA와 구분한다.

## 복구 명령 의존 코드 통합 — 2026/10/11

최종 관측·소유 프로세스 종료 보완 c0c903c를 API 브랜치에 통합했다. 관리 API는 manager의 계획·기존 v1 Journal과 과거 검증 결과를 읽으며 새 verifier나 서비스 제어를 실행하지 않는다. 새 가짜 verifier에 동일한 가짜 서비스 객체를 전달하도록 완료 조회 시험 fixture 한 줄을 보완했다. 수정 전 fixture 오류 9건은 별도 기록하고, 기존 REPLAY_COMPLETE·현재 runtime UNKNOWN·DB/진행/Journal 불변 assertion을 유지한 최종 API·모델 정보·배포 회귀 **98개가 통과했다(173.45초, skip 없음)**. 이 통합 후보는 Pi에 배포하지 않았다. c0c903c 통합 당시 운영 ffa82c0와 이전 운영 검증은 그대로였으며, 공개 부모 CLI 중단·실제 운영 서비스 경계와 배포 전 검증은 PR108에 남아 있었다.

fbdc4ea를 이어받은 당시의 후속 확인: PR108의 full-module/internal-verifier CLI는 Pi 임시 사본에서 manager·pair 175개가 통과했다(68.20초, skip·경고 없음). 실제 child CLI·임시 DB 감사/backup/Git 검사를 사용하며 서비스·runtime·clock과 공통 부모 fixture lock은 시험 값이었다. 당시 API 구현·기존 API 시험·production manager/CLI는 9a9efab와 동일했으므로 기존98개 검증은 그 범위로 유지하고 재실행 숫자를 더하지 않았다. 운영 Pi는 ffa82c0 그대로였으며, 공개 부모 CLI 중단·실제 SSH 단절 서비스 복귀와 새 verifier 운영 배포는 당시 미검증이었다.

이후 PR108 c3f1610에서 공개 verify의 SIGHUP·SIGINT·SIGTERM 처리와 소유 자식/그룹 회수를 보완했다. Pi 임시 사본의 공개 CLI 포함 회귀 **178개가 통과했다(89.05초, skip·경고 없음)**. 이 시험의 서비스 관측은 가짜 값이다. 이어 별도 임시 user-unit을 사용한 public apply·실제 SSH PTY 단절 시험이 **50.547초에 통과했다**. 실제 CLI·잠금·backup·임시 DB commit/감사·nonce 검사를 유지했으며 root 권한 검사와 서비스 이름 대응, runtime·clock·처리 경계 전진은 시험 입력이었다. 최초 UNKNOWN 관측으로 실패한 HOLD는 PASS로 소급하지 않았다. 운영 root 권한·설치된 환경/잠금 설정·원래 system timer/service·운영 DB/PCAP·불확실한 서비스 복원·재부팅·supervisor SIGKILL은 PR108의 배포 전 검증으로 남아 있다. API 생산 구현과 HTTP의 조회 전용 계약은 바뀌지 않았으며 HTTP에서 verifier나 서비스를 제어하지 않는다. 운영 ffa82c0에 새 manager를 배포하거나 복구를 재적용한 결과로 해석하지 않는다.
