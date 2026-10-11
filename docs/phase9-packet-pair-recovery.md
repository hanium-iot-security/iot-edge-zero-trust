# Phase 9 관리자 Rule·IF 통합 복구 CLI

이 문서는 로컬 구현의 계약이다. 실제 Pi 복구·배포를 수행했다는 의미가 아니다.
이 CLI는 HTTP API를 추가하지 않는다. 서비스 자동 관리 기능은
[별도 manager 명령](phase9-packet-pair-manager.md)을 참조한다.

`python -m edge.detection.run_packet_checkpoint_pair_recovery`는 기존 단일 복구 엔진을
Rule → IF 순서로 호출한다. 합집합 runtime 잠금을 한 번 획득하고 두 child 작업은
각각 별도 backup/transaction/audit를 만든다. Rule commit 후 IF 실패는 부분 완료이며
자동 rollback이나 전체 backup 복원을 하지 않는다.

## 종료된 정상 구간 재처리

`dry-run --mode bounded-replay`는 바로 다음 **COMPLETED** Session에 보존된 정상 입력을
먼저 처리하기 위한 명시적 모드다. 기본값인 `live-resume`의 동작은 유지한다.
원본은 처리를 끝낸 COMPLETED Session이거나, 위의 `--allow-failed-current-session`을
함께 승인한 미수집 FAILED 마지막 구간이어야 한다. FAILED 경로에서는 마지막 10초
구간의 끝과 대상의 첫 경계가 정확히 같아야 한다.

대상은 모든 구간이 PROCESSED/EMPTY로 연속 준비돼 있고 종료 시각이 준비 경계를
덮어야 한다. 중간 Session과 겹치는 다른 수집 구간을 건너뛰지 않는다. 더 뒤에 새
RUNNING Session이 있더라도 그것의 첫 경계가 보존 대상의 끝보다 빠르면 차단한다.
두 child 계획은 대상의 전체 Session·Segment·Feature 입력 해시, 시작·끝·행 수 및
나중 RUNNING Session의 식별자를 같은 `bounded_replay`에 고정한다.

이 모드의 pair 승인은 `APPLY-PACKET-PAIR-BOUNDED-REPLAY:<PAIR_SHA256>`이다.
각 child는 일반 원본에 `APPLY-PACKET-BOUNDED-REPLAY`, FAILED 예외 원본에
`APPLY-PACKET-FAILED-TAIL-BOUNDED-REPLAY`를 사용한다. live-resume의 승인 문자열로는
실행할 수 없다. manager는 해당 pair 계획을 그대로 바인딩하며 모드를 바꾸지 않는다.

감사 적용은 기존 ID를 보존하고 대상 첫 경계만 이동한다. 이후 Orchestrator가 실제
정상 입력을 처리해야 한다. 두 Packet 탐지기가 대상의 마지막 특징 ID와 고정 끝 경계에
도달하고, 필수 MQTT 처리와 Trust도 끝까지 진행하며 처리되지 않은 대상 이벤트가
없을 때 `REPLAY_COMPLETE`로 표시한다. 오래된 보존 자료를 처리하므로 현시각 기준
45초 신선도와 두 번의 실시간 전진은 이 상태에 적용하지 않는다.

`REPLAY_COMPLETE`는 보존 대상의 재처리 완료다. 현재 RUNNING Session의 실시간 복구
완료를 뜻하지 않는다. 전원을 꺼 둔 구간을 넘어 현재 수집으로 이어가려면, 재처리를
끝낸 Session에서 현재 Session으로 **새 live-resume 계획과 승인**을 만든다. 기존
10초 손실 승인을 전원 종료 구간 전체에 자동으로 확대하지 않는다. `status`/`resume`는
원래 감사·백업·입력 해시를 재검사하고 이미 적용된 child를 반복하지 않는다.

## 지원 경로와 승인

지원 경로는 COMPLETED 원본 Session의 처리를 끝낸 두 Packet checkpoint에서,
유일한 RUNNING target Session의 첫 경계로 이동하는 기존 `live-resume`이다.
추가로 dry-run의 `--allow-failed-current-session`을 명시한 경우에만 기존 단일 엔진의
**미수집 FAILED 마지막 구간** 경로를 사용한다. 원본은 종료 시각이 있는 FAILED Session이어야
하며, 이미 처리한 경계에서 시작하는 마지막 10초 구간 하나만 `LATE_CAPTURE`로 실패한
경우를 허용한다. 해당 구간에 파일 이름·실제 Capture 시작·수집 시간·Packet·Feature가
없고 두 탐지기가 정상 준비 구간을 모두 소비했는지 단일 엔진이 각각 검사한다.
기록된 PCAP 파일 이름이 있으나 파일이 사라진 경우나 처리 가능한 Feature가 있는 경우는
이 예외가 아니며 차단한다. FAILED 기록과 입력 데이터는 그대로 보존한다.
일반 FAILED 복구, 기존 모드의 임의 gap recovery, 새로운 Migration은 이 CLI 범위에 없다.
원래 checkpoint ID를 보존하고 target 첫 경계만 바꾼다. 백업 이후 재검사,
조건부 UPDATE, 보호 테이블 검사, DB integrity/FK 검사 등 단일 엔진의 안전 조건은 유지한다.

계획에는 실제 DB 절대 경로, Git commit/상태, 원본/대상 Session, 각 child의 원래
before(ID/경계/updated_at), 승인자/사유, Boot ID, Stage 구성, CapturePolicy를 기록한다.
tracked/staged Git 변경이 있는 checkout에서 운영 계획을 만들 수 없다.
모든 명령은 실제 `repository_root`를 CWD로 두고 서비스와 같은 환경 설정으로 실행한다.
Settings의 `.env`/`../.env` 검색으로 Stage·Capture·잠금 설정이 달라지지 않도록 한다.
계획 출력의 부모와 artifact 디렉터리는 미리 존재해야 하고, 저장소 안의 생성 경로와
runtime 잠금 경로는 Git ignore 대상이어야 한다.

pair UUID를 새로 발급하고 각 child ID를 `uuid5(pair_id, detector_name)`으로 정한다.
두 ID는 서로 다르며 같은 승인 계획의 재시도에서 유지된다. parent SHA와 함께 승인한다.
처리 가능한 중간 Session을 건너뛰는 계획은 별도의 parent SHA 승인도 필요하다.
이는 데이터를 정상 입력으로 만드는 조작이 아니라 기존 skip 계약의 명시적 승인이다.

```sh
python -m edge.detection.run_packet_checkpoint_pair_recovery dry-run \
  --db-path /srv/iot/data/iot_security.db \
  --repository-root /srv/iot/iot-edge-zero-trust \
  --current-session-id <SOURCE_UUID> --target-session-id <TARGET_UUID> \
  --approved-by <ADMIN> --reason '<APPROVED_REASON>' \
  --plan-output /srv/iot/recovery/pair-plan.json
```

원본이 위 조건에 맞는 FAILED Session이면 dry-run에
`--allow-failed-current-session`을 추가한다. 기본값은 `false`이며, COMPLETED 원본에
이 옵션을 넣어도 실행 가능 계획이 되지 않는다. 계획에는 parent와 두 child의
`allow_failed_current_session`, 각 child의 `failed_current_tail` 증거와
`UNCAPTURED_FAILED_TAIL_SKIP` 경고가 포함된다. 원본 마지막 구간의 수집 기회를
건너뛰는 승인이며, 실패 데이터를 정상 학습 자료로 바꾸는 기능은 아니다.

계획의 `can_execute`, `blocking_reasons`, 두 child의 before/after, skip 목록을 검토하고
실제 출력된 parent `plan_sha256`을 사용한다. 서비스 상태를 읽을 수 없는 Windows
호스트의 실제 dry-run은 Boot 미확인으로 차단되며, Windows 검증은 fixture 관측을 사용한다.
execute/resume는 POSIX에서만 허용한다. 공개 CLI에 OS/서비스/잠금 우회 옵션은 없다.

execute/resume 전에 기존 서비스 상태를 기록하고, 기존 운영 절차로 Orchestrator와
수동 Rule/IF Runner의 잠금을 해제해야 한다. Orchestrator가 lifetime 잠금을
보유한 채 실행하면 충돌로 차단된다. Capture/MQTT 수집은 유지하고, 적용 뒤에는
원래 active였던 서비스만 기존 절차로 복귀한 후 status를 관측한다. 이 절차를
CLI가 자동 수행하지 않는다. 실패 시 새 before를 승인하거나 잠금을 우회하지 않는다.

Orchestrator는 실행 환경의 `ORCHESTRATOR_LOCK_PATH` 설정(빈 값이면 기존 기본값)을
사용하고 parent/child 계획에 그 절대 경로를 바인딩한다. 실행 시 설정이 달라지면
차단한다. 수동 Runner와 Extractor는 각각 기존 기본 잠금 경로를 사용해야 한다.
별도 `--lock-path`로 실행하는 수동 프로세스가 있다면 이 CLI의 운영 규격과 맞추고
기존 절차로 종료해야 한다. 이 CLI는 임의 custom 잠금 override를 제공하지 않는다.

```sh
python -m edge.detection.run_packet_checkpoint_pair_recovery execute \
  --plan-file /srv/iot/recovery/pair-plan.json \
  --db-path /srv/iot/data/iot_security.db --artifact-dir /srv/iot/recovery/artifacts \
  --confirm APPLY-PACKET-PAIR-LIVE-RESUME:<PARENT_PLAN_SHA256>
```

필요한 경우 동일 명령에
`--confirm-skip-processable SKIP-PROCESSABLE-PAIR:<PARENT_PLAN_SHA256>`을 추가한다.
필요하지 않은 skip 승인을 임의로 추가해도 거부한다.
FAILED 원본의 예외 허용도 같은 parent SHA 승인에 묶인다. child 실행에는 기존 엔진의
`APPLY-PACKET-FAILED-TAIL-LIVE-RESUME` 확인 문자열을 전달한다. execute/resume/status에는
예외 옵션을 다시 받지 않으며, 승인 후 parent 또는 어느 child의 옵션을 바꿀 수 없다.
옵션이 없던 기존 v1 parent 계획은 두 child가 명시적 `false`인 경우에만 기본 경로로 읽는다.

## 부분 완료·응답 유실

`artifacts/<pair_id>/intent.json`은 승인 계획 원문이며, 각 `attempt-<uuid>.json`은
실행 전에 child backup 절대 경로를 기록한다. child plan은
`attempt-<uuid>/<detector>/plan.json`에, backup/checksum/child result는
`attempt-<uuid>/<detector>/<child_id>/`에, pair result는 해당 attempt에 저장한다.
IF backup은 Rule commit 이후 만들어지므로 두 backup hash가 같아야 한다는 조건은 없다.

DB 감사가 stdout/result 파일보다 우선한다. COMMIT 뒤 child/pair result 파일 생성이
실패해도 적용 사실을 보존한다. JSON의 `database_committed=true` 또는 확인 불가한
`null`은 rollback 증거로 해석하면 안 된다. 새 pair 계획을 만들어 기존 적용 단계를
다시 실행하지 않는다.

```sh
python -m edge.detection.run_packet_checkpoint_pair_recovery status \
  --plan-file /srv/iot/recovery/pair-plan.json \
  --db-path /srv/iot/data/iot_security.db --artifact-dir /srv/iot/recovery/artifacts

python -m edge.detection.run_packet_checkpoint_pair_recovery resume \
  --plan-file /srv/iot/recovery/pair-plan.json \
  --db-path /srv/iot/data/iot_security.db --artifact-dir /srv/iot/recovery/artifacts \
  --confirm APPLY-PACKET-PAIR-LIVE-RESUME:<PARENT_PLAN_SHA256>
```

resume에도 원래 skip 승인이 필요한 경우 동일하게 제공한다. Rule만 적용되면 원래
IF before 조건이 정확히 그대로인지 확인하고 IF만 실행한다. 새 before로 재계획하지
않는다. 두 child가 모두 적용되었다면 execute/resume도 검증만 수행한다.

status/resume는 각 child ID의 전체 DB 감사를 계획과 대조한다. detector/table,
DB/commit, source/target, before/after/updated_at, 승인자/사유, child plan 원문/hash,
skip 수, 실제 backup 경로/hash/sidecar/백업의 before checkpoint를 확인한다.
FAILED 원본 예외 옵션과 마지막 구간 증거도 child 계획 원문/hash에 포함되어 감사와 대조된다.
canonical SHA가 제외하는 값도 별도로 확인한다. 같은 detector+target에 다른
operation의 감사가 있어도 이 pair의 적용으로 채택하지 않는다.

현재 committed checkpoint는 감사 after와 정확히 같거나 입증된 정상 target 처리
전진이어야 한다. 전진은 10초 경계, runtime updated_at=경계, 준비된 연속 target
범위, 실제 소비 ID로 검증한다. Rule은 INBOUND, IF는 전체 방향 Feature의 max ID를
소비하며, EMPTY 구간은 ID가 유지될 수 있다. 후퇴, 같은 경계에서 ID/updated_at 변경,
다른 복구, target 식별 정보나 Boot/Stage/CapturePolicy 변경은 HOLD한다.

## 실제 완료 확인

감사 두 개만으로는 `COMPLETE`가 되지 않는다. 두 적용 이후 status의 최초 관측이
기준점이며, 이후 별도 관측 두 번에서 Rule/IF/Trust 경계가 모두 전진해야 한다.
매 관측의 ID는 후퇴하면 안 된다. Trust 입력 이벤트가 없는 정상 경로에서는 Trust
ID 증가를 강제하지 않는다. 관측 간격과 각 경계의 현재 시각 대비 지연은 45초 이하다.
무한 재시도나 자동 polling은 없으며 서비스와 정상 입력이 계속 진행되는 동안 status를
다시 실행한다.

완료에는 동일 Boot/target, Rule·IF enabled+required, NTP 동기화 확인, 아래 필수
서비스의 active 관측, 새 FAILED/연속성 오류 없음, 검증 구간의 공통 Capture 적격성,
실제 Feature ID 소비, Trust cutoff까지 미처리 후보 이벤트 없음이 필요하다.
Trust 경계는 두 Packet 경계를 넘을 수 없고 Rule/IF/Trust는 MQTT producer 경계를
넘을 수 없다. 서비스 관측은 읽기만 하며 시작·중지·재시작하지 않는다.

- `packet-capture.service`
- `packet-feature-extractor.timer`
- `mqtt-subscriber.service`
- `mqtt-feature-builder.service`
- `detection-orchestrator.service`

DB status 읽기는 read-only transaction이다. 연속 관측은 pair 전용 잠금 아래
`progress.json`에 checksum과 함께 기록한다. 증거가 없거나 바뀌면 이를 자동 복원하지
않는다. 완료 이후에도 stale/오류/변경을 관측하면 COMPLETE를 계속 주장하지 않는다.
완료 관측은 임의 DB 관리자가 감사와 입력을 모두 위조할 수 없음을 증명하는 장치가
아니며, 정상 runtime의 조건과 일치하는 로컬 처리 증거를 확인한다.

| 결과 | 의미 |
| --- | --- |
| `PENDING` | 이 pair의 적용 감사 없음 |
| `PARTIAL_HOLD` | Rule 적용 보존, IF는 원래 조건의 명시적 resume 필요 |
| `APPLIED_PENDING_PROGRESS` | 두 child 적용 확인, 실제 완료 증거 대기 |
| `HOLD` | 오류/확인 불가, 적용 사실을 유지하고 원인을 검토 |
| `COMPLETE` | 두 차례 전진과 완료 조건 확인 |

dry-run 성공은 exit 0이다. execute/resume/status는 `COMPLETE`일 때만 exit 0이다.
비완료이며 commit 없음이 확인되면 exit 2, commit이 있거나 확인 불가하면 exit 3이다.
`APPLIED_PENDING_PROGRESS`도 exit 3이며, 아직 전체 복구 완료가 아니다.
변경된 계획을 신뢰할 수 없으면 commit 여부도 `null`이다. 감사 전체 검증 실패는
child `COMMITTED_UNVERIFIED`로 적용 사실과 검증 미완료를 구분한다.

서비스 자동 원상복귀와 전체 Rule → IF 자식 제한시간은 별도 manager가 제공한다.
일반 FAILED 복구, 검증 프로세스의 엄격한 전체 제한시간, OS watchdog과 운영 배포·검증은
이 변경의 완료 범위가 아니다. 이 CLI 구현을 P9-05 전체 완료로 표시하지 않는다.

## 로컬 검증

테스트는 임시 DB에 실제 Migration/backup/조건부 UPDATE/감사를 수행하고 임시 Git
저장소를 사용한다. Linux Boot/서비스/시각/잠금 관측만 fixture로 대체한다.
정상 적용, 공유 잠금 1회, 서로 다른 ID, Rule만 commit, child/pair 응답 유실,
명시적 resume, 반복 실행, stale plan/CAS, 감사·백업 불일치, 실제 ID 소비,
Capture 적격성, 이벤트 없는 Trust, 미처리 Trust, 45초 freshness, 미전진과
두 번의 실제 전진을 검증한다. 미수집 FAILED 마지막 구간의 명시적 opt-in, 기본 차단,
두 child의 동일 옵션·기존 엔진 확인 문자열, 파일 이름/Feature/수집 기록이 있는 구간 거부,
계획 이후 원본 변경, 옵션·감사 변경, 기존 v1 계획, 부분 실패·응답 유실 후 IF만 재개,
manager의 동일 완료 조건과 원본 보존도 검증한다. 이 검증은 운영 수집·모델·등록 상태에 의존하지 않는다.

2026/10/9의 좁은 FAILED tail 추가 소스는 `842b1123896f6692238ecc0f5fdab268ed94b926`다.
Windows Python 3.10.11에서 pair·manager **113 passed, 2 skipped**(Linux 전용),
기존 단일 엔진 FAILED tail **10 passed**를 확인했다. Pi Python 3.10.11의 별도
시험 디렉토리에서는 pair·manager와 관리자 API 호환성 **157 passed in 27.88s**를 확인했다.
이 시험은 API 소스 `137ec8e32c6e7c643171affc1dcbdd9e0620109f`에 위 커밋의 pair 모듈·CLI·시험
세 파일을 덧씌운 사본이며 브랜치를 병합하거나 운영 소스를 바꾸지 않았다.
전송 TAR SHA256은 `9c8b3e8e808b3ba3ffb75253c28aeb2df9cf1fcae10de8f1b5565daf2429ea4c`다.
임시 SQLite·가상 서비스·소유한 시험 자식과 잠금을 사용했으며 실제 운영 복구 결과가 아니다.
HTTP 계획 생성은 기본 false를 유지하고 FAILED opt-in 요청을 허용하지 않는다.


## 2026/10/11 종료된 정상 자료 재처리 검증

`bounded-replay`를 포함한 단일 엔진·Orchestrator·pair·manager 회귀는 Pi Python
3.10.11의 별도 소스 사본에서 **375 passed in 38.11s, skip 없음**이었다. 합성
SQLite·가상 서비스와 소유한 시험 프로세스만 사용했다. 같은 후보 소스의 보존 DB
복사본 통합 시험은 **2 passed in 58.69s**였다. 후보 TAR SHA256은
`79ed98c10bf1a66de28112f2de542f4ccf351203f8f63e19548b2d5a244fde40`이다.

실자료 시험은 종료된 정상 Session의 738개 구간·5,218개 특징 행을 유지한 복사본에서
기존 Rule139713/IF139714의 ID를 보존해 첫 경계로 이동한 뒤, 실제 탐지 Stage와
Orchestrator·Trust를 실행했다. Rule144931/IF144932와 필수 MQTT·Trust가 원래 끝
경계에 도달했고 `REPLAY_COMPLETE`, 재실행 불변, 입력값 변조 거부를 확인했다.

수치 IF 예측·Boot·서비스 관측과 뒤의 RUNNING Session만 시험용으로 주입했다.
실제 모델의 정확도, 운영 서비스 정지·복귀, 운영 DB 복구나 현재 수집의 실시간 완료를
검증한 것은 아니다. 원본 DB·PCAP 압축본의 크기·전체 SHA256은 시험 후에도 같았다.
운영 배포와 새로운 전원 종료 구간의 재개 승인은 별도로 남아 있다.


## 종료된 FAILED Session의 정상 구간만 재처리

`bounded-replay --allow-failed-target-session`은 정상 구간이 연속으로 보존돼 있고
마지막 한 구간만 파일·실제 수집 시각·특징 데이터가 없는 `LATE_CAPTURE`일 때 사용할 수 있다.
기본값은 false다. 대상 Session과 실패 구간은 FAILED로 보존하며, 정상 구간과 실패 구간의
원본 행 전체를 계획 SHA에 묶는다. `replay_end`는 실패 구간의 시작이다.

이 옵션으로 정상 구간을 처리해 `REPLAY_COMPLETE`가 되어도 실패 구간을 건너뛰거나
다음 RUNNING Session으로 이동하는 승인은 포함되지 않는다. 다음 Session 재개에는
실제로 정상 구간을 모두 소비한 뒤 별도 `live-resume --allow-failed-current-session`
계획과 해당 손실 구간 승인이 필요하다. 앞선 Session을 건너뛰는 범용 복구는 지원하지 않는다.

단일 엔진의 확인 문자열은 `APPLY-PACKET-FAILED-TARGET-PREFIX-BOUNDED-REPLAY`다.
Pair의 확인 문자열은 기존 bounded prefix에 새 계획 SHA를 붙인다. 부모와 두 자식 계획은
동일한 target 옵션·실패 증거를 포함해야 한다. 이전 계획에 새 false 필드가 없어도 기존
SHA와 감사 원문은 보존하며, 실행 재검증에서만 기본값을 비교한다.

2026/10/11 로컬 Python 3.10 회귀에서 단일 엔진 233개 통과·Linux 전용 6개 제외,
Orchestrator 79개 통과, pair 115개 통과를 확인했다. 실패 구간의 입력 존재·연속성·
원본 변경·SHA·CAS·옵션 변조와 부분 적용 후 IF만 재개하는 경로를 검사했다.
이 기록은 운영 DB의 실제 복구 완료 기록이 아니다.
