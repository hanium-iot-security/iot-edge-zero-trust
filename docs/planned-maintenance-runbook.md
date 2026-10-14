# 계획 종료·재개 운영

계획된 Pi 종료·재부팅에만 사용하는 관리자 CLI다. 기존 장애 복구 명령의 승인·손실 검사·격리 정책은 변경하지 않는다. 실제 전원 종료 명령, 탐지 상태 API, 대시보드 종료 버튼은 포함하지 않는다.

## 배포 전 확인

- 이 기능의 Migration을 적용하고 MQTT Subscriber, Feature Producer, Orchestrator와 함께 같은 버전을 배포한다. 일부 파일만 배포하면 사용하지 않는다.
- 현재 배포 `.env`의 Stage와 Checkpoint가 지원 프로필이어야 한다. MQTT Feature Builder·MQTT Rule 둘·Packet Rule/IF·Trust의 6개를 기본으로 하고, MQTT IF를 활성화했다면 required에도 포함해 7개 Checkpoint를 drain한다. 활성화된 Stage가 required에서 빠져 있으면 종료 승인이나 서비스 정지 전에 HOLD한다. 평상시 Orchestrator의 optional Stage 처리 방식은 변경하지 않는다.
- Capture의 종료 유예 시간, Subscriber의 메시지 저장 완료, Orchestrator의 유지보수 drain cap을 확인한다. 종료 시 제한 시간을 넘기거나 강제 종료되면 READY로 인정하지 않는다.
- Capture는 초기 정리와 Session INSERT 대기가 끝난 현재 시각으로 첫 Window를 선택하고 그 시작까지의 Gap을 기록한다. 이미 저장한 Window 이후 Commit·실행이 지연되면 기존 `LATE_CAPTURE`로 남기며, 계획 재개도 실제 실패 구간을 자동으로 건너뛰지 않는다.
- Subscriber의 정상 종료 처리를 포함한 버전을 배포한다. 기존 SIGTERM 기본 종료(status 15)는 저장 완료를 보장하지 않는다. 종료 검사는 `Result=success`와 `ExecMainStatus=0`을 유지하며, 현재 메시지 저장이나 Orchestrator Cycle이 끝나기 전에 성공으로 처리하지 않는다. Python 초기 Import 단계는 이 종료 처리보다 앞서므로, 실제 검증 전 서비스 준비와 Checkpoint 전진을 확인한다.
- SQLite DB·서비스 경로·Runtime Lock 설정이 실제 배포와 일치해야 한다. 실행은 Linux root 권한만 허용한다. `--approved-by`는 표시용 이름이며 권한 인증을 대체하지 않는다.
- `resume`은 온라인 일관 백업·SHA256·무결성·FK 검사를 짧은 변경 트랜잭션보다 먼저 수행한다. 백업 저장 공간을 확보한다. 백업이 실패하면 승인을 소비하지 않는다.

## 종료 준비

Pi 저장소에서 실행한다.

```bash
cd /home/pi/iot-edge-zero-trust
sudo venv/bin/python -m edge.maintenance.run_planned_maintenance prepare-stop \
  --approved-by woomin --reason "planned daily shutdown"
```

이 명령은 현재 RUNNING Session·Boot ID·관리자·승인 시각을 먼저 연결해 REQUESTED를 기록한다. 그 뒤 Capture가 현재 Window를 마칠 때까지 기다리고 Subscriber를 정상 종료해 실행 중인 메시지 저장 Callback과 Commit을 마친다. Feature·탐지·Trust·Firewall Worker는 그동안 drain을 계속한다. **원본 메시지나 Capture Segment는 삭제하지 않는다.** 종료·재개 사이 수신 공백은 유지보수 제외 구간으로 기록하며, 아직 읽지 않은 네트워크 버퍼의 무손실 저장을 보장하는 절차는 아니다.

현재 Session의 정상 품질·연속성과 필수 Checkpoint의 마지막 경계 완료를 확인한 뒤 처리 서비스와 Timer를 멈춘다. 공유 Runtime Lock과 DB 트랜잭션 안에서 한 번 더 검증하고 READY를 기록한다. `COMPLETED` Session이나 SIGTERM만으로 READY를 만들지 않는다. READY의 유효 기간은 7일이다.

원본 처리 완료 검사는 탐지기별 조회 범위를 따른다. Packet Rule은 INBOUND, Packet IF는 전체 방향의 처리 ID를 확인하므로 같은 Window를 완료해도 두 ID가 다를 수 있다. 미처리 INBOUND와 IF의 미처리 OUTBOUND는 계속 종료를 막으며, 원본 봉인·해시에는 전체 방향을 포함한다.

JSON 결과가 `READY`인 경우에만 관리자가 OS를 정상 종료한다. 명령 자체는 poweroff/reboot를 실행하지 않는다. 실패하면 CANCELLED로 승인을 무효화하고 원래 활성 서비스의 복귀를 시도한다. `HOLD`와 서비스 복귀 실패가 표시되면 기록을 확인한다. 복귀된 Capture의 새 Session을 이전 승인으로 자동 건너뛰지 않는다.

## 다음 부팅에서 재개

시간 동기화와 정상 Capture/Extractor/MQTT/Orchestrator 서비스가 준비된 뒤 실행한다.

```bash
sudo venv/bin/python -m edge.maintenance.run_planned_maintenance resume \
  --artifact-dir output/planned-maintenance --timeout 120 --verify-timeout 120
```

재개는 READY의 승인과 종료 Session을 다시 검증하고, 다른 Boot ID에서 유일한 새 RUNNING Session 및 첫 정상 Packet Feature를 기다린다. 온라인 백업을 만든 뒤 서비스 전체 실행 중 Lock을 보유하는 Orchestrator만 잠시 정상 정지한다. Capture·Subscriber는 계속 실행한다. Orchestrator·Manual Detector·Extractor의 공유 Lock을 먼저, Firewall Lock을 마지막으로 확보하고 대상·Checkpoint·승인·연속성을 재확인한다. 시간·Boot ID 검사도 쓰기 트랜잭션 전에 끝낸다. **Packet Rule·IF의 Window 경계 두 개, 감사 기록, 승인 사용 완료를 한 트랜잭션으로 반영**한다. Orchestrator는 성공·실패 후 원래 활성 상태로 복귀시키며 기존 처리 ID·MQTT/Trust Checkpoint·점수·격리는 보존한다.

새 Session의 처음 몇 Window가 품질·연속성 검사에 통과한 `EMPTY`라면, 그 이후 최초 `PROCESSED` 구간의 양수 Packet Feature로 준비 상태를 확인한다. `EMPTY`는 집계 대상 트래픽이 없다는 뜻으로 원본 Packet 수가 0이라는 뜻은 아니다. `READY`·실패·누락 구간은 넘어가지 않는다. 재개 경계와 유지보수 종료 시각은 새 Session의 첫 Window 시작을 그대로 사용하므로, 초기 빈 구간과 이후 Feature는 기존 처리기가 순서대로 처리한다. 초기 빈 구간도 감사에 저장하며 적용 전과 적용 후 구간·Feature 변경을 검증한다.

`planned.py`를 배포하면 실행 중인 MQTT Feature Builder를 정상 정지한 뒤 다시 시작해 새 감사 검증을 로드한다. 이전 프로세스의 정상 종료와 새 프로세스의 활성 상태를 확인하며 Capture·Subscriber는 계속 실행한다.

정상 메시지나 정상 Capture 추가를 전체 DB 변경으로 보아 거부하지 않는다. 대신 승인 대상·첫 Window·Source의 봉인된 상태·Checkpoint가 바뀌거나 실패 구간이 있으면 HOLD한다. 승인된 유지보수 시간은 MQTT와 Packet 양쪽의 탐지·정상 학습/평가 후보에서 제외하며 원본은 남긴다. 종료 전에 남은 탐지 이벤트는 먼저 처리한다.

커밋 이후 서비스 활성 상태·새 FAILED Segment 부재를 확인하고, 최근 45초 안의 필수 Checkpoint가 두 차례 연속 전진하며 ID가 후퇴하지 않아야 `RESUMED` 결과를 반환한다. 점검이 끝나지 않으면 `COMMITTED_HOLD`와 승인 ID·감사를 남긴다. 이미 적용한 승인은 같은 Boot·Session과 감사가 유효한 경우에만 진행 확인을 다시 한다. 확인을 마치면 `ALREADY_RESUMED`를 반환하고 새 전이는 만들지 않는다. 다른 Boot·Session이나 변경된 필수 Stage 프로필에는 `HOLD`하며 기존 장애 복구가 필요하다.

## 첫 재개 Session의 정상 prefix 보존 복구

READY를 소비하기 전에 첫 부팅 Session이 정상 Window를 수집한 뒤 끝의 한 `LATE_CAPTURE`로 FAILED되고 다음 Session으로 넘어갔다면, 일반 `resume`은 계속 대기한다. 이때 첫 Session의 정상 데이터를 버리고 새 RUNNING Session으로 바로 이동하지 않는다. `recover-prefix`는 관리자가 대상·후속 Session·사유를 명시하는 별도 수동 경로이며 부팅 Unit은 이 명령을 자동 실행하지 않는다.

이 경로는 봉인된 종료 Source, 실제 첫 부팅 Session의 정상·연속 prefix, 정확한 미수집 실패 tail, 같은 부팅의 유일한 RUNNING 후속 Session을 함께 검증한다. 첫 Session과 후속 Session 사이 추가 Session·공백·원본 변경이 있으면 HOLD한다. 실패를 정상으로 바꾸거나 정상 prefix를 유지보수 시간에 포함하지 않는다. 사전 검증과 실제 적용 전에 관리자 승인을 받고, 적용 명령에는 그 승인자와 사유를 동일하게 넣는다. `--approved-by`는 권한 인증을 대체하지 않으며 적용은 Linux root만 가능하다.

```bash
venv/bin/python -m edge.maintenance.run_planned_maintenance dry-run-prefix \
  --operation-id <READY-승인-ID> --target-session-id <첫-FAILED-Session-UUID> \
  --successor-session-id <현재-RUNNING-Session-UUID> \
  --approved-by woomin --reason "Preserve and process the healthy first-boot prefix"

sudo venv/bin/python -m edge.maintenance.run_planned_maintenance recover-prefix \
  --operation-id <같은-READY-승인-ID> --target-session-id <같은-FAILED-Session-UUID> \
  --successor-session-id <같은-RUNNING-Session-UUID> \
  --approved-by woomin --reason "Preserve and process the healthy first-boot prefix" \
  --artifact-dir output/planned-maintenance --timeout 30 --verify-timeout 120
```

온라인 백업·SHA·무결성 검사와 복사 DB의 동일 계획 검증을 완료한 뒤 Orchestrator만 잠시 정상 정지한다. Capture·Subscriber는 계속 실행한다. 일반 재개와 같은 공유 Lock·부팅·시간·변경 직전 재검증을 거쳐 두 Packet 경계와 감사·승인 사용을 원자적으로 반영한다. 이동 경계와 유지보수 종료 시각은 **첫 FAILED Session의 첫 Window 시작**이며, 기존 처리 ID·MQTT/Trust 경계·점수·격리·원본을 직접 변경하지 않는다. 기존 승인으로 인정되는 시간은 이 첫 경계까지의 계획 종료 공백뿐이다.

복귀한 실제 처리기가 초기 EMPTY와 정상 prefix를 순서대로 처리한다. `PREFIX_DRAINED_RECOVERY_REQUIRED`는 두 Packet Checkpoint가 정확한 실패 시작 경계에 도달하고 다른 필수 처리·원본 검증도 완료됐다는 뜻이다. 탐지 정상 복귀나 실패 tail 제외 완료를 뜻하지 않는다. 자동 공백 정책이 적용되지 않았다면 이후 실패 구간을 별도로 승인한 기존 strict live-resume 절차로 첫 FAILED Session에서 후속 RUNNING Session으로 넘기고 정상 Checkpoint 전진을 확인한다. 정상 prefix는 학습·평가 후보에서 통째로 제외하지 않는다.

`PACKET_CONFIRMED_GAP_POLICY_ENABLED=true`로 동일한 10초 실패 tail을 이미 기록하고 전진했다면 `PREFIX_DRAINED_CONFIRMED_GAP`을 반환한다. 정상 prefix 마지막 Rule/IF 처리 ID와 실패 시작 경계가 공백 감사의 `checkpoints_before`에 정확히 남아 있고, 감사 해시·Source/Successor·실패 Segment·첫 후속 Segment가 보존된 증거와 일치해야 한다. MQTT/Trust의 공백 끝까지 처리가 덜 끝났으면 계속 WAIT한다. 이 결과의 `gap_status=UNINSPECTED`는 유지되며 자료 QC나 학습 승인이 아니다. 이미 기록한 tail에 strict 복구를 중복 적용하지 않는다.

커밋 후 drain 시간 초과·서비스 복귀 실패·새 부팅/Session/원본 변경은 `COMMITTED_HOLD`다. 적용한 승인을 취소하거나 다시 적용하지 않는다. 같은 대상·후속 Session·복구 승인자·사유로 재실행하면 기존 감사 검증과 read-only drain 확인만 수행하며 새로운 전이를 만들지 않는다. 실패 tail에 대한 수동 승인이나 확인된 자동 공백 감사 없이 Checkpoint를 그 이후로 이동하지 않는다.

## 조회와 대기

조회는 root 권한 없이 가능하며 DB를 변경하지 않는다.

```bash
venv/bin/python -m edge.maintenance.run_planned_maintenance status
venv/bin/python -m edge.maintenance.run_planned_maintenance dry-run
journalctl -u planned-maintenance-resume.service --since today
```

`WAIT`는 준비 상태·승인 부재 등을 표시한다. `HOLD`는 조건 실패를 표시한다. 결과의 이유를 해결하기 전에 Checkpoint를 직접 수정하거나 기존 장애 복구의 엄격한 검사를 해제하지 않는다. 새 FAILED Segment, 강제 전원 차단, REQUESTED 상태에서 종료, 승인 만료·중복 사용, 미처리 Source 데이터는 별도 장애 복구 검토 대상으로 남긴다.

종료 준비 도중 강제 전원 차단 등으로 REQUESTED가 남으면 관리자 조회로 대상 ID를 확인한 뒤 다음 명령으로 승인을 취소한다. Checkpoint·원본·격리·서비스를 변경하지 않으며 이후에는 기존 장애 복구 절차를 따른다.

```bash
sudo venv/bin/python -m edge.maintenance.run_planned_maintenance cancel \
  --operation-id <조회한-승인-ID> --reason "Interrupted planned stop; strict recovery required"
```

## 선택적 부팅 연동

CLI와 실제 Pi 검증을 완료한 후 `infra/systemd/planned-maintenance-resume.service`를 설치·활성화한다. 단순 `After=` 대신 명령이 시간 동기화·새 Session·Feature 준비 상태를 직접 검사한다. 실패하면 Journal에 남기고 자동 반복하지 않는다. 운영 설정 경로가 다르면 Unit 경로부터 수정한다. 전체 Unit을 설치했다고 실장비 검증이 완료된 것은 아니다.

부팅 재개 Unit은 `Nice=10`, `IOSchedulingClass=idle`로 온라인 백업·무결성 검사의 CPU·저장장치 경합을 줄인다. 이는 Capture 지연 방지를 보장하지 않으며, 새 FAILED Segment 확인과 기존 재개 검증·중단 조건은 그대로 적용한다.

root로 실행되는 부팅 Unit은 `sudo`의 원래 사용자 소유권 정보가 없으므로, Unit의 Git 환경 설정에서 배포 저장소 한 경로만 `safe.directory`로 지정한다. 전역 Git 설정이나 소유권·Git-ignore 검사는 변경하지 않는다. 배포 경로를 바꾸면 WorkingDirectory·ExecStart·환경 파일 경로와 함께 `GIT_CONFIG_VALUE_0`도 일치시킨다.

CLI 기본값과 부팅 Unit은 Git에서 디렉터리 전체를 제외하는 `output/planned-maintenance`에 백업을 저장한다. `data/recovery/planned`는 디렉터리 재포함 규칙 때문에 첫 백업 후 재실행 시 경로 검사를 통과하지 못할 수 있다. 기존 백업·감사 기록은 이동하거나 삭제하지 않고 원래 경로에 보존한다. 사용자 지정 경로도 생성 전후 모두 Git-ignored 조건을 충족해야 한다.

## 적용 취소·이전 버전 복귀

활성 REQUESTED·READY가 있다면 먼저 관리자 `cancel`로 취소하고, 설치한 부팅 재개 Unit은 비활성화한다. Migration 010의 감사·승인·봉인된 원본 데이터는 보존하며 DROP하거나 승인 상태를 직접 바꾸지 않는다. 부팅 연동 활성화 전 코드 복귀는 이 기록을 유지하는 조건으로 검토할 수 있다. 이미 재개 전이가 적용됐다면 기존 장애 복구 절차와 정상 처리 검증을 마친 뒤 이전 Runtime 사용 가능 여부를 판단한다. 구버전은 유지보수 제외 기준을 읽지 못할 수 있으므로 단순 코드 복귀만으로 탐지·학습 안전을 보장하지 않는다.

## 검증 완료 기준

- 정상 계획 종료·재부팅: 현재 Capture Window 및 종료 전 탐지·Trust 완료, 두 Packet 경계 원자적 재개, 정상 메시지 수신과 필수 Checkpoint 두 차례 전진.
- 강제 전원 차단·종료 준비 도중 중단: READY 승인으로 인정하지 않음.
- 미처리 데이터·실패 Segment·승인 대상 변경: HOLD하고 데이터를 건너뛰지 않음.
- 승인 중복 사용·커밋 응답 유실·재개 도중 중단: 감사 확인, 두 Checkpoint 부분 완료 및 재점프 없음.
- 백업·무결성 검사 실패: 승인 미소비, 기존 점수·격리 보존.
- MQTT/Capture 쓰기가 계속되는 재개: 손실·순서 오류와 새로운 FAILED Segment가 없음을 Pi에서 별도로 확인.
- 첫 부팅 Session의 실패 prefix 복구: 초기 EMPTY와 정상 prefix의 실제 처리, 정확한 실패 시작 경계에서 대기, 별도 tail 복구 전 정상 탐지로 표시하지 않음. 커밋 후 재실행은 감사 확인만 수행.

현재 문서와 테스트는 로컬 구현 검증 범위다. 실장비 서비스 정지·재부팅 및 전원 차단 검증은 운영 승인과 결과 기록을 갖춰 별도로 수행한다.
