# 계획 종료·재개 운영

계획된 Pi 종료·재부팅에만 사용하는 관리자 CLI다. 기존 장애 복구 명령의 승인·손실 검사·격리 정책은 변경하지 않는다. 실제 전원 종료 명령, 탐지 상태 API, 대시보드 종료 버튼은 포함하지 않는다.

## 배포 전 확인

- 이 기능의 Migration을 적용하고 MQTT Subscriber, Feature Producer, Orchestrator와 함께 같은 버전을 배포한다. 일부 파일만 배포하면 사용하지 않는다.
- 현재 배포 `.env`의 Stage와 Checkpoint가 지원 프로필이어야 한다. MQTT Feature Builder·MQTT Rule 둘·Packet Rule/IF·Trust의 6개를 기본으로 하고, MQTT IF를 활성화했다면 required에도 포함해 7개 Checkpoint를 drain한다. 활성화된 Stage가 required에서 빠져 있으면 종료 승인이나 서비스 정지 전에 HOLD한다. 평상시 Orchestrator의 optional Stage 처리 방식은 변경하지 않는다.
- Capture의 종료 유예 시간, Subscriber의 버퍼 flush, Orchestrator의 유지보수 drain cap을 확인한다. 종료 시 제한 시간을 넘기거나 강제 종료되면 READY로 인정하지 않는다.
- SQLite DB·서비스 경로·Runtime Lock 설정이 실제 배포와 일치해야 한다. 실행은 Linux root 권한만 허용한다. `--approved-by`는 표시용 이름이며 권한 인증을 대체하지 않는다.
- `resume`은 온라인 일관 백업·SHA256·무결성·FK 검사를 짧은 변경 트랜잭션보다 먼저 수행한다. 백업 저장 공간을 확보한다. 백업이 실패하면 승인을 소비하지 않는다.

## 종료 준비

Pi 저장소에서 실행한다.

```bash
cd /home/pi/iot-edge-zero-trust
sudo venv/bin/python -m edge.maintenance.run_planned_maintenance prepare-stop \
  --approved-by woomin --reason "planned daily shutdown"
```

이 명령은 현재 RUNNING Session·Boot ID·관리자·승인 시각을 먼저 연결해 REQUESTED를 기록한다. 그 뒤 Capture가 현재 Window를 마칠 때까지 기다리고 Subscriber를 정상 종료해 이미 받은 버퍼를 기록한다. Feature·탐지·Trust·Firewall Worker는 그동안 drain을 계속한다. **원본 메시지나 Capture Segment는 삭제하지 않는다.**

현재 Session의 정상 품질·연속성과 필수 Checkpoint의 마지막 경계 완료를 확인한 뒤 처리 서비스와 Timer를 멈춘다. 공유 Runtime Lock과 DB 트랜잭션 안에서 한 번 더 검증하고 READY를 기록한다. `COMPLETED` Session이나 SIGTERM만으로 READY를 만들지 않는다. READY의 유효 기간은 7일이다.

JSON 결과가 `READY`인 경우에만 관리자가 OS를 정상 종료한다. 명령 자체는 poweroff/reboot를 실행하지 않는다. 실패하면 CANCELLED로 승인을 무효화하고 원래 활성 서비스의 복귀를 시도한다. `HOLD`와 서비스 복귀 실패가 표시되면 기록을 확인한다. 복귀된 Capture의 새 Session을 이전 승인으로 자동 건너뛰지 않는다.

## 다음 부팅에서 재개

시간 동기화와 정상 Capture/Extractor/MQTT/Orchestrator 서비스가 준비된 뒤 실행한다.

```bash
sudo venv/bin/python -m edge.maintenance.run_planned_maintenance resume \
  --artifact-dir data/recovery/planned --timeout 120 --verify-timeout 120
```

재개는 READY의 승인과 종료 Session을 다시 검증하고, 다른 Boot ID에서 유일한 새 RUNNING Session 및 첫 정상 Packet Feature를 기다린다. 온라인 백업을 만든 뒤 서비스 전체 실행 중 Lock을 보유하는 Orchestrator만 잠시 정상 정지한다. Capture·Subscriber는 계속 실행한다. Orchestrator·Manual Detector·Extractor의 공유 Lock을 먼저, Firewall Lock을 마지막으로 확보하고 대상·Checkpoint·승인·연속성을 재확인한다. 시간·Boot ID 검사도 쓰기 트랜잭션 전에 끝낸다. **Packet Rule·IF의 Window 경계 두 개, 감사 기록, 승인 사용 완료를 한 트랜잭션으로 반영**한다. Orchestrator는 성공·실패 후 원래 활성 상태로 복귀시키며 기존 처리 ID·MQTT/Trust Checkpoint·점수·격리는 보존한다.

정상 메시지나 정상 Capture 추가를 전체 DB 변경으로 보아 거부하지 않는다. 대신 승인 대상·첫 Window·Source의 봉인된 상태·Checkpoint가 바뀌거나 실패 구간이 있으면 HOLD한다. 승인된 유지보수 시간은 MQTT와 Packet 양쪽의 탐지·정상 학습/평가 후보에서 제외하며 원본은 남긴다. 종료 전에 남은 탐지 이벤트는 먼저 처리한다.

커밋 이후 서비스 활성 상태·새 FAILED Segment 부재를 확인하고, 최근 45초 안의 필수 Checkpoint가 두 차례 연속 전진하며 ID가 후퇴하지 않아야 `RESUMED` 결과를 반환한다. 점검이 끝나지 않으면 `COMMITTED_HOLD`와 승인 ID·감사를 남긴다. 이미 적용한 승인은 같은 Boot·Session과 감사가 유효한 경우에만 진행 확인을 다시 한다. 확인을 마치면 `ALREADY_RESUMED`를 반환하고 새 전이는 만들지 않는다. 다른 Boot·Session이나 변경된 필수 Stage 프로필에는 `HOLD`하며 기존 장애 복구가 필요하다.

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

## 적용 취소·이전 버전 복귀

활성 REQUESTED·READY가 있다면 먼저 관리자 `cancel`로 취소하고, 설치한 부팅 재개 Unit은 비활성화한다. Migration 010의 감사·승인·봉인된 원본 데이터는 보존하며 DROP하거나 승인 상태를 직접 바꾸지 않는다. 부팅 연동 활성화 전 코드 복귀는 이 기록을 유지하는 조건으로 검토할 수 있다. 이미 재개 전이가 적용됐다면 기존 장애 복구 절차와 정상 처리 검증을 마친 뒤 이전 Runtime 사용 가능 여부를 판단한다. 구버전은 유지보수 제외 기준을 읽지 못할 수 있으므로 단순 코드 복귀만으로 탐지·학습 안전을 보장하지 않는다.

## 검증 완료 기준

- 정상 계획 종료·재부팅: 현재 Capture Window 및 종료 전 탐지·Trust 완료, 두 Packet 경계 원자적 재개, 정상 메시지 수신과 필수 Checkpoint 두 차례 전진.
- 강제 전원 차단·종료 준비 도중 중단: READY 승인으로 인정하지 않음.
- 미처리 데이터·실패 Segment·승인 대상 변경: HOLD하고 데이터를 건너뛰지 않음.
- 승인 중복 사용·커밋 응답 유실·재개 도중 중단: 감사 확인, 두 Checkpoint 부분 완료 및 재점프 없음.
- 백업·무결성 검사 실패: 승인 미소비, 기존 점수·격리 보존.
- MQTT/Capture 쓰기가 계속되는 재개: 손실·순서 오류와 새로운 FAILED Segment가 없음을 Pi에서 별도로 확인.

현재 문서와 테스트는 로컬 구현 검증 범위다. 실장비 서비스 정지·재부팅 및 전원 차단 검증은 운영 승인과 결과 기록을 갖춰 별도로 수행한다.
