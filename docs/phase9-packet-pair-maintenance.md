# 계획 정비 중 Rule·IF 복구

기존 pair 복구 명령을 실행하는 동안 승인된 처리 서비스만 잠시 멈춘다. 기본 모드는
Capture를 정상 종료하는 `bounded-replay` 정비다. 계획에 `allow_capture_appends=true`를
명시한 경우에는 Capture를 유지한 `bounded-replay`와 `live-resume`을 지원한다. 처리할
정상 자료와 건너뛸 손실 구간은 기존 계획에서 검토한다. 실행은 한 번이며, 응답 유실을 재실행
근거로 사용하지 않는다. 원본·실패 구간·기존 감사는 보존한다.

## 실행 조건과 영향

- Pi Linux, 사용자 `pi`의 UID/GID 1000, systemd와 cgroup v2, pidfd가 필요하다.
- 프로젝트 경로는 `/home/pi/iot-edge-zero-trust`다. 복구할 DB는 그 아래
  `backend/data/iot_security.db`이며, 실제 `.env`와 잠금 설정을 사용한다.
- 검증한 코드를 배포한 뒤 그 Git 상태에서 새로운 계획·요청을 생성한다.
  검토한 뒤 소스·설정·DB 경계·원본이 달라지면 실행하지 않는다.
- **선택한 중단 범위와 운영 DB 복구를 포함하는 정비 승인이 필요하다.** 사본 시험
  승인이나 개별 손실 구간 승인만으로 이 절차를 실행하지 않는다.
- 기본 Capture 중지 모드는 Capture, MQTT DB 수신, 탐지·특징 처리, API, 방화벽
  Worker와 관련 타이머를 잠시 멈춘다. 브로커는 유지한다. 중단 중 Packet과 MQTT DB
  자료가 누락될 수 있어 종료·재시작 Session 경계로 공백을 기록한다.
- 수집 유지 모드는 `detection-orchestrator.service`, `packet-feature-extractor.service`,
  `packet-feature-extractor.timer`만 멈춘다. Capture·MQTT 수신/특징·API·방화벽과
  브로커는 제어하지 않는다. 기존 실행 중 상태가 확인된 처리 서비스만 복귀한다.
- 실제 기기 차단, 펌웨어 변경, 재부팅, Migration은 이 명령에 포함하지 않는다.

서비스 제어는 root, SQLite 읽기·백업·적용은 `pi`가 수행한다. 컨트롤러는 제품
모듈을 root로 import하거나 운영 DB를 root로 열지 않는다.

## 순서

1. 기존 pair CLI의 `dry-run --mode bounded-replay`로 대상·손실·정상 자료와 두
   처리 경계를 검토한다. 수집 유지 모드는 여기에 `--allow-capture-appends`를 추가하고
   필요한 경우 `--mode live-resume`을 사용한다. 이 옵션은 부모·자식 계획 SHA에 포함된다.
   FAILED 옵션은 해당 실패 증거를 승인한 경우에만 지정한다.
2. `pi`로 아래 요청을 만든다. 이 단계는 운영 DB와 서비스를 변경하지 않는다.

   ```sh
   cd /home/pi/iot-edge-zero-trust
   venv/bin/python -B -m edge.detection.packet_pair_maintenance_worker prepare \
     --plan-file <검토한_계획_절대경로> --request-output <새_요청_절대경로>
   sha256sum <새_요청_절대경로> edge/scripts/packet_pair_maintenance_controller.py
   ```

3. 정비 승인을 받은 후 요청 파일과 컨트롤러의 검토한 SHA256으로 한 번 실행한다.
   요청 안의 `plan_sha256`은 파일 전체 SHA256과 다르므로 구분한다.

   ```sh
   sudo /usr/bin/python3 -I -B edge/scripts/run_packet_pair_maintenance.py \
     --execute --approve-capture-pause --approval-reference '<승인_기록>' \
     --request-file <새_요청_절대경로> \
     --request-file-sha256 <요청_파일_전체_SHA256> \
     --controller-sha256 <컨트롤러_파일_전체_SHA256>
   ```

   수집 유지 요청에는 위 명령의 `--approve-capture-pause` 대신
   `--approve-processing-pause`를 사용한다. 두 승인을 함께 주거나 요청의 서명된
   수집 모드와 다른 승인을 주면 실행하지 않는다. 과거 요청에 새 필드가 없으면
   기존 Capture 중지 방식으로만 실행된다.

   기본 실행은 HOLD다. 명시적 실행은 고유 작업 번호를 먼저 출력하고, root 소유의
   요청·실행 사양·컨트롤러 사본을 봉인한다. `pi`가 읽을 요청은 0444, 컨트롤러는
   0555, root 전용 사양은 0400이다. 결과와 실제 pair 백업은 `output/packet-pair-maintenance/`
   아래 작업별 디렉토리에 보관한다. OS 제어 기록은 `/run/hanium-pair-maintenance/`
   아래에 있으므로 재부팅 전에 함께 보존한다.

4. 컨트롤러가 현재 Capture의 PID·프로세스 시작 시각·전체 Session 행을 확인한다.
   기본 모드에서는 Capture를 정상 종료한다. 수집 유지 모드에서는 이 신원이 준비·실행·
   분류·복귀 시점까지 동일해야 하며 종료·재시작하거나 다른 Session을 채택하지 않는다.
   승인한 처리 서비스와 cgroup 종료를 확인한 뒤 새 정비 상태의 pair 계획을 생성한다.
   범위·처리 경계·설정·Boot·소스는 같아야 한다. 기본 모드만 수집 종료 상태 변화를
   허용하며, 수집 유지 `live-resume`은 기존 엔진이 허용하는 대상 readiness의 단조 증가만
   허용한다. 승인 뒤 변경된 다른 근거는 HOLD다.
5. 기존 pair 엔진이 백업·무결성 검사·Rule·IF 조건부 적용과 감사를 수행한다.
   root는 작업 프로세스가 완전히 종료된 뒤 별도 `pi` 프로세스로 실제 감사·백업을
   읽어 복귀 방법을 결정한다. 종료 코드나 응답 파일만으로 적용 여부를 판단하지 않는다.
6. 두 감사가 검증되고 서비스가 복귀하면 Capture UUID를 읽어 확인한다. 수집 유지
   모드는 준비 시의 UUID·PID·시작 시각·전체 Session 행이 그대로여야 한다. 기본 중지
   모드에서 새 Capture가 시작되었다면
   [pair CLI의 continuation 절차](phase9-packet-pair-recovery.md#유지보수-재시작-뒤-읽기-전용-상태-확인)로
   원래 계획·감사를 보존한 채 새 수집과 상태 조회를 연결한다. 실제 Rule·IF·Trust와
   필수 MQTT 처리가 목표 경계까지 진행한 뒤에만 `REPLAY_COMPLETE`로 표시한다.

## 수집 유지 중 원본 보호 범위

수집 유지 승인은 실행 중 Capture의 새 segment 기록과 MQTT·API·방화벽 등 승인된
별도 작성자의 활동을 허용한다. Packet 특징 작성자는 정지해야 한다. 코어는 실제
복구 잠금을 취득한 뒤 읽기 트랜잭션에서 보호할 원본을 고정하고, 검증한 백업과
`BEGIN IMMEDIATE` 적용 트랜잭션에서 다시 대조한다. 새 snapshot이나 high-water를
승인 계획에 추가하지 않으며, 최초 dry-run 시점의 Feature 전체를 고정했다는 의미는
아니다. 기존 Session·segment·Feature 근거의 변경이나 삭제를 허용하는 옵션도 아니다.

## 실패와 복귀

아래 표는 기존 Capture 중지 모드다.

| 실제 확인 결과 | 복귀 동작 |
| --- | --- |
| DB 작업을 아직 요청하지 않음 | 원래 실행 중이던 서비스 복귀 |
| 검증된 적용 감사 0개 | 원래 서비스 복귀. 자동 재실행하지 않음 |
| 검증된 적용 감사 2개 | 원래 서비스 복귀. 처리 전진은 별도 확인 |
| Rule만 적용 | 수집·수신·API 등 복귀, Orchestrator와 방화벽 Worker는 대기 |
| 감사·백업·무결성을 확인할 수 없음 | 수집·수신·API 등 복귀, Orchestrator와 방화벽 Worker는 대기 |
| 쓰기 프로세스의 종료를 확인할 수 없음 | 서비스 재개를 보류하고 수동 확인 |

수집 유지 모드에서는 검증된 0개·2개 감사 또는 작업 미시작이면 원래 실행 중이던
처리 서비스를 복귀한다. 부분 적용·불확정 분류이면 Orchestrator, extractor 서비스,
extractor 타이머 **3개 모두 HOLD**하며 원래 꺼져 있던 extractor도 시작하지 않는다.
유지한 Capture·MQTT·API·방화벽은 이 경로에서 중지·재시작하지 않는다. Capture PID·
시작 시각·전체 Session 행이 달라지거나 Worker 종료를 증명하지 못하면 복귀를
완료 처리하지 않는다. 자동 복구나 새 Capture의 임의 채택은 없다.

부분 적용에서는 기존 Rule 감사를 보존한다. 원래 조건에서 미완료 IF만 재개할
수 있는지 재검토해야 하며, 새 작업 번호로 Rule·IF 전체를 다시 실행하지 않는다.
이 버전은 부분 적용 뒤의 추가 Capture 중지나 자동 재개까지 수행하지 않는다.

Worker는 최대 90초, 정상 컨트롤러는 145초로 제한한다. 정지 전에 별도 150초
복원 타이머를 준비한다. 복원기는 기존 컨트롤러와 Worker의 cgroup이 비었음을
확인한 뒤 감사 분류와 복귀를 진행한다. 분류는 최대 20초로 제한한다.
**전체 180초 이내 복귀는 목표이며 보장이 아니다.** 프로세스 종료·감사 확인 실패는
수동 조치가 필요할 수 있고, 독립 복원기의 분류·복귀 시간도 별도로 소요된다.

SSH가 끊기거나 launcher의 관측 시간이 끝나도 systemd 작업은 계속된다.
출력된 작업 번호로 기존 기록부터 확인한다. `RESTORATION_REPORTED`나 종료 코드 3은
탐지 복구 완료를 뜻하지 않는다. 기본 launcher 종료 코드 0도 HOLD의 성공 출력일 뿐이다.

## 검증 범위

Worker 시험은 임시 SQLite에서 실제 백업·조건부 적용·감사를 수행한다. 부분 실패,
Rule/IF COMMIT 뒤 응답 유실, 원본·설정·백업·감사 변조와 재실행 거부를 확인한다.
수집 유지 시험은 bounded/live 적용, 읽기 전용 감사 재분류, Capture 변경 거부,
독립 복원·취소·부분 적용 시 처리 3개 HOLD, 다른 서비스 무조작을 확인한다.
Controller/launcher 단위 시험은 OS 호출을 대체하므로 실물 서비스 시험과 구분한다.
Continuation 시험은 실제 적용 감사와 보존 자료를 대조하고 기본 상태 조회의 엄격한
조건을 유지하는지, 새 수집을 임의 채택하지 않는지 확인한다.

운영 DB 복구 성공과 현재 수집까지의 전체 재개 완료는 별도 운영 검증 결과로 남긴다.
종료된 한 Session의 replay 완료는 뒤의 실패 구간이나 전원 종료 공백을 넘는 승인이 아니다.
