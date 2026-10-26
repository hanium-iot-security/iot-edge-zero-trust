# AI 관찰 모드 운영 가이드

AI 관찰 모드는 IF 추론과 탐지 기록을 유지하면서 AI 이벤트의 자동 감점·격리만 제외한다.
Rule 탐지·감점, 같은 계열의 대표 감점, Window 최대 −30, 격리 기준 `< 30`은 유지한다.
모델·Feature·이상 점수·탐지 임계값을 바꾸거나 기존 오탐이 해결됐다고 판단하는 기능은 아니다.

## 1. 설정과 적용 범위

| `TRUST_AI_MODE` | 동작 |
| --- | --- |
| `enforce` | 기본값. 기존 Rule 우선·AI 단독 대표 최대 −15 정책 유지 |
| `observe` | 유효한 `AI_ANOMALY`·`AI_PACKET_ANOMALY`를 관찰 완료로 기록하고 감점·격리에서 제외 |

설정은 프로세스가 시작할 때 읽는다. 운영 관찰에는 `TRUST_AI_MODE=observe`를 명시한다. 전역 observe는 호출자가 명시한 enforce보다 우선한다. detector_type=AI 또는 알려진 AI event_type은 관찰 대상으로 판단한다.
현재 운영 중인 IF Stage를 `ORCHESTRATOR_ENABLED_STAGES`와
`ORCHESTRATOR_REQUIRED_STAGES`에서 제거하지 않는다. 미배포·비활성 모델을 이 설정만으로
새로 활성화하지도 않는다. Required Stage의 실패·Capture Gap을 통과시키는 옵션이 아니다.

모드는 **미처리 이벤트를 Trust가 처리할 때** 적용된다. 이벤트가 생성될 때 enforce였어도
observe에서 처음 처리되면 관찰 대상이다. 이미 처리한 관찰 이벤트는 enforce로 돌아가도
다시 감점하지 않는다. 지연·미등록·기존 격리·잘못된 정책 등 선행 제외 조건은 기존 사유를
유지하므로 모든 AI 행이 `AI_OBSERVATION_ONLY`가 되는 것은 아니다. 이 경로도 observe 실제0의 Trust 근거를 남긴다. 기존 trust_decision이 있으면 별도 원본 키에 보존한다.

## 2. 저장·조회 계약

관찰 완료된 유효 AI 이벤트는 다음과 같이 기록한다. 예시는 응답의 관련 필드만 나타낸다.

```json
{
  "score_delta": -15,
  "policy_score_delta": -15,
  "actual_score_delta": 0,
  "score_effect_reason": "NOT_APPLIED",
  "applied_to_score": 0,
  "processing_reason": "AI_OBSERVATION_ONLY",
  "processed_at": "2026-10-02T00:00:10Z",
  "evidence": {
    "trust_decision": {
      "ai_mode": "observe",
      "policy_version": "trust-ai-observation-v1",
      "policy_score_delta": -15,
      "original_score_delta": -15,
      "actual_delta": 0,
      "processed_at": "2026-10-02T00:00:10Z"
    }
  }
}
```

- 새 처리에서는 `score_delta` 원본을 유지한다. 원래 저장값은 `original_score_delta`, 공통 감점표의 후보값은 `policy_score_delta`에 보존한다. 기존에0으로 저장된 과거 행도 재작성하지 않는다. 실제 변화는 `actual_score_delta=0`으로 구분한다.
- 기존 모델·탐지 Evidence는 유지한다. Event의 detector `policy_version`, 원본 참조,
  dedupe 식별자는 바꾸지 않고 Trust의 판단 버전은 `evidence.trust_decision`에 분리한다.
- `processed_at`은 해당 Trust cycle의 UTC cutoff이며 별도의 벽시계 실행 시각이 아니다.
  처리 완료와 checkpoint는 진행하되 AI 관찰만 있는 Window는 점수 이력·격리 이력·
  신규 Firewall 요청을 만들지 않는다. 같은 Window의 Rule은 기존 정책대로 처리한다.
- API는 실제 변화·정책 감점·이력 연결 필드를 추가한다. Events 목록은 실제0과 미반영 사유를 표시하며 정책·원본 감점은 별도로 유지한다. 미처리나 감사 근거가 불명인 실제 변화는 null이다.
  Events 상세에서는 처리 사유와 `evidence.trust_decision`을 확인할 수 있다. 여러 이벤트의 구간 총변화를 개별 이벤트마다 감점한 것으로 표시하지 않는다.
  `applied_to_score=0` 집계는 관찰 완료도 포함하므로 미처리 적체 건수가 아니다.
- 과거 감점이나 격리는 자동 취소하지 않는다. 관찰 이벤트는 실제 감점된 Event를
  대상으로 하는 [승인형 점수 보상](operator-trust-compensation-runbook.md)의 대상도 아니다.

## 3. 운영 적용 전 확인

리뷰·병합과 필요한 검증 후 우민이 운영 절차를 실행한다. 문서 작성이나 로컬 통과만으로
Pi 배포·서비스 재개·공식 수집을 완료 처리하지 않는다.

1. 적용 Commit, 운영 DB·모델 경로와 해시, 서비스의 active/enabled 상태, 활성/required
   Stage, Detector·Trust checkpoint를 기록한다. 비밀값을 제외한 설정 변경분을 남긴다.
2. 일관된 SQLite 백업과 SHA256, integrity/FK 검증을 확보한다. MQTT·Feature·PCAP와
   기존 감사 자료는 보존한다. 운영 DB·설정 원본·모델·개인 `output/`은 Git에 올리지 않는다.
3. `TRUST_AI_MODE=observe`와 기존 Stage 구성을 검토한다. 기존 구형 Trust 실행 경로는
   중지 상태를 유지한다. observe 설정 또는 관찰 기록이 있는 DB에서는 구형 경로가 거부된다.
   이 보호는 P8-S01의 v2 DB 전체 구형 실행 차단(PR #88)을 대체하지 않으며 함께 통합 검증한다.
4. 아래 읽기 명령으로 새 프로세스가 해석한 설정·checkpoint를 확인한다. 이는 이미 실행 중인
   서비스의 설정 확인을 대신하지 않으므로, 승인된 적용 후 서비스 시작 로그도 대조한다.

```bash
python -m edge.orchestration.run_detection_orchestrator --status
```

## 4. 공백 복구와 처리 재개

1. Packet 공백이 있으면 [Checkpoint Gap Recovery](packet-checkpoint-gap-recovery-runbook.md)의
   dry-run·복사 DB 검증·승인·백업 절차를 먼저 따른다. 관찰 모드라는 이유로 checkpoint를
   현재로 직접 이동하거나 FAILED 자료를 성공으로 바꾸지 않는다.
2. Live Resume 대상은 공식 절차가 허용하는 현재 Session과 경계로 정한다. Packet Rule·IF가
   모두 required이면 두 Detector의 Plan·Execute·Audit와 Target 경계가 일치해야 한다.
   완료된 Source에서 재개하는 경우 FAILED-tail 예외를 임의로 적용하지 않는다.
3. 중간의 처리 가능한 Session을 건너뛰는 계획은 누락 범위를 별도로 승인·기록한다.
   실제 dry-run의 분류·수량을 대조하고 Plan SHA에 연결된 추가 확인 절차를 따른다.
   원본은 보존하고 건너뛴 행을 탐지 완료·정상 평가 자료로 계산하지 않는다.
4. 두 Audit를 확인한 뒤 Orchestrator `--once`를 먼저 실행해 `PACKET_LIVE_RESUME_CATCHUP`으로
   MQTT·Trust가 Target 시작 경계에 도달하는지 확인한다. 이보다 먼저 Packet Manual Runner로
   checkpoint를 전진시키면 Audit 매칭이 깨질 수 있다. 다음 `--once`에서 Target의 기존 Feature를
   처리하고 Packet·MQTT·Trust의 완료 경계를 확인한다. `--once`는 DB를 변경하는 실행 명령이다.
   IF 추론은 계속 실행하고 이상으로 판정한 경우 AI Event를 남겨야 한다. 관찰 처리는 5절로 확인한다.
   공백·Stage 오류·관측 불확실성이 남으면 HOLD하고 자동으로 live 운용을 재개하지 않는다.
5. 기존 격리·점수 복구가 필요하면 [방화벽 해제](firewall-runbook.md), 실제 Runtime 확인,
   [Baseline Recovery](baseline-recovery-runbook.md)를 별도 절차로 수행한다. 각 절차의
   서비스 격리·Capture 중지·미처리 Event 확인 조건을 그대로 적용한다. 모드 전환만으로
   차단을 해제하거나 점수를 100으로 쓰지 않는다.

## 5. 적용 후 검증

- 새 MQTT 수신 → Feature → 활성 IF·Rule → Trust checkpoint가 연속 두 차례 이상 진행하는지 확인한다.
  서비스 active·API 응답 성공·이벤트 0건만으로 분석 재개를 판단하지 않는다.
- AI 단독 이상 Window에서 Event와 관찰 완료 필드가 일치하는지 확인한다. 해당 기기·Window의
  관찰로 점수·상태가 바뀌거나 점수/격리 이력·Firewall 요청이 새로 생기지 않는지 대조한다.
- Rule과 AI가 함께 발생한 Window에서는 Rule만 기존 대표 감점·cap·격리 기준을 적용한다.
  Rule에 의한 감점까지 막힌 상태를 성공으로 기록하지 않는다.
- 같은 범위 재실행과 observe → enforce 전환 후에도 이미 관찰 완료된 Event가 재감점되지
  않는지 복사 DB에서 확인한다. 운영에서는 `processed_at`을 지우거나 과거 Event를 재작성하지 않는다.
- Events 조회는 `processing_reason=AI_OBSERVATION_ONLY&applied_to_score=0`으로 확인할 수 있다.
  이 조건의 행 수, 실제 모델 입력 수, 제외·실패 수를 구분해 기록한다.

## 6. 설정 복귀와 후속 작업

enforce로 돌아갈 때도 검토된 변경 절차를 따른다. 이후 처음 처리하는 Event에 기존 감점
정책이 적용되며, 관찰 완료한 과거 행은 그대로 남는다. 관찰 기록을 모르는 이전 코드나
구형 Trust로 DB를 열어 자동 처리를 재개하지 않는다. 복구가 필요하면 변경 이후 자료를
보존한 뒤 호환되는 코드·설정·DB 백업 세트와 기존 승인 절차를 사용한다.

기기별 AI 설정, 반복 경고·Cooldown, 정상 학습 자료 확장·재학습·독립 평가와 화면의
전용 관찰 배지는 후속 작업이다. 이 변경의 완료 기준은 추론 유지와 AI 관찰의 무감점 처리다.
