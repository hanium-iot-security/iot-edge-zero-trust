# Packet IF Phase 5 평가 가이드

본 문서는 고정된 Packet IF Dataset과 검증된 Artifact를 사용하여 Phase 5
Offline Test 평가 Core를 재현하는 절차를 설명합니다.

## 공식 평가 진입 Gate

이 PR의 평가 모듈과 `packet-if-dataset-v1` 예시는 Local Fixture·평가 Core
선행 검증 범위입니다. 아래 조건이 모두 충족된 이후에만 같은 평가 절차의
출력을 공식 Phase 5 결과로 사용합니다.

- 공통 Phase 5 Run Manifest Schema 병합·동결
- Packet IF Dataset Manifest v2 병합·동결
- Dataset Exporter·Loader의 v2 계약과 `source_capture_group_id` 검증
- 공식 Session·Split·Source Capture Group 사전 동결

현재 Core는 Session ID 기준 누수만 차단합니다. P5-JM-01 완료로 판정하려면
Dataset Manifest v2 병합 시 동일 `source_capture_group_id`가 Train·Validation·
Test·Holdout 사이에 나뉘지 않는 검증을 추가해야 합니다.

`packet-if-evaluation-v1`은 평가 출력 Bundle의 Schema Version이며 공통 Run
Manifest Schema Version과 별개입니다. 본 모듈은 `run_id`를 비롯한 공통 Run
Manifest 필드를 정의하지 않고, 후속 v2 Dataset Manifest가 참조한 입력만
소비합니다.

## 평가 경계

- Dataset은 `load_packet_if_dataset()`으로 CSV·Manifest·Session SHA256과
  Split·Capture Policy 계약을 먼저 검증합니다.
- Artifact는 운영자가 별도로 고정한 Bundle SHA256을 사용하여
  `load_packet_if_artifact()`로 검증한 뒤 Model을 역직렬화합니다.
- 평가 전후 Dataset·Manifest SHA256이 같아야 하며 실행 중 변경되면 결과를
  게시하지 않습니다.
- Dataset CSV·Manifest의 실제 SHA256과 Test Session 목록이 Artifact 생성 시
  Metadata에 고정된 전체 Dataset Bundle 계약과 정확히 일치해야 합니다.
- Dataset과 Artifact의 Capture Policy 전체 값이 일치해야 합니다.
- 평가는 Dataset의 `test` Split만 사용합니다.
- 평가 Test Session이 Artifact의 Train·Validation Session과 겹치면 데이터
  누수로 간주해 추론 전에 거부합니다.
- Artifact Metadata에 저장된 Threshold를 그대로 사용하며 평가 중 다시
  계산하거나 변경하지 않습니다.
- Test 결과를 확인한 뒤 Threshold를 다시 선택하지 않습니다.

일반 Offline Smoke 명령인 `predict_packet_isolation_forest`는 Train·Validation·
Test 전체를 추론합니다. Phase 5 Test 평가는 이 명령을 사용하지 않고
`evaluate_packet_isolation_forest`를 사용합니다.

## 판정 계약

```text
Actual Positive    = traffic_label == "attack"
Predicted Positive = is_anomaly == true
is_anomaly         = anomaly_score > threshold
```

Anomaly Score가 Threshold와 같으면 정상으로 판정합니다.

## 실행 전 조건

- Dataset CSV와 Manifest가 변경되지 않은 최종 Version이어야 합니다.
- Model·Metadata·Training Report가 하나의 검증된 Artifact Bundle이어야 합니다.
- `PACKET_IF_EXPECTED_BUNDLE_SHA256`은 Artifact Directory 외부에서 전달받은
  값이어야 합니다.
- 평가 Source 변경사항을 Commit한 깨끗한 Revision에서 실행합니다.
- Git Worktree에서는 Evaluator가 clean 상태와 전달 SHA·현재 HEAD 일치를
  다시 검증합니다.
- `.git`이 없는 배포 환경에서는 `--git-commit-sha`를 필수로 전달합니다.
- 매 실행마다 새로운 평가 Version Directory를 사용합니다.

## 실행

```bash
test -z "$(git status --porcelain)" || {
  echo "Packet IF 평가는 clean worktree에서만 실행할 수 있습니다."
  exit 1
}
export SOURCE_COMMIT_SHA="$(git rev-parse HEAD)"

python -m ai.evaluate_packet_isolation_forest \
  --dataset data/exports/packet_if_dataset-v1.csv \
  --manifest data/exports/packet_if_manifest-v1.json \
  --artifact-dir ai/models/packet_if/packet-if-v1 \
  --expected-model-version packet-if-v1 \
  --expected-bundle-sha256 "$PACKET_IF_EXPECTED_BUNDLE_SHA256" \
  --output-dir data/evaluations/packet-if-eval-v1 \
  --git-commit-sha "$SOURCE_COMMIT_SHA"
```

`--git-commit-sha`를 생략하면 `git rev-parse HEAD`로 현재 Revision을
확인합니다. Git Worktree가 Dirty하거나 명시한 SHA가 현재 HEAD와 다르면 평가를
거부합니다. Git이 없는 실행 환경에서는 소문자 40자리 Commit SHA를 반드시
명시하며, 이 경우 `worktree_clean`은 `null`로 기록합니다. 검증 결과는
Evaluation JSON과 Manifest의 `evaluation_source`에 기록합니다.

## 출력 Bundle

```text
data/evaluations/packet-if-eval-v1/
├── packet-if-predictions.jsonl
├── packet-if-evaluation.json
├── packet-if-evaluation.csv
├── evaluation-manifest.json
└── evaluation-manifest.json.sha256
```

- `packet-if-predictions.jsonl`: Test Row별 Score·판정·Feature·Source 식별자
- `packet-if-evaluation.json`: 전체·Label·Session·Scenario별 평가 Summary
- `packet-if-evaluation.csv`: 보고서와 Spreadsheet용 파생 Summary
- `evaluation-manifest.json`: 입력 Provenance와 출력 파일별 크기·SHA256
- `evaluation-manifest.json.sha256`: Evaluation Manifest 검증용 SHA256 Sidecar

Manifest 자체의 SHA256은 Manifest 내부에 넣지 않고 표준 `sha256sum` 형식의
Sidecar에 기록하며 CLI에도 출력합니다. Manifest와 Sidecar는 같은 Staging
Directory에서 생성하여 함께 게시합니다. 기존 출력 Directory는 덮어쓰지
않습니다. 평가 중 오류가 발생하면 완성되지 않은 최종 Directory를 게시하지
않으며, 재평가는 새로운 Version Directory에서 수행합니다.

실제 Dataset, Model과 평가 출력은 Git에 Commit하지 않습니다.
CSV의 외부 문자열이 `=`, `+`, `-`, `@` 등 Spreadsheet 수식 접두사로
해석될 수 있는 경우에는 앞에 작은따옴표를 붙여 수식 실행을 방지합니다.

## 평가 지표

전체 Test, Label, Session과 Scenario 기준으로 다음 값을 기록합니다.

- TP, FP, TN, FN
- Precision, Recall, F1
- 정상 Packet Feature Window 기준 `normal_window_fpr`
- 공격 Packet Feature Row 기준 `row_tpr`
- 공격 Capture Session 기준 `attack_session_tpr`
- 공격 Session 수와 한 개 이상의 이상 Window가 탐지된 Session 수
- 정상·공격 Row 수
- 정상·이상 판정 Row 수
- Anomaly Score Min·Max·Mean·P5·P50·P95·P99

분모가 0인 비율은 `0`으로 바꾸지 않고 JSON에서는 `null`, CSV에서는 빈 값으로
기록하며 `undefined_metrics`에 사유를 함께 남깁니다. Session별 Summary는
Label과 Scenario가 하나로 일치해야 합니다. 공격 Session은 해당 Session의
Test Row 중 하나 이상이 이상으로 판정되면 탐지 성공으로 집계합니다.

Trainer의 Training Report에 포함된 Test Score는 진단 자료이며 Threshold
산정에는 사용하지 않습니다. 공식 Offline Test Summary는 이 평가 CLI에서
생성하고, Pi E2E는 Train·Validation·Offline Test에 사용하지 않은 Holdout
Session으로 별도 검증합니다. 최종 Threshold 보정은 Phase 6 계약을 따릅니다.

## 인계 항목

Pi 배포 담당자에게 아래 값을 함께 전달합니다.

- Dataset Version·SHA256과 Dataset Manifest SHA256
- Model Version·Artifact Directory·Bundle SHA256
- Threshold·Percentile·비교 연산자
- Capture Policy Version
- Artifact Metadata의 학습 Source Commit SHA
- 평가 실행 Source Commit SHA
- Evaluation Manifest와 `evaluation-manifest.json.sha256` Sidecar
- Offline 평가 Summary

Pi E2E에는 Train·Validation·Offline Test와 Threshold 산정에 사용하지 않은
Holdout 공격 Session을 사용합니다.

## 검증

```bash
python -m pytest -q \
  tests/test_packet_if_contract.py \
  tests/test_packet_if_dataset.py \
  tests/test_export_packet_if_dataset.py \
  tests/test_train_packet_isolation_forest.py \
  tests/test_predict_packet_isolation_forest.py \
  tests/test_evaluate_packet_isolation_forest.py

python -m ai.evaluate_packet_isolation_forest --help
python -m compileall -q ai edge backend tests
python -m pip check
git diff --check
```
