# Packet IF 외부 평가(Holdout) 경로

기존 평가기(`ai/evaluate_packet_isolation_forest.py`)는 학습에 쓴 Dataset과 해시가 같은 자료의 test split만 평가한다. 동결한 모델을
새로 수집한 독립 자료로 평가하려면 이 검사를 완화하지 않고 별도 진입 경로가 필요하다. `ai/evaluate_packet_external_holdout.py`가 그 경로다.
Threshold는 Artifact의 값을 그대로 쓰며 다시 산정하지 않는다. 이 도구는 어떤 승인도 발급하지 않는다.

```
python -m ai.evaluate_packet_external_holdout --request request.json --output-dir <새 폴더>
```

## 외부 Holdout 자료

모든 Session이 `split=test`인 기존 Dataset 번들(CSV + Manifest)이다. `load_packet_if_dataset(..., external_holdout=True)`로 읽으며
컬럼·행·Session·해시·Run Manifest 참조·그룹 검증은 기존과 같다. 이 옵션은 세 Split 필수와 "test에 정상·공격 Session이 모두 있어야 한다"는
조건만 바꾼다(정상만 또는 공격만 있는 평가 자료 허용). 기본 동작은 변하지 않는다.

## 요청 (`packet-external-eval-request-v1`, 알 수 없는 필드는 거부)

`purpose`(`DEVELOPMENT`|`FINAL`), `artifact`(`dir`, `expected_bundle_sha256`, 선택 `expected_model_version`),
`dataset`(`csv`, `csv_sha256`, `manifest`, `manifest_sha256`), `training_manifest`(`path`, `sha256`),
`prior_manifests`[{`path`, `sha256`, `role`}](개발에 이미 쓴 자료), FINAL이면 `freeze`{`record_sha256`, `frozen_at`, `code_commit_sha`}.
경로는 요청 파일이 있는 폴더 기준이다.

## 검사 (하나라도 실패하면 HOLD, 평가 결과를 게시하지 않고 새 폴더에 `external-evaluation-hold.json`만 기록)

1. Artifact 고정 번들 해시, Dataset·Manifest·학습 Manifest·이력 Manifest의 선언 해시
2. Capture Policy와 정상 정책 버전이 Artifact와 같을 것(비호환이면 HOLD, 과거 정책을 재명명하지 않음)
3. 학습 Manifest의 해시가 Artifact 메타의 `manifest_sha256`과 같고, 그 Session 목록이 Artifact 메타의 `sessions`와 일치
4. 외부 Session의 `session_id`, `source_capture_group_id`, Run ID, `collection_slot_id`, Session `data_sha256`이 학습 Manifest와 모든 이력 Manifest와
   겹치지 않을 것(이름만 바꾼 중복도 `data_sha256`으로 잡는다)
5. FINAL은 `freeze`가 필수이고 모든 Session의 `started_at`이 `frozen_at` 이후일 것. DEVELOPMENT는 `freeze`를 받지 않으며 결과에 최종 평가가 아님을 기록
6. 평가 중과 게시 직전에 입력 파일이 바뀌지 않았을 것

## 출력

새 디렉터리에만 게시한다. 기존 평가기의 지표 집계와 게시 절차(`predictions`, `evaluation.json/csv`, `evaluation-manifest.json` + sha256)를 재사용하고
`evaluation_schema_version`은 `packet-if-external-evaluation-v1`이다. `external_evaluation` 블록에 목적, 동결 기록, 비중복 검사 요약, 학습·이력
Manifest 해시와 `threshold_recalculated=false`를 남긴다. 종료 코드는 게시 0, HOLD·입력 오류 2다.

## 한계

실제 최종 평가는 동결된 후보와 새로 수집한 독립 자료가 있을 때 실행한다. 학습 Manifest가 보관돼 있지 않으면 이 도구는 HOLD가 정상 결과다.
