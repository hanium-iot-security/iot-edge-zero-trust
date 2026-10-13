# Phase 9 MQTT IF 후보 학습

`ai.train_mqtt_isolation_forest`는 독립 Train·Validation 자료로 **offline 후보 Bundle**을 만드는 개발 도구다. Train만 fit하고, 첫 Validation 그룹(`calibration`)으로 임계값을 정한 뒤 두 번째 Validation 그룹(`validation`)에 고정 임계값을 적용한다. 기존 [MQTT Bundle](phase9-mqtt-if-offline-bundle.md)의 5개 Feature·identity 변환·`decision_function` 점수·`score < threshold` 계약을 유지한다.

실제 데이터의 학습 편입 승인이나 운영 활성화를 수행하지 않는다. 입력과 결과의 `training_approved=false`는 유지한다. 현재 150분 후보를 공식 학습 자료로 바꾸거나 같은 Capture Session을 T/V로 쪼개지 않는다. 기존 `ai.train_isolation_forest`, `ai.export_normal_features`와 운영 모델은 그대로다.

## 입력 준비

수집·QC를 다시 구현하지 않고 기존 `ai.normal_admission`의 request/report, 원본 Run manifest, 후보 QC report와 `mqtt-features.csv`를 읽는다. 작은 JSON 입력목록에서 각 파일의 상대 경로와 SHA256을 고정한다. 입력목록과 실제 읽은 파일들의 해시·역할·그룹·Run·선택 건수를 결과 보고서에 보존한다.

| 학습 역할 | 기존 admission split | 사용 |
| --- | --- | --- |
| `train` | `train` | 모델 fit |
| `calibration` | `validation` | 정상 점수의 하위 percentile로 임계값 보정 |
| `validation` | `validation` | 고정 모델·임계값으로 독립 정상 평가 |

세 역할에는 서로 다른 `source_capture_group_id`가 필요하다. 같은 원본 그룹의 다른 Run·기기·Profile을 별도 역할로 나누면 거부한다. `test`와 `UNASSIGNED`를 재해석하지 않으며 최종 Holdout은 입력하지 않는다. Run·collection slot 중복도 거부한다. 공식 수집 규모(T1·T2, V1·V2 등)는 [정상 운용 기준](phase9-normal-operating-range.md)을 따른다. 작은 합성 fixture의 학습 성공이 그 규모나 실제 다양성을 충족했다는 의미는 아니다.

`BOUNDED_ELIGIBLE`/QC `PASS` 결과와 파일 해시·그룹·범위·기기·건수의 일치를 확인한다. 이 검사는 기존 보고서와 파일의 연결을 확인하는 것이며, 원본 PCAP/DB를 재검사하거나 보고서의 진실성·자료 승인을 인증하지 않는다. 승인 기록을 새로 발급하지 않는다.

선택 전에는 기기별로 범위 내 완전한 UTC 10초 Window가 빠짐없이 한 행씩 있는지 확인한다. 숫자를 명시적으로 변환한 뒤 기존 `mqtt_feature_vector`와 `phase9-normal-v1` 선택 정책을 재사용한다. 단일 메시지의 5초 간격은 관측값이 아닌 기존 fallback이다. Pico의 100B 초과 행을 크기만으로 제외하지 않는다. 선택 전·후·제외 건수와 이유를 기록하며 각 역할·기기에 선택 행이 없으면 실패한다.

입력목록의 형식은 다음과 같다. `path`는 목록 파일 기준 상대 경로이고 `sha256`은 해당 파일 바이트의 소문자 SHA256이다. 기존 request 안의 Run 경로·manifest SHA와 새 목록도 일치해야 한다.

| 위치 | 필드 |
| --- | --- |
| 최상위 | `schema_version="mqtt-if-candidate-dataset-v1"`, `normal_selection_policy="phase9-normal-v1"`, `device_ids`, `groups` |
| 각 `groups[]` | `role`, `admission_request={path,sha256}`, `admission_report={path,sha256}`, `runs` |
| 각 `runs[]` | `manifest={path,sha256}`, `qc_report={path,sha256}`, `mqtt_features={path,sha256}` |

세 역할의 최소 합성 입력 예제는 `tests/test_mqtt_if_dataset.py`의 `_write_dataset`을 참고한다. 이 helper의 request/report는 시험용으로 직접 작성한 값이다. 실제 exporter·admission을 합성 DB/PCAP에 실행하고 그 산출물을 연결하는 예제는 같은 파일의 `test_real_export_and_admission_outputs_load_without_mutating_sources`다. 시험용 request/report를 실제 수집이 통과한 근거로 사용하지 않는다.

## 실행

기존 Python 가상환경에서 저장소 루트를 작업 디렉터리로 사용한다. 입력목록이 `data/mqtt-candidate-inputs/dataset.json`에 준비된 경우의 예시다. `1` percentile은 명령 예시이며 공식 품질 기준이 아니다.

```powershell
python -m ai.train_mqtt_isolation_forest --manifest data/mqtt-candidate-inputs/dataset.json --artifact-dir output/mqtt-if-experiment-01 --model-version mqtt-if-experiment-01 --threshold-percentile 1
```

출력 디렉터리 이름은 `model_version`과 일치해야 하고 입력목록의 디렉터리 밖에 있어야 한다. 기본값은 `--n-estimators 100 --random-state 42`다. 실행 checkout의 Git HEAD와 수정 여부도 기록한다. 깨끗한 Commit에서 실행하면 소스 재현이 쉬우며 dirty 결과는 그 사실을 숨기지 않는다. 콘솔은 후보 Bundle 경로·임계값·Bundle SHA256과 승인·활성화 false를 출력한다.

## 학습과 결과 해석

IsolationForest는 고정 seed, `n_jobs=1`, `contamination="auto"`로 학습한다. MQTT 점수는 낮을수록 이상이므로 임계값은 **calibration 점수의 하위 percentile**이다. percentile은 호출자가 명시해야 하며 도구가 공식 허용 오탐률을 정하지 않는다. `score == threshold`는 정상으로 판정한다. 별도 scaling·imputation이나 기기별 모델은 추가하지 않는다.

평가용 Validation은 fit과 임계값 보정에 참여하지 않는다. 보고서는 전체·기기·그룹별 정상 경보 건수와 비율을 남긴다. 정상으로 가정한 후보만 입력하므로 이 비율은 공격 탐지율·정밀도·F1이나 모델 채택 근거가 아니다. 평가 결과를 보고 다시 임계값을 조정하면 독립 평가라는 전제가 깨지므로 새 실험과 별도 자료로 기록해야 한다.

출력은 `model.joblib`, `metadata.json`, `training_report.json` 세 파일이다. 입력 해시·정책·분할·선택 수, 학습 설정·seed, 소스 Commit, 라이브러리 버전, 임계값 보정 방법을 기록하고 기존 Bundle inspector/loader로 재검증한다. 기존 출력은 덮어쓰지 않으며 실패한 생성 중간 파일을 완성 Bundle로 남기지 않는다. 출력 Bundle SHA256은 후속 검토에서 외부 pin으로 보관한다. 해시 일치 자체가 모델이나 자료의 승인은 아니다.

## 검증과 다음 단계

이번 검증은 합성 자료로 입력 연결, 그룹 분리, Train-only fit, 보정·평가 분리, 변조 거부, Bundle 저장·재로딩을 확인한다. 실제 후보 학습·공식 성능 평가·Pi 활성화는 수행하지 않았다.

2026/10/13 Windows Python 3.10.11에서 신규 두 모듈 **39 passed**, 기존 Bundle·admission·수집 Export·선택 정책·legacy MQTT Export·AI 탐지·MQTT pipeline 회귀는 **247 passed, 5 skipped**였다. skip은 이 호스트가 허용하지 않는 기존 symlink 시험이다. NumPy 2.0.2, SciPy 1.15.3, scikit-learn 1.6.1, joblib 1.4.2 환경을 사용했다.

```powershell
python -m pytest tests/test_mqtt_if_dataset.py tests/test_train_mqtt_isolation_forest.py tests/test_mqtt_if_artifact.py tests/test_normal_admission.py tests/test_normal_selection_policy.py -q
```

Pi 사용이 가능해지면 독립 정상 수집 그룹을 확보하고 기존 QC·bounded admission 결과를 검토해 실제 학습 편입 근거를 연결한다. 그 뒤 후보 비교를 수행하고, 운영 loader·시작 경계·모델 활성화 연결은 별도 작업으로 검증한다. 이 CLI 실행 성공만으로 Phase 9 공식 학습이나 운영 적용을 완료 처리하지 않는다.
