# MQTT IF 독립 offline 계약

이번 준비 인터페이스는 타입이 있는 MQTT 입력 행, 세 파일 Bundle의 무결성, 모델의 학습 상태·입력 차원·라이브러리 호환성, 점수 판정 계약을 검증한다. 학습, 자료 편입·QC, 운영 loader, Orchestrator, API, DB, Pi 활성화에는 연결하지 않았다. 공식 MQTT 후보를 학습하거나 승인하지 않았으며 시험에서만 synthetic fixture를 fit한다.

[P9-02 계획](https://app.notion.com/p/3f296c0fdc1c80f78f50d43800e25b72)은 공식 학습 전에 P9-01 자료 적격성과 독립 Train/Validation 그룹을, 운영 적용 전에 P9-03 시작 경계 검증을 요구한다. 해당 계약과 구현은 별도 남은 작업이다. 기존 150분 후보 자료는 사용하지 않았다. 이 인터페이스는 Dataset manifest, 승인, 그룹 배정, split, 자료 해시, 정상 정책 버전, 평가 결과를 만들거나 검증하지 않는다.

## 입력과 점수

`ai.mqtt_if_contract`는 아래 순서를 유지하고 identity transform을 적용한다.

| Feature | 입력 행의 필수 타입 | 의미 |
| --- | --- | --- |
| `publish_count` | 음이 아닌 정수 | nominal 10초 Window의 메시지 수 |
| `avg_payload_size` | 유한한 음이 아닌 실수 | 평균 Payload 크기, bytes |
| `max_payload_size` | 음이 아닌 정수 | 최대 Payload 크기, bytes |
| `avg_message_interval` | 유한한 음이 아닌 실수 | Window 안 평균 수신 간격 또는 대체값, 초 |
| `min_message_interval` | 유한한 음이 아닌 실수 | Window 안 최소 수신 간격 또는 대체값, 초 |

결측값, 숫자 문자열, bool, NaN/Inf, 음수는 거부한다. 정수 필드는 현재 DB Integer 행 계약에 맞춰 `2.5`뿐 아니라 `2.0`도 거부한다. 후속 CSV parser는 명시적인 변환과 자료 계약을 별도로 처리해야 한다. 100B 상한, 정상 범위 필터, clipping, scaling, imputation은 적용하지 않는다. sklearn IF가 내부에서 입력을 float32로 변환하므로 matrix는 float32로 유한하게 표현할 수 없는 값을 거부한다.

기존 builder는 메시지가 한 건이면 두 간격을 모두 `5.0`으로 대체한다. 이는 **실측 송신 주기가 아닌 대체값**이다. 한 건 행의 간격 중 하나라도 `5.0`과 다르면 기존 Feature 계약 불일치로 거부한다. 추론 결과는 `publish_count == 1`일 때 `interval_is_fallback`을 표시하며 metadata/report에도 같은 의미를 기록한다. 두 건 이상은 해당 Window 안 수신 시각의 차이를 사용하고, 동일 시각의 `0.0` 간격도 허용한다. Window를 넘는 실제 송신 주기 적격성은 원본 연속 기록과 별도 QC로 확인해야 한다. 타입 검증만으로 완전한 Window, Capture 품질, 출처, 정상 여부를 입증하지 않는다. 메시지 수가 0인 행도 숫자 계약만 검증한다.

MQTT는 `raw_decision_score = anomaly_score = model.decision_function(X)`를 유지한다. **낮을수록 이상**이며 `score < threshold`로 판정하고 경계와 같으면 이상이 아니다. Packet의 부호 반전 점수·`>` 연산과 구별한다. 이 인터페이스는 `model.predict`를 사용하지 않으며 contamination 경계를 별도 Validation Threshold로 취급하지 않는다. `threshold_source`는 작성자의 설명이며 보정 결과를 검증했다는 뜻이 아니다.

## Bundle 검사와 offline 사용

해시에는 `model.joblib`, `metadata.json`, `training_report.json` 세 파일만 참여하며 디렉터리의 다른 파일은 포함하지 않는다. symlink가 아닌 일반 파일을 각각 한 번 읽고, 바이트를 변경할 수 없는 검사 snapshot에 보관한다. Bundle 해시는 기존 Packet framing을 재사용한다. 위 순서대로 4바이트 big-endian UTF-8 파일명 길이, 파일명, 8바이트 big-endian 내용 길이, 내용을 연결한다. metadata는 모델·보고서의 개별 SHA256도 고정한다. 외부 Bundle SHA256은 신뢰할 수 있는 검토 경로로 받아야 한다. 검사 대상 디렉터리에서 즉석 계산한 해시만으로 신뢰를 확보할 수는 없다.

```python
from pathlib import Path
from ai.mqtt_if_artifact import (
    inspect_mqtt_if_bundle,
    load_inspected_mqtt_if_artifact,
    score_mqtt_feature_rows,
)

inspection = inspect_mqtt_if_bundle(
    Path("private-candidate-directory"),
    expected_bundle_sha256=trusted_external_pin,
    expected_model_version="reviewed-candidate-id",
)
print(inspection.summary())  # 모델 역직렬화 없음
artifact = load_inspected_mqtt_if_artifact(inspection)
predictions = score_mqtt_feature_rows(artifact, typed_feature_rows)
```

inspect는 unpickle 전에 외부 고정 해시, 두 JSON 객체, metadata 필드, 보고서의 계약 일치, 라이브러리 버전을 확인한다. load는 같은 메모리 snapshot을 재확인하고 `BytesIO`의 모델 바이트를 역직렬화한다. 파일 경로를 다시 열거나 파일명으로 cache하지 않는다. 검사 뒤 파일을 교체해도 이미 검사한 모델·metadata·보고서를 바꿀 수 없으며 교체 후 기존 해시로 새로 검사하면 실패한다. Bundle 해시는 바이트 일치만 검증한다. 신뢰하지 않는 pickle을 안전하게 만들거나 자료 적격성·보고서 통계의 진실성을 인증하지 않는다.

metadata schema v1의 필수 필드는 다음과 같다.

- `artifact_schema_version: 1`, `model_type: "IsolationForest"`, 비어 있지 않은 `model_version`;
- 고정 `model_filename`, `training_report_filename`과 각각의 소문자 SHA256 필드;
- `feature_version: "mqtt-if-features-v1"`, 위 다섯 항목의 `feature_order`, `transform_version: "mqtt-identity-v1"`, `nominal_window_seconds: 10.0`;
- `score_method: "decision_function"`, `score_direction: "lower_is_more_anomalous"`, `threshold_operator: "<"`, 유한한 `threshold`, 비어 있지 않은 `threshold_source`;
- `interval_semantics: {"single_message_fallback_seconds": 5.0, "single_message_is_observed_interval": false, "multi_message_source": "within_window_received_at_differences"}`;
- `library_versions`: Python major/minor 일치(patch 차이는 허용), 설치된 `numpy`, `scipy`, `scikit_learn`, `joblib` 버전의 정확한 일치.

보고서는 `model_version`, `feature_order`, 점수 함수·방향, 비교 연산, threshold·source, 간격 의미를 반복 기록한다. 다른 보고서 주장은 보관하지만 인증하지 않는다. JSON key 중복과 비표준 NaN/Infinity 상수는 거부한다. load는 정확한 sklearn `IsolationForest` 클래스, 학습된 estimator 상태, 입력 다섯 개, 저장된 Feature 이름이 있으면 순서 일치, 유한한 offset, 유효한 유한 점수 출력을 요구한다. metadata가 현재 버전이라고 주장하더라도 모델 역직렬화의 sklearn 버전 불일치 경고는 실패 처리한다. 공식 학습 metadata의 설정·seed, 출처, split·그룹별 행 수, Commit, 정책, 보정 근거는 실제 P9-01·trainer 계약으로 추가해야 한다. 이번 인터페이스에서 검증하지 않는다는 이유로 공식 학습에서 생략할 수는 없다.

inspect 요약은 `data_eligibility_verified`, `report_claims_verified`, `operational_activation_verified`를 false로 명시한다. offline 추론 성공은 이벤트·checkpoint·Trust 변경·활성화를 만들지 않는다.

## 검증

기존 Python 의존성이 설치된 가상환경을 활성화하고 깨끗한 로컬 checkout에서 실행한다.

```powershell
python -m pytest tests/test_mqtt_if_artifact.py tests/test_ai_detector.py tests/test_mqtt_feature_pipeline.py tests/test_predict_packet_isolation_forest.py -q
```

시험은 100B 초과 입력, 기존 builder의 한 건·두 건 의미, 정확한 Threshold 경계, 파일 변조, 오래된 보고서, unpickle 이전 Feature·변환·점수·라이브러리 불일치, 한 번 읽은 snapshot의 파일 교체, 학습된 모델 타입·차원, 잘못된 점수 출력을 확인한다. 통과 범위는 offline 코드 계약이며 실제 정상·공격 성능, Dataset QC, 공식 학습, Pi 배포·활성화는 미실행이다.

2026/10/11 Windows 로컬 시험에서 위 네 모듈 회귀는 **169개 통과, 1개 건너뜀**(6.15초)이다. 실제 symlink 생성이 허용되지 않아 해당 fixture 한 건을 건너뛰었다. 같은 소스 해시를 Pi의 일반 계정·별도 임시 디렉터리로 전달한 신규 모듈 합성 시험은 **106개 통과, skip 없음**(2.65초)이며 실제 symlink 검사를 포함한다. Pi Python 3.10.11·라이브러리는 위 로컬 계약과 일치한다. 기존 운영 DB·자료·모델을 사용하거나 서비스를 중단하지 않았고, 시험 프로세스 그룹의 살아 있는 구성원 0명·직접 자식 회수·임시 디렉터리 정리를 확인했다. 네 모듈 전체 회귀는 로컬에서만 실행했다. 파일 교체 중 inode 변경 검사는 통과했고 신규 Python 파일의 compile 검사·`git diff --check`도 통과했다. 개인 경로·명령·원본 출력·파일별 해시는 비공개 `output/phase9-resume-20261011/mqtt-if-offline-bundle-validation-20261011.json`에 보관한다. Pi 합성 시험의 import 경로·소스 해시·원본 결과·정리 확인은 비공개 `output/phase9-resume-20261011/mqtt-if-linux-synthetic-validation-20261011.json`에 보관한다. 시험 후 세 기기 수신과 필수 처리 경계의 전진을 읽기 전용으로 확인했다. 이 결과는 공식 자료 학습·정상/공격 성능·운영 배포·활성화의 근거가 아니다.
