"""Isolation Forest 추론 도우미.

입력 feature:
- publish_count
- avg_payload_size
- max_payload_size
- avg_message_interval
- min_message_interval
"""


def predict_feature_window() -> None:
    raise NotImplementedError("학습된 Isolation Forest 모델을 불러와 feature window 하나를 평가하도록 구현해야 합니다.")
