"""Abnormal topic 공격 시나리오 진입점.

저장되는 detection event_type은 ABNORMAL_TOPIC을 사용해야 합니다.
"""


def main() -> None:
    raise NotImplementedError("허용된 topic 정책 밖의 topic으로 telemetry를 publish하도록 구현해야 합니다.")


if __name__ == "__main__":
    main()
