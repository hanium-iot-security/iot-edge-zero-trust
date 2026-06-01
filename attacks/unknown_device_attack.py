"""Unknown device 공격 시나리오 진입점.

저장되는 detection event_type은 UNKNOWN_DEVICE를 사용해야 합니다.
"""


def main() -> None:
    raise NotImplementedError("등록되지 않은 device ID로 telemetry를 publish하도록 구현해야 합니다.")


if __name__ == "__main__":
    main()
