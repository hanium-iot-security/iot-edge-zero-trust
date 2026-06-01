"""Malformed payload 공격 시나리오 진입점.

저장되는 detection event_type은 MALFORMED_PAYLOAD를 사용해야 합니다.
"""


def main() -> None:
    raise NotImplementedError("유효한 JSON이 아닌 payload를 보내도록 구현해야 합니다.")


if __name__ == "__main__":
    main()
