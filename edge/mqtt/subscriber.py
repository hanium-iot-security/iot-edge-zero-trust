"""iot/+/sensor에서 ESP32 telemetry를 받아 저장하는 MQTT subscriber 진입점."""


def main() -> None:
    raise NotImplementedError("Mosquitto에 연결하고 iot/+/sensor를 구독한 뒤 payload 검증과 MQTT log 저장을 구현해야 합니다.")


if __name__ == "__main__":
    main()
