from pathlib import Path


NORMAL_SENDER = Path("firmware/esp32/normal_sender/normal_sender.ino")
NORMAL_SENDER_CREDENTIALS_EXAMPLE = Path(
    "firmware/esp32/normal_sender/mqtt_credentials.example.h"
)
ATTACK_SENDER = Path("firmware/esp32/attack_sender/attack_sender.ino")
ATTACK_SENDER_CREDENTIALS_EXAMPLE = Path(
    "firmware/esp32/attack_sender/mqtt_credentials.example.h"
)
GITIGNORE = Path(".gitignore")


def test_normal_sender_supports_optional_mqtt_credentials() -> None:
    source = NORMAL_SENDER.read_text(encoding="utf-8")

    assert '#if __has_include("mqtt_credentials.h")' in source
    assert '#include "mqtt_credentials.h"' in source
    assert '#define MQTT_USERNAME ""' in source
    assert '#define MQTT_PASSWORD ""' in source
    assert "strlen(MQTT_USERNAME) > 0" in source
    assert "mqttClient.connect(clientId.c_str(), MQTT_USERNAME, MQTT_PASSWORD)" in source
    # 익명 Fallback 경로도 여전히 남아 있어야 전환 기간 호환이 유지된다.
    assert "mqttClient.connect(clientId.c_str())" in source


def test_attack_sender_supports_optional_mqtt_credentials() -> None:
    source = ATTACK_SENDER.read_text(encoding="utf-8")

    assert '#if __has_include("mqtt_credentials.h")' in source
    assert '#include "mqtt_credentials.h"' in source
    assert '#define MQTT_USERNAME ""' in source
    assert '#define MQTT_PASSWORD ""' in source
    assert "bool mqttConnectWithCredentials(const char* clientId)" in source
    assert "strlen(MQTT_USERNAME) > 0" in source
    assert "mqttClient.connect(clientId, MQTT_USERNAME, MQTT_PASSWORD)" in source

    # 두 연결 지점 모두 공용 Credential Helper를 거쳐야 하고, 더 이상 원본
    # mqttClient.connect(...)를 직접 호출하지 않아야 한다(중복 구현 방지).
    assert 'mqttConnectWithCredentials("phase4_attack_esp32_02")' in source
    assert 'mqttConnectWithCredentials("phase4_observation_esp32_02")' in source
    assert 'mqttClient.connect("phase4_attack_esp32_02")' not in source
    assert 'mqttClient.connect("phase4_observation_esp32_02")' not in source


def test_mqtt_credentials_example_headers_document_the_right_device() -> None:
    normal_example = NORMAL_SENDER_CREDENTIALS_EXAMPLE.read_text(encoding="utf-8")
    attack_example = ATTACK_SENDER_CREDENTIALS_EXAMPLE.read_text(encoding="utf-8")

    assert '#define MQTT_USERNAME "esp32_01"' in normal_example
    assert "mqtt_credentials.h" in normal_example
    assert "Git 제외" in normal_example

    assert '#define MQTT_USERNAME "esp32_02"' in attack_example
    assert "mqtt_credentials.h" in attack_example
    assert "Git 제외" in attack_example

    # 실제 비밀번호로 보일 수 있는 값을 커밋하지 않는다 — Placeholder만 존재해야 한다.
    for example in (normal_example, attack_example):
        assert "REPLACE_WITH_MQTT_PASSWORD" in example


def test_gitignore_excludes_real_mqtt_credential_headers() -> None:
    gitignore = GITIGNORE.read_text(encoding="utf-8")

    assert "firmware/esp32/normal_sender/mqtt_credentials.h" in gitignore
    assert "firmware/esp32/attack_sender/mqtt_credentials.h" in gitignore
