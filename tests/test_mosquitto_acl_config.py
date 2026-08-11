"""Mosquitto 설정·ACL·Credential 문서 검증.

실제 Broker 동작(Own Topic PASS / Cross Topic DENY / Wrong Password DENY /
Anonymous DENY / Subscriber Read PASS·Write DENY)은 이 저장소 개발 과정에서
실제 Mosquitto(2.0.18, apt 패키지)로 직접 검증했다. 이 테스트 파일은 그
검증을 뒷받침하는 설정 파일들이 저장소에 올바른 형태로 존재하는지, 그리고
"acl_file을 allow_anonymous true 상태에서 먼저 켜면 안 된다"는 안전 불변식이
운영 mosquitto.conf에서 계속 지켜지는지 확인한다.
"""

from __future__ import annotations

from pathlib import Path
import re


MOSQUITTO_CONF = Path("infra/mosquitto/mosquitto.conf")
MOSQUITTO_STRICT_CONF = Path("infra/mosquitto/mosquitto-strict.conf")
ACL_FILE = Path("infra/mosquitto/aclfile.conf")
PASSWD_EXAMPLE = Path("infra/mosquitto/passwd.example")
README = Path("infra/mosquitto/README.md")

_DIRECTIVE_LINE = re.compile(r"^\s*(\S+)")


def _directive_lines(text: str) -> list[str]:
    """주석·빈 줄을 제외한 실제 설정 지시어 줄만 반환한다."""
    lines = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


class TestTransitionalMosquittoConf:
    """운영 mosquitto.conf는 acl_file 도입 전(Phase 6-A 5.3 전환 순서 1~6단계)."""

    def test_keeps_anonymous_allowed_on_both_listeners(self) -> None:
        lines = _directive_lines(MOSQUITTO_CONF.read_text(encoding="utf-8"))
        assert lines.count("allow_anonymous true") == 2

    def test_does_not_load_acl_file_or_password_file_yet(self) -> None:
        lines = _directive_lines(MOSQUITTO_CONF.read_text(encoding="utf-8"))
        assert not any(line.startswith("acl_file") for line in lines)
        assert not any(line.startswith("password_file") for line in lines)

    def test_has_both_listeners(self) -> None:
        lines = _directive_lines(MOSQUITTO_CONF.read_text(encoding="utf-8"))
        assert "listener 1883" in lines
        assert "listener 9001" in lines
        assert "protocol websockets" in lines


class TestStrictMosquittoConf:
    """mosquitto-strict.conf는 Strict Test Listener이자 전환 후 목표 설정."""

    def test_enforces_authentication_on_both_listeners(self) -> None:
        lines = _directive_lines(MOSQUITTO_STRICT_CONF.read_text(encoding="utf-8"))
        assert lines.count("allow_anonymous false") == 2

    def test_references_password_file_and_acl_file_on_both_listeners(self) -> None:
        lines = _directive_lines(MOSQUITTO_STRICT_CONF.read_text(encoding="utf-8"))
        assert lines.count("password_file /etc/mosquitto/passwd") == 2
        assert lines.count("acl_file /etc/mosquitto/aclfile.conf") == 2

    def test_has_both_listeners(self) -> None:
        lines = _directive_lines(MOSQUITTO_STRICT_CONF.read_text(encoding="utf-8"))
        assert "listener 1883" in lines
        assert "listener 9001" in lines


class TestAclFile:
    def test_defines_all_four_principals(self) -> None:
        lines = _directive_lines(ACL_FILE.read_text(encoding="utf-8"))
        assert "user esp32_01" in lines
        assert "user esp32_02" in lines
        assert "user edge_subscriber" in lines
        assert "user mqtt_test_tool" in lines

    def test_esp32_principals_can_only_write_their_own_topic(self) -> None:
        source = ACL_FILE.read_text(encoding="utf-8")
        esp32_01_block = source.split("user esp32_01", 1)[1].split("user esp32_02", 1)[0]
        assert "topic write iot/esp32_01/sensor" in esp32_01_block
        assert "read" not in esp32_01_block

    def test_edge_subscriber_is_read_only(self) -> None:
        source = ACL_FILE.read_text(encoding="utf-8")
        block = source.split("user edge_subscriber", 1)[1].split(
            "user mqtt_test_tool", 1
        )[0]
        assert "topic read iot/+/sensor" in block
        assert "write" not in block

    def test_test_tool_has_full_namespace_access(self) -> None:
        source = ACL_FILE.read_text(encoding="utf-8")
        block = source.split("user mqtt_test_tool", 1)[1]
        assert "topic write #" in block
        assert "topic read #" in block

    def test_test_tool_scope_covers_every_attack_script_topic(self) -> None:
        import re as _re

        from attacks.config import MALICIOUS_TOPICS
        from attacks.abnormal_topic_attack import _ABNORMAL_TOPIC_POOL
        from attacks.unknown_device_attack import _ABNORMAL_TOPICS

        source = ACL_FILE.read_text(encoding="utf-8")
        block = source.split("user mqtt_test_tool", 1)[1]
        assert _re.search(r"^topic write #\s*$", block, _re.MULTILINE), (
            "mqtt_test_tool must allow write on the full namespace (#) so every "
            "attack-script topic (including non-iot/ ones) is publishable"
        )

        all_attack_topics = set(MALICIOUS_TOPICS) | set(_ABNORMAL_TOPIC_POOL) | set(
            _ABNORMAL_TOPICS
        )
        assert all_attack_topics, "sanity check: attack topic pools must not be empty"

    def test_no_password_values_present(self) -> None:
        lines = _directive_lines(ACL_FILE.read_text(encoding="utf-8"))
        for line in lines:
            assert not line.startswith("password"), f"password directive found: {line!r}"
        assert "password_file" not in ACL_FILE.read_text(encoding="utf-8")


class TestPasswdExample:
    def test_documents_mosquitto_passwd_generation(self) -> None:
        text = PASSWD_EXAMPLE.read_text(encoding="utf-8")
        assert "mosquitto_passwd -c /etc/mosquitto/passwd esp32_01" in text
        assert "mosquitto_passwd /etc/mosquitto/passwd esp32_02" in text
        assert "mosquitto_passwd /etc/mosquitto/passwd edge_subscriber" in text
        assert "mosquitto_passwd /etc/mosquitto/passwd mqtt_test_tool" in text

    def test_uses_placeholders_not_real_looking_secrets(self) -> None:
        text = PASSWD_EXAMPLE.read_text(encoding="utf-8")
        assert "<salt-placeholder>" in text
        assert "<hash-placeholder>" in text

    def test_documents_rollback(self) -> None:
        text = PASSWD_EXAMPLE.read_text(encoding="utf-8")
        assert "systemctl restart mosquitto" in text
        assert "cp -a" in text

    def test_references_the_actual_esp32_credential_header_paths(self) -> None:
        text = PASSWD_EXAMPLE.read_text(encoding="utf-8")
        assert "firmware/esp32/normal_sender/mqtt_credentials.example.h" in text
        assert "firmware/esp32/attack_sender/mqtt_credentials.example.h" in text
        assert Path("firmware/esp32/normal_sender/mqtt_credentials.example.h").is_file()
        assert Path("firmware/esp32/attack_sender/mqtt_credentials.example.h").is_file()


class TestMosquittoReadme:
    def test_documents_rollout_sequence(self) -> None:
        text = README.read_text(encoding="utf-8")
        for required in (
            "mosquitto-strict.conf",
            "aclfile.conf",
            "passwd.example",
            "edge.scripts.mqtt_acl_test_pack",
            "Denied PUBLISH",
            "DEVICE_ID_MISMATCH",
            "통신 암호화",
        ):
            assert required in text
