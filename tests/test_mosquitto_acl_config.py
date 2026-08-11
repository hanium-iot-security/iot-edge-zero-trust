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

    def test_no_password_values_present(self) -> None:
        # ACL 파일은 Principal 이름과 Topic 정책만 있어야 한다. 설명 주석에서 "Password"라는 단어 자체는 등장할 수 있지만,
        # 실제 지시어 줄에는 password/secret 관련 지시어나 해시처럼 보이는 값이 없어야 한다.
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
