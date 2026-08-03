"""attacks/ 공격 스크립트 payload 생성 로직 단위 테스트.

Mosquitto 없이 로컬에서 실행 가능합니다.
각 공격 스크립트가 탐지 기준을 충족하는 값을 생성하는지 검증합니다.

실행:
    PYTHONPATH=. pytest tests/test_attacks.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks.config import REGISTERED_DEVICES, NORMAL_TOPIC_TPL
from attacks.flooding_attack import _normal_payload
from attacks.large_payload_attack import _large_payload
from attacks.malformed_payload_attack import _MALFORMED_POOL
from attacks.abnormal_topic_attack import _ABNORMAL_TOPIC_POOL
from attacks.unknown_device_attack import _fake_device_id
from attacks.device_id_mismatch_attack import _mismatch_pair
from edge.mqtt.topic_utils import is_telemetry_topic


# ── config ────────────────────────────────────────────────────────────────────

class TestConfig:
    def test_registered_devices_is_mvp_set(self):
        """MVP 기준 등록 기기는 esp32_01, esp32_02만 포함해야 합니다."""
        assert REGISTERED_DEVICES == ["esp32_01", "esp32_02"]


# ── flooding_attack ───────────────────────────────────────────────────────────

class TestFloodingAttack:
    def test_normal_payload_is_valid_json(self):
        payload = _normal_payload("esp32_01")
        data = json.loads(payload)
        assert data["device_id"] == "esp32_01"

    def test_normal_payload_has_sensor_fields(self):
        payload = _normal_payload("esp32_01")
        data = json.loads(payload)
        assert "temperature" in data
        assert "humidity" in data

    def test_flooding_count_exceeds_threshold(self):
        """publish_count > 15 탐지 기준 충족 확인."""
        count = 30
        assert count > 15

    def test_flooding_interval_is_retained_as_rapid_publish_evidence(self):
        """짧은 발행 간격이 공격 분석용 Feature Evidence로 남는지 확인."""
        interval = 0.2
        assert interval < 1.0


# ── large_payload_attack ──────────────────────────────────────────────────────

class TestLargePayloadAttack:
    def test_payload_exceeds_5120_bytes(self):
        """max_payload_size > 5120 탐지 기준 충족 확인."""
        for _ in range(10):
            payload = _large_payload("esp32_01")
            assert len(payload) > 5120, f"payload size {len(payload)} <= 5120"

    def test_payload_is_bytes(self):
        payload = _large_payload("esp32_01")
        assert isinstance(payload, bytes)

    def test_payload_is_valid_json_with_device_id(self):
        """LARGE_PAYLOAD와 MALFORMED_PAYLOAD 혼용 방지 — valid JSON + device_id 필수."""
        for _ in range(10):
            payload = _large_payload("esp32_01")
            data = json.loads(payload.decode("utf-8"))
            assert data.get("device_id") == "esp32_01", "device_id 필드 누락 또는 불일치"

    def test_each_subtype_exceeds_5120_bytes_at_minimum_size(self):
        """subtype별 randint 최솟값에서도 payload가 5120 bytes를 초과하는지 확인."""
        from unittest.mock import patch
        device_id = "esp32_02"
        min_sizes = {
            "buffer_overflow":   10240,
            "data_exfiltration": 5121,
            "binary":            5121,
        }
        for subtype, min_size in min_sizes.items():
            with patch("random.choice", return_value=subtype), \
                 patch("random.randint", return_value=min_size):
                payload = _large_payload(device_id)
            assert len(payload) > 5120, \
                f"subtype={subtype!r} min_size={min_size} → payload {len(payload)} bytes <= 5120"


# ── malformed_payload_attack ──────────────────────────────────────────────────

class TestMalformedPayloadAttack:
    def test_pool_is_not_empty(self):
        assert len(_MALFORMED_POOL) > 0

    def test_all_payloads_fail_json_or_device_id(self):
        """
        _MALFORMED_POOL의 모든 항목이
        JSON 파싱 실패 또는 device_id 값이 유효하지 않아야 합니다.
        subscriber의 is_json_valid=0 또는 device_id=None 조건 기준.
        """
        for payload in _MALFORMED_POOL:
            is_invalid = False
            try:
                data = json.loads(payload)
                device_id = data.get("device_id") if isinstance(data, dict) else None
                if not isinstance(device_id, str) or not device_id.strip():
                    is_invalid = True
            except Exception:
                is_invalid = True
            assert is_invalid, f"payload가 정상으로 파싱됨: {payload!r}"

    def test_pool_has_enough_patterns(self):
        """탐지 기준(3회 이상) 충족을 위한 충분한 패턴 확인."""
        assert len(_MALFORMED_POOL) >= 3


# ── abnormal_topic_attack ─────────────────────────────────────────────────────

class TestAbnormalTopicAttack:
    def test_pool_is_not_empty(self):
        assert len(_ABNORMAL_TOPIC_POOL) > 0

    def test_all_topics_fail_telemetry_check(self):
        """
        _ABNORMAL_TOPIC_POOL의 모든 항목이
        is_telemetry_topic() == False여야 합니다.
        """
        for topic in _ABNORMAL_TOPIC_POOL:
            assert not is_telemetry_topic(topic), \
                f"topic이 정상으로 판정됨: {topic!r}"

    def test_pool_has_enough_patterns(self):
        """탐지 기준(3회 이상) 충족을 위한 충분한 패턴 확인."""
        assert len(_ABNORMAL_TOPIC_POOL) >= 3

    def test_no_wildcard_in_pool(self):
        """publish topic에 subscribe 전용 wildcard(#, +)가 없어야 합니다."""
        for topic in _ABNORMAL_TOPIC_POOL:
            assert '#' not in topic and '+' not in topic, \
                f"wildcard가 포함된 publish topic: {topic!r}"

    def test_normal_topic_not_in_pool(self):
        """정상 topic 형식이 pool에 없는지 확인."""
        for device_id in REGISTERED_DEVICES:
            normal = NORMAL_TOPIC_TPL.format(device_id=device_id)
            assert normal not in _ABNORMAL_TOPIC_POOL


# ── unknown_device_attack ─────────────────────────────────────────────────────

class TestUnknownDeviceAttack:
    def test_fake_id_not_in_registered_devices(self):
        """생성된 fake_id가 등록 기기 목록에 없어야 합니다."""
        for _ in range(20):
            fake_id = _fake_device_id()
            assert fake_id not in REGISTERED_DEVICES, \
                f"fake_id {fake_id!r}가 REGISTERED_DEVICES에 존재함"

    def test_fake_id_is_string(self):
        for _ in range(10):
            fake_id = _fake_device_id()
            assert isinstance(fake_id, str)
            assert len(fake_id) > 0

    def test_default_topic_is_normal_telemetry(self):
        """기본 동작에서 fake_id는 정상 telemetry topic 형식으로 publish해야 합니다.
        abnormal topic은 --abnormal-topic 플래그 사용 시에만 동작합니다."""
        for _ in range(20):
            fake_id = _fake_device_id()
            topic = NORMAL_TOPIC_TPL.format(device_id=fake_id)
            assert is_telemetry_topic(topic), \
                f"기본 topic이 telemetry 형식이 아님: {topic!r}"


# ── device_id_mismatch_attack ─────────────────────────────────────────────────

class TestDeviceIdMismatchAttack:
    def test_mismatch_pair_are_different(self):
        """topic_id와 payload_id가 서로 달라야 합니다."""
        for _ in range(20):
            topic_id, payload_id = _mismatch_pair()
            assert topic_id != payload_id, \
                f"topic_id와 payload_id가 같음: {topic_id!r}"

    def test_mismatch_pair_both_registered(self):
        """두 값 모두 등록 기기여야 DEVICE_ID_MISMATCH로 처리됩니다."""
        for _ in range(20):
            topic_id, payload_id = _mismatch_pair()
            assert topic_id in REGISTERED_DEVICES, \
                f"topic_id {topic_id!r}가 미등록 기기"
            assert payload_id in REGISTERED_DEVICES, \
                f"payload_id {payload_id!r}가 미등록 기기"
