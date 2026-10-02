from typing import Literal
from urllib.parse import urlparse

from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_API_ALLOWED_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"


class Settings(BaseSettings):
    app_env: str = "local"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    database_url: str = "sqlite:///./backend/data/iot_security.db"
    mqtt_host: str = "localhost"
    mqtt_port: int = 1883
    mqtt_normal_topic: str = "iot/+/sensor"
    mqtt_subscribe_topic: str = "iot/+/sensor"
    mqtt_subscriber_username: str = ""
    mqtt_subscriber_password: str = ""
    mqtt_test_tool_username: str = ""
    mqtt_test_tool_password: str = ""
    capture_interface_ip: str = ""
    feature_window_seconds: int = 10
    initial_trust_score: int = 100
    isolation_threshold: int = 30
    api_allowed_origins: str = DEFAULT_API_ALLOWED_ORIGINS
    api_allow_credentials: bool = True
    recovery_admin_api_key: str = ""
    recovery_admin_principal: str = "recovery-admin"
    recovery_artifact_dir: str = "data/recovery/baseline"

    # MQTT Feature Producer
    mqtt_feature_builder_interval_seconds: float = 5.0
    mqtt_feature_builder_lock_path: str = ""

    # Detection Orchestrator
    orchestrator_interval_seconds: float = 5.0
    orchestrator_enabled_stages: str = "mqtt_feature_rule,mqtt_message_rule"
    orchestrator_required_stages: str = "mqtt_feature_rule,mqtt_message_rule"
    orchestrator_lock_path: str = ""
    # AI inference/checkpoints keep running in both modes. Only Trust changes.
    trust_ai_mode: Literal["enforce", "observe"] = "enforce"

    # Gateway Metrics
    gateway_metrics_interval_seconds: float = 10.0
    internal_lan_interface: str = "eth0"
    usb_lan_interface: str = "eth1"

    # Packet Capture
    capture_interface: str = "eth0"
    pcap_window_seconds: int = 10
    pcap_capture_filter: str = "tcp or udp"
    pcap_incoming_dir: str = "data/pcap/incoming"
    pcap_ready_dir: str = "data/pcap/ready"
    pcap_processed_dir: str = "data/pcap/processed"
    pcap_failed_dir: str = "data/pcap/failed"
    pcap_samples_dir: str = "data/pcap/samples"
    pcap_retention_hours: int = 1
    pcap_max_storage_mb: int = 1024
    failed_pcap_retention_hours: int = 24
    failed_pcap_max_storage_mb: int = 256
    failed_pcap_max_files: int = 20
    pcap_max_start_delay_seconds: float = 1.0
    packet_min_capture_duration_seconds: float = 9.0
    capture_time_epsilon_seconds: float = 0.01
    capture_policy_version: str = "packet-capture-policy-v1"

    # Packet Isolation Forest
    packet_if_artifact_dir: str = ""
    packet_if_expected_model_version: str = ""
    packet_if_expected_bundle_sha256: str = ""

    # Packet Rule Detector
    packet_rule_packet_rate_threshold: float = 10.0
    packet_rule_byte_rate_threshold: float = 2_500.0
    packet_rule_port_scan_distinct_port_threshold: int = 5
    packet_rule_port_scan_syn_threshold: int = 5
    packet_rule_broker_dos_tcp_syn_threshold: int = 10
    packet_rule_broker_dos_mqtt_packet_threshold: int = 20
    packet_rule_excluded_peer_ips: str = ""
    packet_rule_policy_version: str = "packet-rule-policy-v3"

    # Firewall Worker
    firewall_worker_interval_seconds: float = 5.0
    firewall_worker_batch_size: int = 20
    firewall_retry_delay_seconds: int = 30
    firewall_protected_ips: str = ""
    firewall_wrapper_path: str = "/usr/local/sbin/hanium-firewall-rule"
    firewall_sudo_path: str = "/usr/bin/sudo"
    firewall_command_timeout_seconds: float = 10.0
    firewall_lock_path: str = ""
    firewall_lock_wait_seconds: float = 15.0
    # Worker가 실제 iptables를 읽고 기록하는 read-only Recovery 검증 Snapshot.
    # API는 NoNewPrivileges=true를 유지하며 sudo/iptables를 직접 실행하지 않는다.
    firewall_runtime_snapshot_path: str = "data/runtime/firewall-runtime.json"
    firewall_runtime_snapshot_max_age_seconds: float = 15.0

    model_config = SettingsConfigDict(env_file=(".env", "../.env"), env_file_encoding="utf-8")


settings = Settings()


def parse_allowed_origins(
    raw_origins: str,
    *,
    allow_credentials: bool = True,
) -> list[str]:
    origins: list[str] = []
    seen: set[str] = set()
    for part in raw_origins.split(","):
        origin = part.strip()
        if not origin:
            continue
        if origin == "*":
            if allow_credentials:
                raise ValueError("API_ALLOWED_ORIGINS cannot be '*' when credentials are allowed")
            if origin not in seen:
                origins.append(origin)
                seen.add(origin)
            continue

        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("API_ALLOWED_ORIGINS entries must use http or https")
        if not parsed.netloc:
            raise ValueError("API_ALLOWED_ORIGINS entries must include a host")
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            raise ValueError("API_ALLOWED_ORIGINS entries must not include path, query, or fragment")
        normalized = origin.rstrip("/")
        if normalized not in seen:
            origins.append(normalized)
            seen.add(normalized)
    return origins
