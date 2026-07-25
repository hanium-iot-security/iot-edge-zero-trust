from pydantic_settings import BaseSettings, SettingsConfigDict
from urllib.parse import urlparse


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
    capture_interface_ip: str = ""
    feature_window_seconds: int = 10
    initial_trust_score: int = 100
    isolation_threshold: int = 30
    api_allowed_origins: str = DEFAULT_API_ALLOWED_ORIGINS
    api_allow_credentials: bool = True

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
