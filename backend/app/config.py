from pydantic_settings import BaseSettings, SettingsConfigDict


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
