from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "local"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    database_url: str = "sqlite:///./backend/data/iot_security.db"
    mqtt_host: str = "localhost"
    mqtt_port: int = 1883
    mqtt_normal_topic: str = "iot/+/sensor"
    mqtt_attack_topic: str = "attack/#"
    feature_window_seconds: int = 10
    initial_trust_score: int = 100
    isolation_threshold: int = 30

    model_config = SettingsConfigDict(env_file=(".env", "../.env"), env_file_encoding="utf-8")


settings = Settings()
