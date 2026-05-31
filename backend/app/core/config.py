from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "local"
    database_url: str = "sqlite:///./data/iot_security.db"
    mqtt_host: str = "localhost"
    mqtt_port: int = 1883
    feature_window_seconds: int = 10
    trust_score_initial: int = 100
    trust_score_isolation_threshold: int = 50

    model_config = SettingsConfigDict(env_file=("../.env", ".env"), env_file_encoding="utf-8")


settings = Settings()
