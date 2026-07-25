from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import parse_allowed_origins, settings
from .routers import (
    dashboard,
    detection_events,
    devices,
    feature_logs,
    firewall_rules,
    gateway_metrics,
    health,
    isolation,
    mqtt_logs,
    packet_feature_logs,
    trust_score,
)

app = FastAPI(title="IoT Edge Zero Trust API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_allowed_origins(
        settings.api_allowed_origins,
        allow_credentials=settings.api_allow_credentials,
    ),
    allow_credentials=settings.api_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(mqtt_logs.router, prefix="/api")
app.include_router(feature_logs.router, prefix="/api")
app.include_router(packet_feature_logs.router, prefix="/api")
app.include_router(gateway_metrics.router, prefix="/api")
app.include_router(firewall_rules.router, prefix="/api")
app.include_router(detection_events.router, prefix="/api")
app.include_router(trust_score.router, prefix="/api")
app.include_router(isolation.router, prefix="/api")
