from fastapi import FastAPI

from .routers import (
    dashboard,
    detection_events,
    devices,
    feature_logs,
    health,
    isolation,
    mqtt_logs,
    trust_score,
)

app = FastAPI(title="IoT Edge Zero Trust API")

app.include_router(health.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(mqtt_logs.router, prefix="/api")
app.include_router(feature_logs.router, prefix="/api")
app.include_router(detection_events.router, prefix="/api")
app.include_router(trust_score.router, prefix="/api")
app.include_router(isolation.router, prefix="/api")
