from fastapi import FastAPI

from app.routers import health

app = FastAPI(title="Hanium MQTT Security API")

app.include_router(health.router, prefix="/api")

