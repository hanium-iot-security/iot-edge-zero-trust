from fastapi import APIRouter

from backend.app.schemas.model_schema import ModelInfoResponse
from backend.app.services.model_info_service import build_model_info


router = APIRouter(prefix="/models", tags=["models"])


@router.get("", response_model=ModelInfoResponse)
def get_models() -> dict:
    return build_model_info()
