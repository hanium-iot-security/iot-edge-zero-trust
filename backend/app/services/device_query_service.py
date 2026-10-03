"""Device reads share the policy snapshot used by management responses."""

from backend.app.services.device_policy_service import get_device, list_devices

__all__ = ["get_device", "list_devices"]
