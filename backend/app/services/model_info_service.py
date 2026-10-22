"""Inspect configured model bundles; never deserialize or activate a model."""
from datetime import datetime, timezone
from pathlib import Path
import re

from ai.packet_if_artifact import PACKET_IF_BUNDLE_FILENAMES
from ai.predict_packet_isolation_forest import inspect_packet_if_artifact
from ai.mqtt_if_artifact import MQTT_IF_BUNDLE_FILENAMES, inspect_mqtt_if_bundle
from backend.app.config import settings
from edge.detection.packet_checkpoint_pair_manager import Error as UnsafePathError, _safe_path


MAX_ARTIFACT_FILE_BYTES = 64 * 1024 * 1024
PUBLIC_METADATA_FIELDS = (
    "model_type", "model_version", "feature_version", "feature_order",
    "transform_version", "score_direction", "threshold", "threshold_operator",
    "threshold_source", "threshold_percentile", "dataset_version",
    "created_at",
    "dataset_sha256", "manifest_sha256",
)
MQTT_PUBLIC_METADATA_FIELDS = (
    "artifact_schema_version", "model_type", "model_version", "feature_version", "feature_order",
    "transform_version", "nominal_window_seconds", "score_method", "score_direction",
    "threshold", "threshold_operator", "threshold_source", "interval_semantics",
)


def _mqtt_model_info() -> dict:
    version = settings.mqtt_if_expected_model_version.strip()
    pin = settings.mqtt_if_expected_bundle_sha256.strip()
    directory = settings.mqtt_if_artifact_dir.strip()
    item = {
        "detector": "mqtt_if", "artifact_status": "LEGACY_CONTRACT_UNAVAILABLE",
        "configured_model_version": version or None,
        "configured_bundle_sha256": pin if re.fullmatch(r"[0-9a-f]{64}", pin) else None,
        "artifact": None, "checks": {},
        "runtime": {"status": "UNKNOWN", "reason_code": "RUNTIME_MODEL_EVIDENCE_NOT_AVAILABLE"},
        "error_code": "MQTT_IF_PINNED_ARTIFACT_CONTRACT_UNAVAILABLE",
    }
    if not any((directory, version, pin)):
        return item
    if not all((directory, version, pin)):
        item.update(artifact_status="UNCONFIGURED", error_code="MQTT_IF_CONFIGURATION_INCOMPLETE")
        return item
    try:
        artifact_dir = _safe_path(Path(directory))
        for filename in MQTT_IF_BUNDLE_FILENAMES:
            _safe_path(artifact_dir / filename)
        inspected = inspect_mqtt_if_bundle(
            artifact_dir, expected_bundle_sha256=pin, expected_model_version=version,
            maximum_file_bytes=MAX_ARTIFACT_FILE_BYTES,
        )
        metadata = inspected.metadata
        item.update(
            artifact_status="BUNDLE_METADATA_VERIFIED", error_code=None,
            artifact={key: metadata[key] for key in MQTT_PUBLIC_METADATA_FIELDS},
            checks={"bundle_sha256_verified": True, "metadata_contract_verified": True,
                    "report_sha256_verified": True, "report_json_object_verified": True},
        )
        item["artifact"]["bundle_sha256"] = inspected.bundle_sha256
    except OSError:
        item.update(artifact_status="UNAVAILABLE", error_code="MQTT_IF_ARTIFACT_UNAVAILABLE")
    except (ValueError, RuntimeError, UnsafePathError) as error:
        if isinstance(error.__cause__, OSError):
            item.update(artifact_status="UNAVAILABLE", error_code="MQTT_IF_ARTIFACT_UNAVAILABLE")
        else:
            item.update(artifact_status="INVALID", error_code="MQTT_IF_ARTIFACT_INVALID")
    return item


def build_model_info() -> dict:
    version = settings.packet_if_expected_model_version.strip()
    pin = settings.packet_if_expected_bundle_sha256.strip()
    directory = settings.packet_if_artifact_dir.strip()
    packet = {
        "detector": "packet_if", "artifact_status": "UNCONFIGURED",
        "configured_model_version": version or None,
        "configured_bundle_sha256": pin if re.fullmatch(r"[0-9a-f]{64}", pin) else None,
        "artifact": None, "checks": {}, "error_code": None,
        "runtime": {"status": "UNKNOWN", "reason_code": "RUNTIME_MODEL_EVIDENCE_NOT_AVAILABLE"},
    }
    if not directory or not version or not pin:
        packet["error_code"] = "PACKET_IF_CONFIGURATION_INCOMPLETE"
    else:
        try:
            artifact_dir = _safe_path(Path(directory))
            for filename in PACKET_IF_BUNDLE_FILENAMES:
                member = _safe_path(artifact_dir / filename)
                if not member.is_file():
                    raise FileNotFoundError(filename)
                if member.stat().st_size > MAX_ARTIFACT_FILE_BYTES:
                    raise ValueError("artifact exceeds inspection size limit")
            inspected = inspect_packet_if_artifact(
                artifact_dir, expected_bundle_sha256=pin,
                expected_model_version=version,
                maximum_file_bytes=MAX_ARTIFACT_FILE_BYTES,
            )
            packet.update(
                artifact_status="BUNDLE_METADATA_VERIFIED",
                artifact={key: inspected.metadata[key] for key in PUBLIC_METADATA_FIELDS},
                checks={"bundle_sha256_verified": True, "metadata_contract_verified": True,
                        "report_sha256_verified": True, "report_json_object_verified": True},
            )
            packet["artifact"]["bundle_sha256"] = inspected.bundle_sha256
            packet["artifact"]["normal_policy_version"] = inspected.metadata.get("normal_policy_version")
            packet["artifact"]["row_counts"] = {
                key: inspected.metadata["row_counts"][key] for key in ("train", "validation", "test")
            }
            packet["artifact"]["capture_policy"] = {
                key: inspected.metadata["capture_policy"][key] for key in (
                    "version", "nominal_window_seconds", "max_start_delay_seconds",
                    "minimum_duration_seconds", "epsilon_seconds", "minimum_coverage_ratio",
                )
            }
        except (OSError, PermissionError):
            packet.update(artifact_status="UNAVAILABLE", error_code="PACKET_IF_ARTIFACT_UNAVAILABLE")
        except (ValueError, RuntimeError, UnsafePathError) as error:
            if isinstance(error.__cause__, OSError):
                packet.update(artifact_status="UNAVAILABLE", error_code="PACKET_IF_ARTIFACT_UNAVAILABLE")
            else:
                packet.update(artifact_status="INVALID", error_code="PACKET_IF_ARTIFACT_INVALID")
    return {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "models": [packet, _mqtt_model_info()],
    }
