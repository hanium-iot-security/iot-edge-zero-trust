"""Phase 5 Packet IF Dataset Manifest v2 provenance helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
import json
from pathlib import PurePosixPath, Path
import re
from typing import Any
from uuid import UUID

from edge.phase5.contracts import (
    ManifestStatus,
    RUN_MANIFEST_SHA256_SIDECAR_SUFFIX,
    RunManifest,
    is_supported_run_manifest_schema_version,
    run_manifest_sha256,
)
from edge.phase5.verified_collection_contract import (
    VERIFIED_COLLECTION_SCHEMA_VERSION,
    DatasetSessionIdentity,
    VerifiedCollectionManifest,
    load_verified_collection_manifest,
    validate_verified_collection_identity,
)


PACKET_IF_DATASET_VERSION_V1 = "packet-if-dataset-v1"
PACKET_IF_DATASET_VERSION_V2 = "packet-if-dataset-v2"
PACKET_IF_DATASET_VERSION_V3 = "packet-if-dataset-v3"
SUPPORTED_PACKET_IF_DATASET_VERSIONS = frozenset(
    {PACKET_IF_DATASET_VERSION_V1, PACKET_IF_DATASET_VERSION_V2, PACKET_IF_DATASET_VERSION_V3}
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PORTABLE_PATH_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED_PATH_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)
_RUN_MANIFEST_FILENAME = "run-manifest.json"


@dataclass(frozen=True)
class PacketIFRunManifestReference:
    run_id: str
    relative_path: str
    schema_version: str
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", require_identifier(self.run_id, "run_id"))
        relative_path = normalize_relative_path(
            self.relative_path,
            "run_manifest_ref.relative_path",
        )
        if PurePosixPath(relative_path).name != _RUN_MANIFEST_FILENAME:
            raise ValueError(
                "run_manifest_ref.relative_path must end with "
                f"{_RUN_MANIFEST_FILENAME!r}"
            )
        object.__setattr__(
            self,
            "relative_path",
            relative_path,
        )
        schema_version = require_non_empty_string(
            self.schema_version,
            "run_manifest_ref.schema_version",
        )
        if not is_supported_run_manifest_schema_version(schema_version):
            raise ValueError(
                "unsupported Run Manifest schema version: "
                f"{schema_version!r}"
            )
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(
            self,
            "sha256",
            normalize_sha256(self.sha256, "run_manifest_ref.sha256"),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PacketIFRunManifestReference":
        allowed = {"run_id", "relative_path", "schema_version", "sha256"}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise ValueError(f"run_manifest_ref contains unknown fields: {unknown}")
        missing = sorted(allowed - set(payload))
        if missing:
            raise ValueError(f"run_manifest_ref is missing fields: {missing}")
        return cls(
            run_id=payload["run_id"],
            relative_path=payload["relative_path"],
            schema_version=payload["schema_version"],
            sha256=payload["sha256"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "relative_path": self.relative_path,
            "schema_version": self.schema_version,
            "sha256": self.sha256,
        }


def assert_run_manifest_complete(manifest: RunManifest, run_id: str) -> None:
    """Raise ValueError if the Run Manifest is not a completed SUCCESS run."""
    if manifest.is_active:
        raise ValueError(
            f"Run Manifest {run_id!r} is still active (is_active=True); "
            "only completed Runs may be referenced in a Dataset Manifest"
        )
    if manifest.ended_at is None:
        raise ValueError(
            f"Run Manifest {run_id!r} has no ended_at; "
            "only completed Runs may be referenced in a Dataset Manifest"
        )
    if manifest.statuses.scenario_status != ManifestStatus.SUCCESS:
        raise ValueError(
            f"Run Manifest {run_id!r} scenario_status must be ManifestStatus.SUCCESS; "
            f"got {manifest.statuses.scenario_status!r}"
        )


def load_verified_run_manifest(
    path: Path,
    *,
    expected_sha256: str,
) -> RunManifest:
    """Load a Run Manifest only after canonical JSON and sidecar verification."""
    expected = normalize_sha256(expected_sha256, "expected_run_manifest_sha256")
    try:
        raw_manifest = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read Run Manifest: {path}") from exc

    try:
        manifest = RunManifest.from_json(raw_manifest)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid Run Manifest: {path}") from exc

    actual = run_manifest_sha256(manifest)
    if actual != expected:
        # Older v1 pins predate the optional firewall release ID field. Accept
        # only that missing null; all other typed normalization stays pinned.
        raw_payload = json.loads(raw_manifest)
        legacy_payload = manifest.to_dict()
        release_ids = legacy_payload["matched_ids"].pop("firewall_release_request_ids")
        raw_sha256 = run_manifest_sha256(raw_payload)
        if (
            raw_payload.get("run_manifest_schema_version") == "phase5-run-manifest-v1"
            and release_ids is None
            and "firewall_release_request_ids" not in raw_payload.get("matched_ids", {})
            and run_manifest_sha256(legacy_payload) == raw_sha256
        ):
            actual = raw_sha256
    if actual != expected:
        raise ValueError(
            "Run Manifest SHA256 mismatch: "
            f"expected={expected}, actual={actual}"
        )

    sidecar_path = Path(f"{path}{RUN_MANIFEST_SHA256_SIDECAR_SUFFIX}")
    sidecar_sha256 = _read_sha256_sidecar(sidecar_path)
    if sidecar_sha256 != expected:
        raise ValueError(
            "Run Manifest sidecar SHA256 mismatch: "
            f"expected={expected}, actual={sidecar_sha256}"
        )
    return manifest


def load_verified_session_manifest(
    run_manifest_path: Path,
    run_manifest: RunManifest,
    *,
    session_id: str,
    scenario: str,
    target_device_id: str | None,
    target_source_ip: str | None,
    included_device_ips: Mapping[str, str],
    dataset_identity: DatasetSessionIdentity | None = None,
    required: bool = False,
) -> VerifiedCollectionManifest | None:
    """Verify the Run Manifest's Verified Collection reference, when present.

    Existing Scenario Runner Runs carry `session_manifest_ref=null` and stay
    accepted with `required=False`; only Verified Collection Runs must resolve.
    The reference is resolved relative to the already-verified Run Manifest, so
    the whole chain Dataset -> Run -> Collection -> Evidence is hash-verified.
    """
    reference = run_manifest.session_manifest_ref
    if reference is None:
        if required:
            raise ValueError(
                "Verified Collection Runs must declare session_manifest_ref: "
                f"run_id={run_manifest.run_id!r}"
            )
        return None

    if reference.schema_version != VERIFIED_COLLECTION_SCHEMA_VERSION:
        raise ValueError(
            "unsupported session_manifest_ref schema version: "
            f"{reference.schema_version!r}"
        )

    run_directory = run_manifest_path.parent.resolve()
    collection_path = (run_directory / reference.relative_path).resolve()
    if run_directory not in collection_path.parents:
        raise ValueError(
            "session_manifest_ref escapes the Run Manifest directory: "
            f"{reference.relative_path}"
        )

    collection = load_verified_collection_manifest(
        collection_path,
        expected_sha256=reference.sha256,
    )
    validate_verified_collection_identity(
        collection,
        run_manifest=run_manifest,
        session_id=session_id,
        scenario=scenario,
        target_device_id=target_device_id,
        target_source_ip=target_source_ip,
        included_device_ips=included_device_ips,
        dataset_identity=dataset_identity,
    )
    return collection


def validate_run_manifest_identity(
    manifest: RunManifest,
    reference: PacketIFRunManifestReference,
    *,
    session_id: str,
    scenario: str,
    target_device_id: str | None,
    target_source_ip: str | None,
    included_device_ips: Mapping[str, str] | None = None,
) -> None:
    if manifest.run_id != reference.run_id:
        raise ValueError(
            "Run Manifest run_id mismatch: "
            f"expected={reference.run_id!r}, actual={manifest.run_id!r}"
        )
    if manifest.run_manifest_schema_version != reference.schema_version:
        raise ValueError(
            "Run Manifest schema version mismatch: "
            f"expected={reference.schema_version!r}, "
            f"actual={manifest.run_manifest_schema_version!r}"
        )
    if manifest.session_id != session_id:
        raise ValueError(
            "Run Manifest session_id mismatch: "
            f"expected={session_id!r}, actual={manifest.session_id!r}"
        )
    if manifest.scenario.scenario_id != scenario:
        raise ValueError(
            "Run Manifest scenario_id mismatch: "
            f"expected={scenario!r}, actual={manifest.scenario.scenario_id!r}"
        )
    if target_device_id is None:
        normalized_devices = dict(included_device_ips or {})
        run_device_id = manifest.target_device_id
        if run_device_id not in normalized_devices:
            raise ValueError(
                "normal Run Manifest target_device_id must identify an included "
                f"Device: actual={run_device_id!r}"
            )
        expected_source_ip = normalized_devices[run_device_id]
        if manifest.source_ip != expected_source_ip:
            raise ValueError(
                "normal Run Manifest source_ip must match its included Device: "
                f"expected={expected_source_ip!r}, actual={manifest.source_ip!r}"
            )
        return

    if manifest.target_device_id != target_device_id:
        raise ValueError(
            "Run Manifest target_device_id mismatch: "
            f"expected={target_device_id!r}, actual={manifest.target_device_id!r}"
        )
    if manifest.source_ip != target_source_ip:
        raise ValueError(
            "Run Manifest source_ip mismatch: "
            f"expected={target_source_ip!r}, actual={manifest.source_ip!r}"
        )


def require_identifier(value: Any, field_name: str) -> str:
    text = require_non_empty_string(value, field_name)
    if _IDENTIFIER_RE.fullmatch(text) is None:
        raise ValueError(
            f"{field_name} must use letters, numbers, '.', '_', ':', or '-'"
        )
    return text


def require_canonical_uuid4(value: Any, field_name: str) -> str:
    text = require_non_empty_string(value, field_name)
    try:
        parsed = UUID(text)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a canonical UUID4") from exc
    if parsed.version != 4 or str(parsed) != text:
        raise ValueError(f"{field_name} must be a canonical UUID4")
    return text


def require_non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    text = value.strip()
    if any(ord(character) < 32 for character in text):
        raise ValueError(f"{field_name} must not contain control characters")
    if len(text) > 256:
        raise ValueError(f"{field_name} must be at most 256 characters")
    return text


def normalize_relative_path(value: Any, field_name: str) -> str:
    text = require_non_empty_string(value, field_name).replace("\\", "/")
    if text.startswith(("/", "//")) or _WINDOWS_DRIVE_RE.match(text):
        raise ValueError(f"{field_name} must be a relative path")
    parts = PurePosixPath(text).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{field_name} must not contain '.', '..', or empty parts")
    for part in parts:
        if (
            _PORTABLE_PATH_PART_RE.fullmatch(part) is None
            or part.endswith(".")
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_PATH_NAMES
        ):
            raise ValueError(
                f"{field_name} contains a non-portable path component: "
                f"{part!r}"
            )
    return "/".join(parts)


def normalize_sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a 64-character hexadecimal string")
    return value.lower()


def normalize_optional_ipv4(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    text = require_non_empty_string(value, field_name)
    try:
        parsed = ip_address(text)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IPv4 address") from exc
    if not isinstance(parsed, IPv4Address):
        raise ValueError(f"{field_name} must be a valid IPv4 address")
    return str(parsed)


def normalize_device_ids(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{field_name} must be a non-empty array")
    normalized = tuple(require_identifier(item, f"{field_name}[]") for item in value)
    if not normalized:
        raise ValueError(f"{field_name} must be a non-empty array")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicates")
    return tuple(sorted(normalized))


def require_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _read_sha256_sidecar(path: Path) -> str:
    try:
        content = path.read_text(encoding="ascii")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read Run Manifest SHA256 sidecar: {path}") from exc
    lines = content.splitlines()
    if len(lines) != 1:
        raise ValueError("Run Manifest SHA256 sidecar must contain exactly one line")
    tokens = lines[0].split()
    if not tokens or len(tokens) > 2:
        raise ValueError("invalid Run Manifest SHA256 sidecar format")
    if len(tokens) == 2:
        referenced_name = tokens[1].removeprefix("*")
        expected_name = path.name.removesuffix(
            RUN_MANIFEST_SHA256_SIDECAR_SUFFIX
        )
        if referenced_name != expected_name:
            raise ValueError(
                "Run Manifest SHA256 sidecar references the wrong file: "
                f"expected={expected_name!r}, actual={referenced_name!r}"
            )
    return normalize_sha256(tokens[0], "run_manifest_sidecar_sha256")
