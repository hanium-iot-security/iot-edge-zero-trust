"""Phase 5 Packet IF Dataset Manifest v2 provenance helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
from pathlib import PurePosixPath, Path
import re
from typing import Any
from uuid import UUID

from edge.phase5.contracts import (
    RUN_MANIFEST_SHA256_SIDECAR_SUFFIX,
    RunManifest,
    is_supported_run_manifest_schema_version,
    run_manifest_sha256,
)


PACKET_IF_DATASET_VERSION_V1 = "packet-if-dataset-v1"
PACKET_IF_DATASET_VERSION_V2 = "packet-if-dataset-v2"
SUPPORTED_PACKET_IF_DATASET_VERSIONS = frozenset(
    {PACKET_IF_DATASET_VERSION_V1, PACKET_IF_DATASET_VERSION_V2}
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
