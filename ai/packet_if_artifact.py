"""Packet IF Artifact Bundle digest helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from ai.packet_if_contract import (
    PACKET_IF_METADATA_FILENAME,
    PACKET_IF_MODEL_FILENAME,
    PACKET_IF_TRAINING_REPORT_FILENAME,
)


PACKET_IF_BUNDLE_FILENAMES = (
    PACKET_IF_MODEL_FILENAME,
    PACKET_IF_METADATA_FILENAME,
    PACKET_IF_TRAINING_REPORT_FILENAME,
)


def packet_if_bundle_sha256(artifact_dir: Path) -> str:
    files = {
        filename: (artifact_dir / filename).read_bytes()
        for filename in PACKET_IF_BUNDLE_FILENAMES
    }
    return packet_if_bundle_sha256_bytes(files)


def packet_if_bundle_sha256_bytes(files: Mapping[str, bytes]) -> str:
    missing = [
        filename
        for filename in PACKET_IF_BUNDLE_FILENAMES
        if filename not in files
    ]
    if missing:
        raise ValueError(f"Packet IF Bundle is missing files: {missing}")

    digest = hashlib.sha256()
    for filename in PACKET_IF_BUNDLE_FILENAMES:
        name_bytes = filename.encode("utf-8")
        content = files[filename]
        digest.update(len(name_bytes).to_bytes(4, "big"))
        digest.update(name_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def bytes_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
