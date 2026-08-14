"""Read-only runtime firewall snapshot contract for Recovery preflight.

The FastAPI service deliberately runs with ``NoNewPrivileges=true`` and must not
invoke sudo/iptables directly. The privileged Firewall Worker already owns the
narrow root wrapper boundary, so it periodically records what it actually sees
in the INPUT chain. Recovery reads only this short-lived JSON snapshot.

This module never inserts, deletes, or changes firewall rules. Any missing,
stale, malformed, or unavailable observation fails closed as ``UNAVAILABLE``.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import shlex
from typing import Any, Mapping
from uuid import uuid4

from edge.trust.firewall_worker import (
    ACTION,
    CHAIN,
    COMMENT_PREFIX,
    DEST_PORT,
    LIST_RULES,
    PROTOCOL,
    IptablesRunner,
)


SNAPSHOT_SCHEMA_VERSION = "firewall-runtime-snapshot-v1"
DEFAULT_MAX_FUTURE_SKEW_SECONDS = 5.0


class FirewallRuntimeSnapshotError(ValueError):
    """Runtime observation or snapshot payload cannot be trusted."""


def capture_firewall_runtime_snapshot(
    runner: IptablesRunner,
    *,
    snapshot_path: str | Path,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Read the runtime INPUT chain and atomically persist a minimal snapshot.

    Runtime list/parse failures are themselves persisted as an unavailable
    snapshot whenever the filesystem is writable. This prevents a previously
    successful snapshot from looking current after an observation failure.
    """
    observed = _normalize_utc(observed_at or datetime.now(timezone.utc))
    try:
        result = runner.run_operation(LIST_RULES)
        if result.returncode != 0:
            detail = " ".join((result.stderr or "").split())
            raise FirewallRuntimeSnapshotError(
                f"iptables list failed (rc={result.returncode}): {detail or 'no stderr'}"
            )
        managed_rules = _parse_managed_rules(result.stdout)
        payload: dict[str, Any] = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": _format_utc(observed),
            "available": True,
            "managed_rules": managed_rules,
            "error": None,
        }
    except (FirewallRuntimeSnapshotError, OSError, ValueError) as exc:
        payload = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": _format_utc(observed),
            "available": False,
            "managed_rules": [],
            "error": str(exc),
        }

    _write_json_atomically(Path(snapshot_path), payload)
    return payload


def verify_firewall_runtime_snapshot(
    device: Mapping[str, Any],
    *,
    snapshot_path: str | Path,
    max_age_seconds: float,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify that no managed runtime DROP rule remains for ``device``.

    The returned shape matches ``RecoveryCommandService.RuntimeFirewallVerifier``.
    A PASS is possible only from a fresh, schema-valid, successful Worker
    observation. Everything else is fail-closed ``UNAVAILABLE``.
    """
    if max_age_seconds <= 0:
        return _unavailable("Runtime firewall snapshot max age must be positive.")

    target_ip = _normalize_device_ip(device.get("ip_address"))
    if target_ip is None:
        return _unavailable("Device has no valid IPv4 address for runtime firewall verification.")

    path = Path(snapshot_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _unavailable(f"Runtime firewall snapshot not found: {path}")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _unavailable(f"Runtime firewall snapshot cannot be read: {exc}")

    try:
        normalized = _validate_snapshot_payload(payload)
        observed_at = normalized["observed_at"]
        current = _normalize_utc(now or datetime.now(timezone.utc))
        age_seconds = (current - observed_at).total_seconds()
        if age_seconds < -DEFAULT_MAX_FUTURE_SKEW_SECONDS:
            raise FirewallRuntimeSnapshotError(
                f"Runtime firewall snapshot timestamp is in the future by {-age_seconds:.1f}s."
            )
        if age_seconds > max_age_seconds:
            raise FirewallRuntimeSnapshotError(
                f"Runtime firewall snapshot is stale: age={age_seconds:.1f}s, "
                f"max_age={max_age_seconds:.1f}s."
            )
        if not normalized["available"]:
            raise FirewallRuntimeSnapshotError(
                str(normalized["error"] or "Firewall Worker runtime observation unavailable.")
            )
    except FirewallRuntimeSnapshotError as exc:
        return _unavailable(str(exc))

    matches = [
        rule for rule in normalized["managed_rules"] if rule["source_ip"] == target_ip
    ]
    if matches:
        rule_ids = [int(rule["rule_id"]) for rule in matches]
        return {
            "available": True,
            "passed": False,
            "status": "ACTIVE",
            "rule_count": len(matches),
            "details": (
                f"Runtime firewall still has {len(matches)} managed DROP rule(s) "
                f"for {target_ip}: rule_ids={rule_ids}."
            ),
        }

    return {
        "available": True,
        "passed": True,
        "status": "VERIFIED_RELEASED",
        "rule_count": 0,
        "details": f"Fresh runtime snapshot has no managed DROP rule for {target_ip}.",
    }


def _parse_managed_rules(stdout: str) -> list[dict[str, Any]]:
    managed: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if COMMENT_PREFIX not in line:
            continue
        managed.append(_parse_managed_rule_line(line))
    managed.sort(key=lambda item: (int(item["rule_id"]), str(item["source_ip"])))
    return managed


def _parse_managed_rule_line(line: str) -> dict[str, Any]:
    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        raise FirewallRuntimeSnapshotError(
            f"Malformed managed firewall rule cannot be parsed: {line!r}"
        ) from exc

    if len(tokens) < 2 or tokens[0] != "-A" or tokens[1] != CHAIN:
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule is outside expected {CHAIN} chain: {line!r}"
        )
    if "!" in tokens:
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule contains unsupported inversion: {line!r}"
        )

    protocol = _option_value(tokens, "-p")
    source = _option_value(tokens, "-s")
    dest_port = _option_value(tokens, "--dport")
    comment = _option_value(tokens, "--comment")
    action = _option_value(tokens, "-j")

    if protocol != PROTOCOL:
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule has unexpected protocol: {line!r}"
        )
    if dest_port != str(DEST_PORT):
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule has unexpected destination port: {line!r}"
        )
    if action != ACTION:
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule has unexpected target: {line!r}"
        )
    if comment is None or not comment.startswith(COMMENT_PREFIX):
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule has invalid comment: {line!r}"
        )

    rule_id_text = comment.removeprefix(COMMENT_PREFIX)
    if not rule_id_text.isdigit():
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule has invalid rule id: {line!r}"
        )

    source_ip = _single_host_ipv4(source, line=line)
    return {"rule_id": int(rule_id_text), "source_ip": source_ip}


def _option_value(tokens: list[str], option: str) -> str | None:
    try:
        index = tokens.index(option)
    except ValueError:
        return None
    if index + 1 >= len(tokens):
        return None
    return tokens[index + 1]


def _single_host_ipv4(value: str | None, *, line: str) -> str:
    if not value:
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule has no source IP: {line!r}"
        )
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule has invalid source IP: {line!r}"
        ) from exc
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32:
        raise FirewallRuntimeSnapshotError(
            f"Managed firewall rule source must be a single IPv4 host: {line!r}"
        )
    return str(network.network_address)


def _validate_snapshot_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise FirewallRuntimeSnapshotError("Runtime firewall snapshot root must be an object.")
    if payload.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise FirewallRuntimeSnapshotError(
            f"Unsupported runtime firewall snapshot schema: {payload.get('schema_version')!r}."
        )

    observed_raw = payload.get("observed_at")
    if not isinstance(observed_raw, str) or not observed_raw:
        raise FirewallRuntimeSnapshotError("Runtime firewall snapshot has no observed_at.")
    observed_at = _parse_utc(observed_raw)

    available = payload.get("available")
    if not isinstance(available, bool):
        raise FirewallRuntimeSnapshotError("Runtime firewall snapshot available must be boolean.")

    raw_rules = payload.get("managed_rules")
    if not isinstance(raw_rules, list):
        raise FirewallRuntimeSnapshotError("Runtime firewall snapshot managed_rules must be a list.")

    normalized_rules: list[dict[str, Any]] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            raise FirewallRuntimeSnapshotError("Runtime firewall snapshot contains invalid rule data.")
        rule_id = item.get("rule_id")
        source_ip = _normalize_device_ip(item.get("source_ip"))
        if isinstance(rule_id, bool) or not isinstance(rule_id, int) or rule_id < 0:
            raise FirewallRuntimeSnapshotError("Runtime firewall snapshot contains invalid rule_id.")
        if source_ip is None:
            raise FirewallRuntimeSnapshotError("Runtime firewall snapshot contains invalid source_ip.")
        normalized_rules.append({"rule_id": rule_id, "source_ip": source_ip})

    error = payload.get("error")
    if error is not None and not isinstance(error, str):
        raise FirewallRuntimeSnapshotError("Runtime firewall snapshot error must be a string or null.")

    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "observed_at": observed_at,
        "available": available,
        "managed_rules": normalized_rules,
        "error": error,
    }


def _normalize_device_ip(value: Any) -> str | None:
    if value is None:
        return None
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    return str(address)


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FirewallRuntimeSnapshotError(
            f"Runtime firewall snapshot observed_at is invalid: {value!r}."
        ) from exc
    if parsed.tzinfo is None:
        raise FirewallRuntimeSnapshotError(
            "Runtime firewall snapshot observed_at must include UTC timezone."
        )
    return parsed.astimezone(timezone.utc)


def _normalize_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _format_utc(value: datetime) -> str:
    return _normalize_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unavailable(details: str) -> dict[str, Any]:
    return {
        "available": False,
        "passed": False,
        "status": "UNAVAILABLE",
        "rule_count": None,
        "details": details,
    }


def _write_json_atomically(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp-{os.getpid()}-{uuid4().hex}")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
