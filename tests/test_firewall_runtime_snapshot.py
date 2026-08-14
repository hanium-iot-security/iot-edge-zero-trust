from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from edge.trust.firewall_runtime_snapshot import (
    SNAPSHOT_SCHEMA_VERSION,
    capture_firewall_runtime_snapshot,
    verify_firewall_runtime_snapshot,
)
from edge.trust.firewall_worker import (
    CommandResult,
    FirewallRuleSpec,
    FirewallTransientError,
    LIST_RULES,
)


NOW = datetime(2026, 8, 14, 7, 30, 0, tzinfo=timezone.utc)
DEVICE_IP = "192.168.0.5"


class ListingRunner:
    def __init__(self, *, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list[tuple[str, FirewallRuleSpec | None]] = []

    def run_operation(
        self, operation: str, spec: FirewallRuleSpec | None = None
    ) -> CommandResult:
        self.calls.append((operation, spec))
        assert operation == LIST_RULES
        assert spec is None
        return CommandResult(
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


class RaisingRunner:
    def run_operation(
        self, operation: str, spec: FirewallRuleSpec | None = None
    ) -> CommandResult:
        assert operation == LIST_RULES
        assert spec is None
        raise FirewallTransientError("firewall wrapper timed out")


def _managed_rule(rule_id: int, source_ip: str) -> str:
    return (
        f'-A INPUT -s {source_ip}/32 -p tcp -m tcp --dport 1883 '
        f'-m comment --comment "hanium-firewall:{rule_id}" -j DROP'
    )


def _write_snapshot(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _device(ip_address: str | None = DEVICE_IP) -> dict:
    return {
        "device_id": "esp32_02",
        "ip_address": ip_address,
        "current_status": "isolated",
        "current_trust_score": 20,
    }


def test_capture_writes_only_managed_hanium_rules_atomically(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    runner = ListingRunner(
        stdout="\n".join(
            [
                "-P INPUT ACCEPT",
                "-A INPUT -p tcp --dport 22 -j ACCEPT",
                _managed_rule(12, DEVICE_IP),
                _managed_rule(13, "192.168.0.6"),
            ]
        )
    )

    payload = capture_firewall_runtime_snapshot(
        runner,
        snapshot_path=snapshot,
        observed_at=NOW,
    )

    assert payload["schema_version"] == SNAPSHOT_SCHEMA_VERSION
    assert payload["available"] is True
    assert payload["observed_at"] == "2026-08-14T07:30:00Z"
    assert payload["managed_rules"] == [
        {"rule_id": 12, "source_ip": DEVICE_IP},
        {"rule_id": 13, "source_ip": "192.168.0.6"},
    ]
    assert json.loads(snapshot.read_text(encoding="utf-8")) == payload
    assert not list(tmp_path.glob("*.tmp-*"))


def test_capture_marks_snapshot_unavailable_when_runtime_list_fails(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    payload = capture_firewall_runtime_snapshot(
        ListingRunner(returncode=2, stderr="permission denied"),
        snapshot_path=snapshot,
        observed_at=NOW,
    )

    assert payload["available"] is False
    assert payload["managed_rules"] == []
    assert "iptables list failed" in payload["error"]
    assert json.loads(snapshot.read_text(encoding="utf-8"))["available"] is False


def test_capture_replaces_previous_success_when_runner_raises(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    _write_snapshot(
        snapshot,
        {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": "2026-08-14T07:29:59Z",
            "available": True,
            "managed_rules": [],
            "error": None,
        },
    )

    payload = capture_firewall_runtime_snapshot(
        RaisingRunner(), snapshot_path=snapshot, observed_at=NOW
    )

    assert payload["available"] is False
    assert "timed out" in payload["error"]
    assert json.loads(snapshot.read_text(encoding="utf-8"))["available"] is False


def test_capture_marks_snapshot_unavailable_for_malformed_managed_rule(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    malformed = (
        '-A INPUT -s 192.168.0.0/24 -p tcp --dport 1883 '
        '-m comment --comment "hanium-firewall:9" -j DROP'
    )

    payload = capture_firewall_runtime_snapshot(
        ListingRunner(stdout=malformed),
        snapshot_path=snapshot,
        observed_at=NOW,
    )

    assert payload["available"] is False
    assert payload["managed_rules"] == []
    assert "single IPv4 host" in payload["error"]


def test_verify_passes_when_fresh_snapshot_has_no_rule_for_target(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    _write_snapshot(
        snapshot,
        {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": "2026-08-14T07:29:55Z",
            "available": True,
            "managed_rules": [{"rule_id": 13, "source_ip": "192.168.0.6"}],
            "error": None,
        },
    )

    result = verify_firewall_runtime_snapshot(
        _device(),
        snapshot_path=snapshot,
        max_age_seconds=15,
        now=NOW,
    )

    assert result == {
        "available": True,
        "passed": True,
        "status": "VERIFIED_RELEASED",
        "rule_count": 0,
        "details": f"Fresh runtime snapshot has no managed DROP rule for {DEVICE_IP}.",
    }


def test_verify_holds_when_target_has_one_or_more_runtime_rules(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    _write_snapshot(
        snapshot,
        {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": "2026-08-14T07:29:59Z",
            "available": True,
            "managed_rules": [
                {"rule_id": 12, "source_ip": DEVICE_IP},
                {"rule_id": 99, "source_ip": DEVICE_IP},
            ],
            "error": None,
        },
    )

    result = verify_firewall_runtime_snapshot(
        _device(),
        snapshot_path=snapshot,
        max_age_seconds=15,
        now=NOW,
    )

    assert result["available"] is True
    assert result["passed"] is False
    assert result["status"] == "ACTIVE"
    assert result["rule_count"] == 2
    assert "12" in result["details"] and "99" in result["details"]


def test_verify_fails_closed_when_snapshot_is_missing(tmp_path: Path) -> None:
    result = verify_firewall_runtime_snapshot(
        _device(),
        snapshot_path=tmp_path / "missing.json",
        max_age_seconds=15,
        now=NOW,
    )

    assert result["available"] is False
    assert result["passed"] is False
    assert result["status"] == "UNAVAILABLE"
    assert result["rule_count"] is None
    assert "not found" in result["details"]


def test_verify_fails_closed_when_snapshot_is_stale(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    _write_snapshot(
        snapshot,
        {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": "2026-08-14T07:29:40Z",
            "available": True,
            "managed_rules": [],
            "error": None,
        },
    )

    result = verify_firewall_runtime_snapshot(
        _device(),
        snapshot_path=snapshot,
        max_age_seconds=15,
        now=NOW,
    )

    assert result["available"] is False
    assert result["passed"] is False
    assert result["status"] == "UNAVAILABLE"
    assert "stale" in result["details"]


def test_verify_fails_closed_for_invalid_or_unavailable_snapshot(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    snapshot.write_text("{not-json", encoding="utf-8")

    invalid = verify_firewall_runtime_snapshot(
        _device(), snapshot_path=snapshot, max_age_seconds=15, now=NOW
    )
    assert invalid["status"] == "UNAVAILABLE"
    assert invalid["passed"] is False

    _write_snapshot(
        snapshot,
        {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": "2026-08-14T07:30:00Z",
            "available": False,
            "managed_rules": [],
            "error": "iptables list failed",
        },
    )
    unavailable = verify_firewall_runtime_snapshot(
        _device(), snapshot_path=snapshot, max_age_seconds=15, now=NOW
    )
    assert unavailable["status"] == "UNAVAILABLE"
    assert "iptables list failed" in unavailable["details"]


def test_verify_fails_closed_when_device_ip_is_missing_invalid_or_public(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    _write_snapshot(
        snapshot,
        {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": "2026-08-14T07:30:00Z",
            "available": True,
            "managed_rules": [],
            "error": None,
        },
    )

    for value in (None, "", "not-an-ip", "8.8.8.8"):
        result = verify_firewall_runtime_snapshot(
            _device(value), snapshot_path=snapshot, max_age_seconds=15, now=NOW
        )
        assert result["available"] is False
        assert result["passed"] is False
        assert result["status"] == "UNAVAILABLE"


def test_verify_rejects_future_snapshot_beyond_clock_skew(tmp_path: Path) -> None:
    snapshot = tmp_path / "firewall-runtime.json"
    future = NOW + timedelta(seconds=6)
    _write_snapshot(
        snapshot,
        {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "observed_at": future.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "available": True,
            "managed_rules": [],
            "error": None,
        },
    )

    result = verify_firewall_runtime_snapshot(
        _device(), snapshot_path=snapshot, max_age_seconds=15, now=NOW
    )
    assert result["status"] == "UNAVAILABLE"
    assert "future" in result["details"]
