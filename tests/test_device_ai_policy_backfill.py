"""P9-03: 기존 기기의 AI 모드 이관(승인 목록)과 CLI 검증."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from db import backfill_device_ai_policies as cli
from edge.policy import device_ai_policy_repository as repo
from edge.policy.device_ai_policy_backfill import (
    LegacyAiOverride,
    apply_ai_backfill,
    parse_ai_override,
    plan_ai_backfill,
)
from edge.policy.device_policy import BackfillBlockedError, DevicePolicyValidationError
from tests.device_policy_support import at, clock_at, count, insert_legacy_device, open_db

EFFECTIVE = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)  # 과거 시점도 허용


def override(device_id, mode="OBSERVE", source="approval:1"):
    return LegacyAiOverride(device_id=device_id, mode=mode, source=source)


@pytest.fixture
def db(tmp_path):
    connection = open_db(tmp_path)
    insert_legacy_device(connection, "esp32_01", "192.168.0.4")
    insert_legacy_device(connection, "esp32_02", "192.168.0.5")
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


def apply(db, overrides, **kwargs):
    return apply_ai_backfill(
        db, overrides, effective_from=EFFECTIVE, reason="approved", clock=clock_at(at(0)), **kwargs
    )


class TestApply:
    def test_creates_approved_revision_one_for_every_legacy_device(self, db) -> None:
        result = apply(db, {"esp32_01": override("esp32_01"), "esp32_02": override("esp32_02", "OFF")})

        assert result.created == ("esp32_01", "esp32_02")
        first = repo.get_latest_ai_revision(db, "esp32_01")
        assert (first.revision, first.mode, first.effective_from) == (1, "OBSERVE", "2026-10-01T00:00:00Z")
        assert first.created_by == "backfill:approval:1"
        assert repo.get_latest_ai_revision(db, "esp32_02").mode == "OFF"

    def test_missing_approval_blocks_everything_and_reports_all_problems(self, db) -> None:
        with pytest.raises(BackfillBlockedError) as error:
            apply(db, {"esp32_01": override("esp32_01"), "ghost": override("ghost")})

        problems = " ".join(error.value.problems)
        assert "MISSING_OVERRIDE:esp32_02" in problems and "UNKNOWN_OVERRIDE:ghost" in problems
        assert count(db, "device_ai_policy_revisions") == 0

    def test_rerun_skips_existing_revisions_and_never_overwrites(self, db) -> None:
        apply(db, {"esp32_01": override("esp32_01"), "esp32_02": override("esp32_02")})
        again = apply(db, {"esp32_01": override("esp32_01", "OFF"), "esp32_02": override("esp32_02", "OFF")})

        assert again.created == () and again.already_revised == ("esp32_01", "esp32_02")
        assert repo.get_latest_ai_revision(db, "esp32_01").mode == "OBSERVE"

    def test_dry_run_changes_nothing(self, db) -> None:
        plan = plan_ai_backfill(db, {"esp32_01": override("esp32_01")})
        assert plan.to_create == ("esp32_01",) and len(plan.problems) == 1
        assert count(db, "device_ai_policy_revisions") == 0

    def test_windows_before_the_migration_boundary_stay_unavailable(self, db) -> None:
        from edge.policy.device_ai_policy_resolver import resolve_ai_mode

        apply(db, {"esp32_01": override("esp32_01"), "esp32_02": override("esp32_02")})
        assert resolve_ai_mode(db, "esp32_01", "2026-09-30T23:59:50Z").mode is None
        assert resolve_ai_mode(db, "esp32_01", "2026-10-01T00:00:00Z").mode == "OBSERVE"

    def test_device_registered_before_the_migration_is_readable_after_backfill(self, db) -> None:
        # 007 이후 API로 등록됐지만 012 이전이라 AI revision이 없는 기기(등록 효력이 NULL이 아님).
        db.execute(
            "UPDATE devices SET registration_effective_from = '2026-09-30T00:00:00Z' "
            "WHERE device_id = 'esp32_01'"
        )
        apply(db, {"esp32_01": override("esp32_01"), "esp32_02": override("esp32_02")})

        snapshot = repo.get_ai_policy_snapshot(db, "esp32_01", server_time=at(0))
        assert snapshot.current.revision == 1 and snapshot.current.mode == "OBSERVE"

    @pytest.mark.parametrize(
        "bad",
        [
            {"device_id": "esp32_01", "mode": "ENFORCE", "source": "s"},
            {"device_id": "esp32_01", "mode": "observe", "source": "s"},
            {"device_id": "esp32_01", "mode": "OFF"},
            {"device_id": "esp32_01", "mode": "OFF", "source": "s", "extra": 1},
            {"device_id": "bad id", "mode": "OFF", "source": "s"},
        ],
    )
    def test_manifest_entries_are_strict(self, bad) -> None:
        with pytest.raises(DevicePolicyValidationError):
            parse_ai_override(bad)

    def test_directly_built_overrides_are_revalidated(self, db) -> None:
        with pytest.raises(DevicePolicyValidationError):
            apply(db, {"esp32_01": LegacyAiOverride("esp32_01", "ENFORCE", "s")})
        with pytest.raises(DevicePolicyValidationError):
            apply(db, {"other": override("esp32_01")})


def write_manifest(path, **overrides):
    manifest = {
        "schema_version": "device-ai-policy-backfill-v1",
        "effective_from": "2026-10-01T00:00:00Z",
        "reason": "approved",
        "devices": [
            {"device_id": "esp32_01", "mode": "OBSERVE", "source": "approval:1"},
            {"device_id": "esp32_02", "mode": "OFF", "source": "approval:1"},
        ],
    }
    manifest.update(overrides)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class TestCli:
    def run(self, tmp_path, manifest, *extra):
        return cli.main(["--db", str(tmp_path / "policy.db"), "--manifest", str(manifest), *extra])

    def test_dry_run_then_apply(self, db, tmp_path, capsys) -> None:
        manifest = write_manifest(tmp_path / "m.json")

        assert self.run(tmp_path, manifest) == 0
        assert count(db, "device_ai_policy_revisions") == 0
        assert self.run(tmp_path, manifest, "--apply") == 0
        assert count(db, "device_ai_policy_revisions") == 2
        assert "이관 완료" in capsys.readouterr().out

    def test_incomplete_list_is_refused_with_exit_code_2(self, db, tmp_path, capsys) -> None:
        manifest = write_manifest(
            tmp_path / "m.json",
            devices=[{"device_id": "esp32_01", "mode": "OFF", "source": "approval:1"}],
        )

        assert self.run(tmp_path, manifest) == 2
        assert self.run(tmp_path, manifest, "--apply") == 2
        assert count(db, "device_ai_policy_revisions") == 0
        assert "MISSING_OVERRIDE:esp32_02" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "change",
        [
            {"schema_version": "v0"},
            {"reason": None},
            {"effective_from": "2026-10-01T00:00:05Z"},
            {"devices": []},
            {"unexpected": 1},
        ],
    )
    def test_invalid_manifest_exits_with_2(self, db, tmp_path, change) -> None:
        assert self.run(tmp_path, write_manifest(tmp_path / "m.json", **change)) == 2

    def test_unreadable_manifest_and_missing_db(self, db, tmp_path) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        assert self.run(tmp_path, broken) == 2
        assert cli.main(["--db", str(tmp_path / "none.db"), "--manifest", str(broken)]) == 2
