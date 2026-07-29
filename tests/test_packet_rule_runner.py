from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from edge.detection.detector_contract import DetectorRunResult
from edge.detection import run_packet_rule_detector
from edge.packet.capture_session_repository import PacketFeatureReadiness


RANGE_START = datetime(2026, 7, 26, 10, 0, 0, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 7, 26, 10, 0, 10, tzinfo=timezone.utc)
SESSION_ID = "11111111-1111-4111-8111-111111111111"


def test_manual_packet_rule_runner_uses_one_stage_transaction(
    monkeypatch,
    capsys,
) -> None:
    session = FakeSession()
    stage = FakeStage()
    monkeypatch.setattr(run_packet_rule_detector, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        run_packet_rule_detector,
        "PacketRuleDetectorStage",
        lambda: stage,
    )
    _stub_ready_range(monkeypatch)

    exit_code = run_packet_rule_detector.main(
        [
            "--session-id",
            SESSION_ID,
            "--range-start",
            "2026-07-26T10:00:00Z",
            "--cutoff",
            "2026-07-26T10:00:10Z",
        ]
    )

    assert exit_code == 0
    assert session.entered is True
    assert session.transaction_entered is True
    # --commit을 안 줬으므로 검증만 하고 반드시 롤백해야 한다 (실수로 커밋되면 안 됨).
    assert session.transaction_rolled_back is True
    assert session.transaction_committed is False
    assert stage.call_count == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["committed"] is False
    assert payload["session_id"] == SESSION_ID
    assert payload["detector_name"] == "packet_rule"
    assert payload["selected_count"] == 2
    assert payload["created_event_count"] == 1


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-26T10:00:00",
        "2026-07-26T10:00:00+00:00",
        "2026-07-26T10:00:00.100Z",
    ],
)
def test_manual_packet_rule_runner_rejects_noncanonical_timestamps(value) -> None:
    with pytest.raises(SystemExit):
        run_packet_rule_detector.parse_args(
            [
                "--session-id",
                SESSION_ID,
                "--range-start",
                value,
                "--cutoff",
                "2026-07-26T10:00:10Z",
            ]
        )


def test_manual_packet_rule_runner_commits_only_when_explicitly_requested(
    monkeypatch,
    capsys,
    tmp_path,
) -> None:
    session = FakeSession()
    monkeypatch.setattr(run_packet_rule_detector, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        run_packet_rule_detector,
        "PacketRuleDetectorStage",
        lambda: FakeStage(),
    )
    _stub_ready_range(monkeypatch)

    exit_code = run_packet_rule_detector.main(
        [
            "--session-id",
            SESSION_ID,
            "--range-start",
            "2026-07-26T10:00:00Z",
            "--cutoff",
            "2026-07-26T10:00:10Z",
            "--commit",
            "--lock-path",
            str(tmp_path / "packet-rule.lock"),
        ]
    )

    assert exit_code == 0
    assert session.transaction_committed is True
    assert session.transaction_rolled_back is False
    assert json.loads(capsys.readouterr().out)["committed"] is True


def test_manual_packet_rule_runner_rejects_stage_failure_without_committing(
    monkeypatch,
    tmp_path,
) -> None:
    """Stage.run_until()이 예외를 내면 --commit이어도 절대 커밋되면 안 된다."""
    session = FakeSession()
    monkeypatch.setattr(run_packet_rule_detector, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        run_packet_rule_detector,
        "PacketRuleDetectorStage",
        lambda: FailingStage(),
    )
    _stub_ready_range(monkeypatch)

    with pytest.raises(RuntimeError, match="boom"):
        run_packet_rule_detector.main(
            [
                "--session-id",
                SESSION_ID,
                "--range-start",
                "2026-07-26T10:00:00Z",
                "--cutoff",
                "2026-07-26T10:00:10Z",
                "--commit",
                "--lock-path",
                str(tmp_path / "packet-rule.lock"),
            ]
        )

    assert session.transaction_committed is False
    assert session.transaction_rolled_back is True


def test_manual_packet_rule_runner_rejects_cutoff_after_feature_ready_range(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        run_packet_rule_detector,
        "get_packet_feature_ready_through",
        lambda *_args, **_kwargs: PacketFeatureReadiness(
            session_id=SESSION_ID,
            first_window_start=RANGE_START,
            packet_feature_ready_through=CUTOFF,
        ),
    )
    monkeypatch.setattr(
        run_packet_rule_detector.checkpoints,
        "get_detector_checkpoint",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(RuntimeError, match="exceeds.*ready range"):
        run_packet_rule_detector._validate_manual_range(
            object(),
            session_id=SESSION_ID,
            range_start=RANGE_START,
            cutoff=datetime(2026, 7, 26, 10, 0, 20, tzinfo=timezone.utc),
        )


def test_manual_packet_rule_runner_requires_checkpoint_continuity(monkeypatch) -> None:
    _stub_ready_range(monkeypatch, checkpoint_window_end="2026-07-26T10:00:10Z")

    with pytest.raises(RuntimeError, match="must continue"):
        run_packet_rule_detector._validate_manual_range(
            object(),
            session_id=SESSION_ID,
            range_start=RANGE_START,
            cutoff=CUTOFF,
        )


def test_manual_packet_rule_runner_rejects_capture_session_gap(monkeypatch) -> None:
    session_first_window = datetime(2026, 7, 26, 10, 0, 20, tzinfo=timezone.utc)
    session_ready_through = datetime(2026, 7, 26, 10, 0, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(
        run_packet_rule_detector,
        "get_packet_feature_ready_through",
        lambda *_args, **_kwargs: PacketFeatureReadiness(
            session_id=SESSION_ID,
            first_window_start=session_first_window,
            packet_feature_ready_through=session_ready_through,
        ),
    )
    monkeypatch.setattr(
        run_packet_rule_detector.checkpoints,
        "get_detector_checkpoint",
        lambda *_args, **_kwargs: {
            "last_processed_id": None,
            "last_completed_window_end": "2026-07-26T10:00:10Z",
        },
    )

    with pytest.raises(RuntimeError, match="cannot bridge a Capture Session gap"):
        run_packet_rule_detector._validate_manual_range(
            object(),
            session_id=SESSION_ID,
            range_start=CUTOFF,
            cutoff=session_ready_through,
        )


def test_manual_packet_rule_runner_missing_session_raises(monkeypatch) -> None:
    monkeypatch.setattr(
        run_packet_rule_detector,
        "get_packet_feature_ready_through",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(ValueError, match="Capture Session not found"):
        run_packet_rule_detector._validate_manual_range(
            object(),
            session_id=SESSION_ID,
            range_start=RANGE_START,
            cutoff=CUTOFF,
        )


def test_runner_lock_blocks_concurrent_commit(monkeypatch, tmp_path) -> None:
    """--commit 실행 중에는 동시에 다른 --commit 실행이 Lock에 막혀야 한다."""
    lock_path = tmp_path / "packet-rule.lock"

    with run_packet_rule_detector._runner_lock(lock_path):
        with pytest.raises(RuntimeError, match="another detection process holds the lock"):
            with run_packet_rule_detector._runner_lock(lock_path):
                pass  # pragma: no cover - 도달하면 안 됨


def test_runner_lock_is_not_required_without_commit(monkeypatch, capsys, tmp_path) -> None:
    """--commit 없이는(검증 전용 실행) Lock을 아예 안 잡아야 동시에 여러 번 돌릴 수 있다."""
    session = FakeSession()
    monkeypatch.setattr(run_packet_rule_detector, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        run_packet_rule_detector,
        "PacketRuleDetectorStage",
        lambda: FakeStage(),
    )
    _stub_ready_range(monkeypatch)
    lock_path = tmp_path / "packet-rule.lock"

    with run_packet_rule_detector._runner_lock(lock_path):
        # Lock을 이미 잡고 있는 상태에서도 --commit 없는 실행은 막히지 않아야 한다.
        exit_code = run_packet_rule_detector.main(
            [
                "--session-id",
                SESSION_ID,
                "--range-start",
                "2026-07-26T10:00:00Z",
                "--cutoff",
                "2026-07-26T10:00:10Z",
                "--lock-path",
                str(lock_path),
            ]
        )
    assert exit_code == 0
    assert session.transaction_committed is False


class FakeSession:
    def __init__(self) -> None:
        self.entered = False
        self.transaction_entered = False
        self.transaction_committed = False
        self.transaction_rolled_back = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def begin(self):
        self.transaction_entered = True
        return FakeTransaction(self)


class FakeTransaction:
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.is_active = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def commit(self) -> None:
        self.session.transaction_committed = True
        self.is_active = False

    def rollback(self) -> None:
        self.session.transaction_rolled_back = True
        self.is_active = False


class FakeStage:
    def __init__(self) -> None:
        self.call_count = 0

    def run_until(self, db, *, cycle_range_start, cycle_cutoff):
        self.call_count += 1
        return DetectorRunResult(
            detector_name="packet_rule",
            source_table="packet_feature_logs",
            range_start=cycle_range_start,
            cutoff=cycle_cutoff,
            selected_count=2,
            created_event_count=1,
            last_processed_id_before=10,
            last_processed_id_after=12,
            completed_window_end_before=datetime(2026, 7, 26, 10, 0, 0, tzinfo=timezone.utc),
            completed_window_end_after=cycle_cutoff,
        )


class FailingStage:
    def run_until(self, db, *, cycle_range_start, cycle_cutoff):
        raise RuntimeError("boom")


def _stub_ready_range(
    monkeypatch,
    *,
    checkpoint_window_end: str | None = None,
) -> None:
    monkeypatch.setattr(
        run_packet_rule_detector,
        "get_packet_feature_ready_through",
        lambda *_args, **_kwargs: PacketFeatureReadiness(
            session_id=SESSION_ID,
            first_window_start=RANGE_START,
            packet_feature_ready_through=CUTOFF,
        ),
    )
    checkpoint = (
        {
            "last_processed_id": None,
            "last_completed_window_end": checkpoint_window_end,
        }
        if checkpoint_window_end is not None
        else None
    )
    monkeypatch.setattr(
        run_packet_rule_detector.checkpoints,
        "get_detector_checkpoint",
        lambda *_args, **_kwargs: checkpoint,
    )