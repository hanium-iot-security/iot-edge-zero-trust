from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from edge.detection.detector_contract import DetectorRunResult
from edge.detection import run_packet_ai_detector
from edge.packet.capture_session_repository import PacketFeatureReadiness


RANGE_START = datetime(2026, 7, 26, 10, 0, 0, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 7, 26, 10, 0, 10, tzinfo=timezone.utc)
SESSION_ID = "11111111-1111-4111-8111-111111111111"


def test_manual_packet_if_runner_uses_one_stage_transaction(
    monkeypatch,
    capsys,
) -> None:
    session = FakeSession()
    stage = FakeStage()
    monkeypatch.setattr(
        run_packet_ai_detector,
        "SessionLocal",
        lambda: session,
    )
    monkeypatch.setattr(
        run_packet_ai_detector.PacketIsolationForestStage,
        "from_settings",
        staticmethod(lambda **_: stage),
    )
    _stub_ready_range(monkeypatch)

    exit_code = run_packet_ai_detector.main(
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
    assert session.transaction_rolled_back is True
    assert session.transaction_committed is False
    assert stage.call_count == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["committed"] is False
    assert payload["session_id"] == SESSION_ID
    assert payload["detector_name"] == "packet_if"
    assert payload["selected_count"] == 2
    assert payload["created_event_count"] == 1


def test_manual_packet_if_runner_binds_stage_to_requested_capture_session(
    monkeypatch,
    capsys,
) -> None:
    session = FakeSession()
    stage = FakeStage()
    monkeypatch.setattr(run_packet_ai_detector, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        run_packet_ai_detector.PacketIsolationForestStage,
        "from_settings",
        staticmethod(lambda **_: stage),
    )
    _stub_ready_range(monkeypatch)

    assert run_packet_ai_detector.main([
        "--session-id", SESSION_ID,
        "--range-start", "2026-07-26T10:00:00Z",
        "--cutoff", "2026-07-26T10:00:10Z",
    ]) == 0

    assert stage.capture_session_ids == [SESSION_ID]


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-26T10:00:00",
        "2026-07-26T10:00:00+00:00",
        "2026-07-26T10:00:00.100Z",
    ],
)
def test_manual_packet_if_runner_rejects_noncanonical_timestamps(value) -> None:
    with pytest.raises(SystemExit):
        run_packet_ai_detector.parse_args(
            [
                "--session-id",
                SESSION_ID,
                "--range-start",
                value,
                "--cutoff",
                "2026-07-26T10:00:10Z",
            ]
        )


def test_manual_packet_if_runner_commits_only_when_explicitly_requested(
    monkeypatch,
    capsys,
    tmp_path,
) -> None:
    session = FakeSession()
    monkeypatch.setattr(run_packet_ai_detector, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        run_packet_ai_detector.PacketIsolationForestStage,
        "from_settings",
        staticmethod(lambda **_: FakeStage()),
    )
    _stub_ready_range(monkeypatch)

    exit_code = run_packet_ai_detector.main(
        [
            "--session-id",
            SESSION_ID,
            "--range-start",
            "2026-07-26T10:00:00Z",
            "--cutoff",
            "2026-07-26T10:00:10Z",
            "--commit",
            "--lock-path",
            str(tmp_path / "packet-if.lock"),
        ]
    )

    assert exit_code == 0
    assert session.transaction_committed is True
    assert session.transaction_rolled_back is False
    assert json.loads(capsys.readouterr().out)["committed"] is True


def test_manual_packet_if_runner_rejects_cutoff_after_feature_ready_range(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        run_packet_ai_detector,
        "get_packet_feature_ready_through",
        lambda *_args, **_kwargs: PacketFeatureReadiness(
            session_id=SESSION_ID,
            first_window_start=RANGE_START,
            packet_feature_ready_through=CUTOFF,
        ),
    )
    monkeypatch.setattr(
        run_packet_ai_detector.checkpoints,
        "get_detector_checkpoint",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(RuntimeError, match="exceeds.*ready range"):
        run_packet_ai_detector._validate_manual_range(
            object(),
            session_id=SESSION_ID,
            range_start=RANGE_START,
            cutoff=datetime(
                2026,
                7,
                26,
                10,
                0,
                20,
                tzinfo=timezone.utc,
            ),
        )


def test_manual_packet_if_runner_requires_checkpoint_continuity(
    monkeypatch,
) -> None:
    _stub_ready_range(
        monkeypatch,
        checkpoint_window_end="2026-07-26T10:00:10Z",
    )

    with pytest.raises(RuntimeError, match="must continue"):
        run_packet_ai_detector._validate_manual_range(
            object(),
            session_id=SESSION_ID,
            range_start=RANGE_START,
            cutoff=CUTOFF,
        )


def test_manual_packet_if_runner_rejects_capture_session_gap(
    monkeypatch,
) -> None:
    session_first_window = datetime(
        2026,
        7,
        26,
        10,
        0,
        20,
        tzinfo=timezone.utc,
    )
    session_ready_through = datetime(
        2026,
        7,
        26,
        10,
        0,
        30,
        tzinfo=timezone.utc,
    )
    monkeypatch.setattr(
        run_packet_ai_detector,
        "get_packet_feature_ready_through",
        lambda *_args, **_kwargs: PacketFeatureReadiness(
            session_id=SESSION_ID,
            first_window_start=session_first_window,
            packet_feature_ready_through=session_ready_through,
        ),
    )
    monkeypatch.setattr(
        run_packet_ai_detector.checkpoints,
        "get_detector_checkpoint",
        lambda *_args, **_kwargs: {
            "last_processed_id": None,
            "last_completed_window_end": "2026-07-26T10:00:10Z",
        },
    )

    with pytest.raises(RuntimeError, match="cannot bridge a Capture Session gap"):
        run_packet_ai_detector._validate_manual_range(
            object(),
            session_id=SESSION_ID,
            range_start=CUTOFF,
            cutoff=session_ready_through,
        )


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
        self.capture_session_ids: list[str] = []

    def run_until(self, db, *, cycle_range_start, cycle_cutoff):
        self.call_count += 1
        return DetectorRunResult(
            detector_name="packet_if",
            source_table="packet_feature_logs",
            range_start=cycle_range_start,
            cutoff=cycle_cutoff,
            selected_count=2,
            created_event_count=1,
            last_processed_id_before=10,
            last_processed_id_after=12,
            completed_window_end_before=datetime(
                2026,
                7,
                26,
                10,
                0,
                0,
                tzinfo=timezone.utc,
            ),
            completed_window_end_after=cycle_cutoff,
        )

    def run_until_for_capture_session(
        self,
        db,
        *,
        cycle_range_start,
        cycle_cutoff,
        expected_capture_session_id,
    ):
        self.capture_session_ids.append(expected_capture_session_id)
        return self.run_until(
            db,
            cycle_range_start=cycle_range_start,
            cycle_cutoff=cycle_cutoff,
        )


def _stub_ready_range(
    monkeypatch,
    *,
    checkpoint_window_end: str | None = None,
) -> None:
    monkeypatch.setattr(
        run_packet_ai_detector,
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
        run_packet_ai_detector.checkpoints,
        "get_detector_checkpoint",
        lambda *_args, **_kwargs: checkpoint,
    )
