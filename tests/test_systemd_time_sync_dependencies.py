from configparser import ConfigParser
from pathlib import Path


SYSTEMD_DIR = Path("infra/systemd")
TIME_WAIT_UNIT = "systemd-time-wait-sync.service"


def read_unit(name: str) -> ConfigParser:
    parser = ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    read_files = parser.read(SYSTEMD_DIR / name, encoding="utf-8")
    assert read_files == [str(SYSTEMD_DIR / name)]
    assert parser.has_section("Unit")
    return parser


def tokens(parser: ConfigParser, key: str) -> set[str]:
    assert parser.has_option("Unit", key)
    return set(parser["Unit"][key].split())


def test_time_window_services_wait_for_initial_time_sync() -> None:
    for name in (
        "packet-capture.service",
        "gateway-metrics.service",
        "mqtt-feature-builder.service",
    ):
        unit = read_unit(name)
        assert TIME_WAIT_UNIT in tokens(unit, "After"), name
        assert TIME_WAIT_UNIT in tokens(unit, "Wants"), name


def test_detection_orchestrator_keeps_builder_and_waits_for_time_sync() -> None:
    unit = read_unit("detection-orchestrator.service")
    required = {
        "network-online.target",
        TIME_WAIT_UNIT,
        "mqtt-feature-builder.service",
    }

    assert required.issubset(tokens(unit, "After"))
    assert required.issubset(tokens(unit, "Wants"))


def test_non_window_services_are_not_broadened_by_this_fix() -> None:
    for name in ("iot-edge-api.service", "firewall-worker.service"):
        unit = read_unit(name)
        assert TIME_WAIT_UNIT not in tokens(unit, "After"), name
        assert TIME_WAIT_UNIT not in tokens(unit, "Wants"), name
