"""Host checks with synthetic registers, time, and networking; no hardware I/O."""

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import ModuleType, SimpleNamespace

import pytest


FIRMWARE_DIR = Path(__file__).resolve().parents[1] / "firmware" / "pico_wh_bme280"


def test_bundled_mqtt_library_matches_documented_pin_and_includes_mit_license():
    expected = "5458b97fc074db01263e82ae898727aee2a15079ea5cff9d2f6d6abbea8ea217"
    library = FIRMWARE_DIR / "lib" / "umqtt"
    assert hashlib.sha256((library / "simple.py").read_bytes()).hexdigest() == expected
    assert expected in (FIRMWARE_DIR / "PROVENANCE.md").read_text(encoding="utf-8")
    license_text = (library / "LICENSE.txt").read_text(encoding="utf-8")
    assert "Copyright (c) 2013, 2014 micropython-lib contributors" in license_text
    assert "Permission is hereby granted, free of charge" in license_text
    assert "The above copyright notice and this permission notice shall be included" in license_text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in license_text


def _load_module(name):
    spec = importlib.util.spec_from_file_location("pico_test_" + name, FIRMWARE_DIR / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Clock:
    def __init__(self):
        self.now = 0

    def sleep_ms(self, duration):
        assert duration >= 0
        self.now += duration

    def module(self):
        module = ModuleType("time")
        module.ticks_ms = lambda: self.now
        module.ticks_diff = lambda left, right: left - right
        module.ticks_add = lambda tick, duration: tick + duration
        module.sleep_ms = self.sleep_ms
        return module


def _calibration(*, t1=27504, p1=36477, h2=362, h3=25, h4=-20, h5=-10, h6=-30):
    # Synthetic coefficients, including both signed nibble-packed humidity terms.
    first = struct.pack("<HhhH8h", t1, 26435, -1000, p1, -10685, 3024, 2855,
                        140, -7, 15500, -14600, 6000) + bytes((0, 75))
    packed_h4, packed_h5 = h4 & 0xFFF, h5 & 0xFFF
    second = struct.pack("<hB", h2, h3) + bytes((
        packed_h4 >> 4,
        ((packed_h5 & 15) << 4) | (packed_h4 & 15),
        packed_h5 >> 4,
        h6 & 0xFF,
    ))
    return first, second


def _measurement(raw_t=519888, raw_h=3200, raw_p=415148):
    return bytes((raw_p >> 12, (raw_p >> 4) & 0xFF, (raw_p & 15) << 4,
                  raw_t >> 12, (raw_t >> 4) & 0xFF, (raw_t & 15) << 4,
                  raw_h >> 8, raw_h & 0xFF))


class RegisterI2C:
    def __init__(self, *, chip_id=0x60, calibration=None, raw=None, measurement_state=None):
        first, second = calibration or _calibration()
        self.registers = {0xD0: bytes((chip_id,)), 0x88: first, 0xE1: second,
                          0xF2: b"\x00", 0xF4: b"\x00", 0xF7: raw or _measurement()}
        self.status = 0
        self.measurement_state = measurement_state
        self.writes = []
        self.reads = []

    def readfrom_mem(self, address, register, size):
        self.reads.append((address, register, size))
        value = bytes((self.status,)) if register == 0xF3 else self.registers[register]
        assert len(value) == size
        return value

    def writeto_mem(self, address, register, value):
        self.writes.append((address, register, value))
        self.registers[register] = value
        if register == 0xF4 and value == b"\x25":
            # A completed forced conversion automatically returns to sleep mode.
            self.registers[0xF4] = b"\x24"
            if self.measurement_state is not None:
                ctrl_hum, ctrl_meas, self.status = self.measurement_state
                self.registers[0xF2] = bytes((ctrl_hum,))
                self.registers[0xF4] = bytes((ctrl_meas,))


@pytest.fixture
def driver(monkeypatch):
    clock = Clock()
    monkeypatch.setitem(sys.modules, "time", clock.module())
    return _load_module("bme280"), clock


def _fixed_point_humidity(raw_t, raw_h, *, h3=25, h4=-20, h5=-10, h6=-30):
    # Independent integer oracle from Bosch BME280 datasheet section 4.2.3:
    # https://www.bosch-sensortec.com/media/boschsensortec/downloads/datasheets/bst-bme280-ds002.pdf
    temperature_delta = (raw_t >> 4) - 27504
    fine = ((((raw_t >> 3) - (27504 << 1)) * 26435) >> 11)
    fine += (((temperature_delta * temperature_delta) >> 12) * -1000) >> 14
    delta = fine - 76800
    sample = ((raw_h << 14) - (h4 << 20) - h5 * delta + 16384) >> 15
    gain = (((delta * h6) >> 10) * (((delta * h3) >> 11) + 32768)) >> 10
    gain = ((gain + 2097152) * 362 + 8192) >> 14
    humidity = sample * gain
    humidity -= ((((humidity >> 15) ** 2) >> 7) * 75) >> 4
    return (min(419430400, max(0, humidity)) >> 12) / 1024


@pytest.mark.parametrize("raw_t,raw_h", [(519888, 3200), (519888, 6000), (490000, 4200)])
def test_compensation_matches_independent_integer_humidity_oracle(driver, raw_t, raw_h):
    module, _ = driver
    sensor = module.BME280(RegisterI2C(raw=_measurement(raw_t=raw_t, raw_h=raw_h)))

    values, raw = sensor.measure()

    assert raw == (raw_t, raw_h, 415148)
    assert (sensor.h3, sensor.h4, sensor.h5, sensor.h6) == (25, -20, -10, -30)
    assert values[1] == pytest.approx(_fixed_point_humidity(raw_t, raw_h), abs=0.02)


def test_measurement_reports_celsius_percent_and_hectopascals(driver):
    module, _ = driver
    bus = RegisterI2C()
    values, raw = module.BME280(bus).measure()

    assert values[0] == pytest.approx(25.08248, abs=0.0001)
    assert values[2] == pytest.approx(1006.53267, abs=0.001)
    assert raw == (519888, 3200, 415148)
    assert bus.writes == [(0x76, 0xE0, b"\xb6"), (0x76, 0xF2, b"\x01"),
                          (0x76, 0xF5, b"\x00"), (0x76, 0xF4, b"\x25")]
    assert (0x76, 0xF7, 8) in bus.reads


@pytest.mark.parametrize("value,bits,expected", [(0x7FF, 12, 2047), (0x800, 12, -2048),
                                                 (0xFFF, 12, -1), (0x80, 8, -128)])
def test_signed_calibration_conversion(driver, value, bits, expected):
    module, _ = driver
    assert module.signed(value, bits) == expected


def test_wrong_sensor_id_is_rejected_before_reset(driver):
    module, _ = driver
    bus = RegisterI2C(chip_id=0x58)
    with pytest.raises(RuntimeError, match="chip ID"):
        module.BME280(bus)
    assert bus.writes == []


@pytest.mark.parametrize("coefficient", ["t1", "p1", "h2"])
def test_missing_factory_calibration_is_rejected(driver, coefficient):
    module, _ = driver
    with pytest.raises(RuntimeError, match="factory calibration"):
        module.BME280(RegisterI2C(calibration=_calibration(**{coefficient: 0})))


@pytest.mark.parametrize("phase,status", [("initialization", 0x01), ("measurement", 0x08)])
def test_busy_sensor_has_bounded_status_timeout(driver, phase, status):
    module, clock = driver
    bus = RegisterI2C()
    sensor = module.BME280(bus) if phase == "measurement" else None
    bus.status = status
    started = clock.now
    with pytest.raises(RuntimeError, match="status timeout"):
        sensor.measure() if sensor else module.BME280(bus)
    assert 100 <= clock.now - started <= 120
    assert not any(register == 0xF7 for _, register, _ in bus.reads)


@pytest.mark.parametrize("field,midpoint,index", [("raw_t", 0x80000, 0),
    ("raw_h", 0x8000, 1), ("raw_p", 0x80000, 2)])
def test_completed_active_measurement_accepts_midpoint_adc_values(driver, field, midpoint, index):
    module, _ = driver
    sensor = module.BME280(RegisterI2C(raw=_measurement(**{field: midpoint})))

    values, raw = sensor.measure()

    assert raw[index] == midpoint
    assert -40 <= values[0] <= 85
    assert 0 <= values[1] <= 100
    assert 300 <= values[2] <= 1100


@pytest.mark.parametrize("state", [
    pytest.param((0x00, 0x24, 0), id="humidity-skipped"),
    pytest.param((0x01, 0x04, 0), id="temperature-skipped"),
    pytest.param((0x01, 0x20, 0), id="pressure-skipped"),
    pytest.param((0x02, 0x24, 0), id="humidity-x2"),
    pytest.param((0x01, 0x44, 0), id="temperature-x2"),
    pytest.param((0x01, 0x28, 0), id="pressure-x2"),
    pytest.param((0x01, 0x25, 0), id="forced-mode-unfinished"),
    pytest.param((0x01, 0x27, 0), id="normal-mode-active"),
    pytest.param((0x01, 0x24, 0x01), id="calibration-update-unfinished"),
    pytest.param((0x01, 0x24, 0x08), id="measurement-busy"),
])
def test_invalid_or_incomplete_conversion_never_reaches_compensation(driver, monkeypatch, state):
    module, _ = driver
    sensor = module.BME280(RegisterI2C(measurement_state=state))
    compensation_calls = []
    monkeypatch.setattr(sensor, "compensate", lambda *raw: compensation_calls.append(raw))

    with pytest.raises(RuntimeError):
        sensor.measure()

    assert compensation_calls == []


@pytest.mark.parametrize("raw_t,raw_p", [(0, 415148), (519888, 0)])
def test_readings_outside_sensor_operating_range_are_rejected(driver, raw_t, raw_p):
    module, _ = driver
    sensor = module.BME280(RegisterI2C(raw=_measurement(raw_t=raw_t, raw_p=raw_p)))
    with pytest.raises(RuntimeError, match="operating range"):
        sensor.measure()


class Socket:
    def __init__(self):
        self.closed = False
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


class Client:
    def __init__(self, clock, *, fail_publish=None):
        self.clock = clock
        self.sock = Socket()
        self.socket = self.sock
        self.fail_publish = fail_publish
        self.attempts = 0
        self.sent = []
        self.pings = []

    def publish(self, topic, payload, *, qos, retain):
        self.attempts += 1
        if self.attempts == self.fail_publish:
            raise OSError("synthetic disconnected socket")
        self.sent.append((self.clock.now, topic, json.loads(payload), qos, retain))

    def ping(self):
        self.pings.append(self.clock.now)


@pytest.fixture
def sender(monkeypatch):
    clock = Clock()
    config = ModuleType("config")
    config.__dict__.update(WIFI_SSID="synthetic-test-network", WIFI_PASSWORD="synthetic-wifi-value",
                           MQTT_HOST="198.51.100.10", MQTT_PORT=1883,
                           MQTT_USERNAME="synthetic-test-user", MQTT_PASSWORD="synthetic-mqtt-value",
                           DEVICE_ID="pico_01", MQTT_TOPIC="iot/pico_01/sensor")
    wlan = SimpleNamespace(active=lambda value: None, isconnected=lambda: True)
    machine = ModuleType("machine")
    machine.I2C = lambda *args, **kwargs: object()
    machine.Pin = lambda number: number
    network = ModuleType("network")
    network.STA_IF = 0
    network.WLAN = lambda interface: wlan
    bme280 = ModuleType("bme280")
    bme280.BME280 = lambda *args, **kwargs: None
    simple = ModuleType("umqtt.simple")
    simple.MQTTClient = lambda *args, **kwargs: None
    umqtt = ModuleType("umqtt")
    umqtt.simple = simple
    for name, module in (("time", clock.module()), ("config", config), ("machine", machine),
                         ("network", network), ("bme280", bme280), ("umqtt", umqtt),
                         ("umqtt.simple", simple)):
        monkeypatch.setitem(sys.modules, name, module)
    module = _load_module("telemetry_sender")
    events = []
    monkeypatch.setattr(module, "log", lambda event, **fields: events.append(dict(event=event, **fields)))
    return SimpleNamespace(module=module, config=config, clock=clock, events=events)


@pytest.mark.parametrize("field,value", [("WIFI_SSID", ""), ("MQTT_PASSWORD", "REPLACE_VALUE"),
    ("MQTT_HOST", "broker.example.test"), ("MQTT_HOST", "192.0.2.1"),
    ("MQTT_HOST", "256.1.2.3"), ("MQTT_PORT", True), ("MQTT_PORT", 65536),
    ("DEVICE_ID", "pico_02"), ("MQTT_TOPIC", "iot/pico_02/sensor")])
def test_invalid_configuration_stops_before_hardware_initialization(sender, monkeypatch, field, value):
    setattr(sender.config, field, value)
    hardware_calls = []
    monkeypatch.setattr(sender.module, "I2C", lambda *args, **kwargs: hardware_calls.append(args))
    with pytest.raises(ValueError):
        sender.module.main()
    assert hardware_calls == []


def test_payload_contains_actual_values_and_rejects_non_finite_readings(sender):
    sender.module.validate_config()
    payload = sender.module.build_payload(7, 35000, (25.126, 47.234, 1006.532))
    assert json.loads(payload) == {"device_id": "pico_01", "seq": 7, "uptime_ms": 35000,
                                  "temperature_c": 25.13, "humidity_pct": 47.23,
                                  "pressure_hpa": 1006.53}
    for invalid in (float("nan"), float("inf"), -float("inf")):
        with pytest.raises(ValueError, match="Non-finite"):
            sender.module.build_payload(7, 35000, (invalid, 47.2, 1006.5))


@pytest.mark.parametrize("error", [OSError("synthetic failure"), KeyboardInterrupt()])
def test_failed_mqtt_connect_closes_socket_even_on_interrupt(sender, monkeypatch, error):
    client = Client(sender.clock)

    def connect(**kwargs):
        assert kwargs == {"clean_session": True, "timeout": 5}
        raise error

    client.connect = connect
    monkeypatch.setattr(sender.module, "MQTTClient", lambda *args, **kwargs: client)
    with pytest.raises(type(error)):
        sender.module.connect_mqtt()
    assert client.socket.closed
    assert client.sock is None


def test_mqtt_connection_uses_configured_identity_and_bounded_socket_timeout(sender, monkeypatch):
    client = Client(sender.clock)
    calls = []

    def factory(*args, **kwargs):
        calls.append((args, kwargs))
        return client

    client.connect = lambda **kwargs: calls.append(kwargs)
    monkeypatch.setattr(sender.module, "MQTTClient", factory)
    assert sender.module.connect_mqtt() is client
    assert calls == [((b"pico_01", "198.51.100.10"), {
        "port": 1883, "user": b"synthetic-test-user", "password": b"synthetic-mqtt-value",
        "keepalive": 30}), {"clean_session": True, "timeout": 5}]
    assert client.socket.timeouts == [5]


def test_unavailable_sensor_sends_no_fabricated_measurements_and_closes_on_stop(sender, monkeypatch):
    client = Client(sender.clock)
    attempts = []

    def unavailable(*args, **kwargs):
        attempts.append(sender.clock.now)
        if len(attempts) == 5:
            raise KeyboardInterrupt
        raise OSError("synthetic absent sensor")

    monkeypatch.setattr(sender.module, "connect_mqtt", lambda: client)
    monkeypatch.setattr(sender.module, "BME280", unavailable)
    with pytest.raises(KeyboardInterrupt):
        sender.module.main()

    assert attempts == [0, 5000, 10000, 15000, 20000]
    assert client.sent == []
    assert client.pings == [15000]
    assert client.socket.closed
    assert [row["seq"] for row in sender.events if row["event"] == "sensor_error"] == [1, 2, 3, 4]
    assert sender.events[-1] == {"event": "sender_stopped", "publish_sent": 0}


def test_slow_measurement_does_not_queue_catch_up_publishes(sender, monkeypatch):
    client = Client(sender.clock)
    reads = []

    def measure():
        reads.append(sender.clock.now)
        if len(reads) == 4:
            raise KeyboardInterrupt
        if len(reads) == 1:
            sender.clock.sleep_ms(12000)
        return (25.1, 48.0, 1006.5), (519888, 3200, 415148)

    monkeypatch.setattr(sender.module, "connect_mqtt", lambda: client)
    monkeypatch.setattr(sender.module, "BME280", lambda *args, **kwargs: SimpleNamespace(measure=measure))
    with pytest.raises(KeyboardInterrupt):
        sender.module.main()

    assert [row[0] for row in client.sent] == [12000, 17000, 22000]
    assert [row[2]["seq"] for row in client.sent] == [1, 2, 3]
    assert [row[2]["uptime_ms"] for row in client.sent] == [12000, 17000, 22000]
    assert all(row[1] == b"iot/pico_01/sensor" and row[3:] == (0, False) for row in client.sent)
    assert client.socket.closed
    assert sender.events[-1] == {"event": "sender_stopped", "publish_sent": 3}


def test_reconnection_resumes_current_sampling_without_replaying_missed_samples(sender, monkeypatch):
    clients = [Client(sender.clock, fail_publish=2), Client(sender.clock)]
    connections = []
    reads = []

    def connect():
        if connections:
            sender.clock.sleep_ms(10000)
        client = clients[len(connections)]
        connections.append(client)
        return client

    def measure():
        reads.append(sender.clock.now)
        if len(reads) == 5:
            raise KeyboardInterrupt
        return (25.1, 48.0, 1006.5), (519888, 3200, 415148)

    monkeypatch.setattr(sender.module, "connect_mqtt", connect)
    monkeypatch.setattr(sender.module, "BME280", lambda *args, **kwargs: SimpleNamespace(measure=measure))
    with pytest.raises(KeyboardInterrupt):
        sender.module.main()

    sent = clients[0].sent + clients[1].sent
    assert [row[0] for row in sent] == [0, 16000, 21000]
    assert [row[2]["seq"] for row in sent] == [1, 3, 4]
    assert all(client.socket.closed for client in clients)
    assert len([row for row in sender.events if row["event"] == "publish_retry"]) == 1
    assert sender.events[-1] == {"event": "sender_stopped", "publish_sent": 3}
