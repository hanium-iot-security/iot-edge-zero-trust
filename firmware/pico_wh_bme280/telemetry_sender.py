"""Pico W BME280 telemetry; QoS 0 sends require separate gateway verification."""
from machine import I2C, Pin
import json
import math
import network
import time

import config
from bme280 import BME280
from umqtt.simple import MQTTClient


INTERVAL_MS = 5000
WIFI_TIMEOUT_MS = 15000
SOCKET_TIMEOUT_SECONDS = 5
MAX_BACKOFF_MS = 30000
KEEPALIVE_SECONDS = 30
MAX_PAYLOAD_BYTES = 5120


def log(event, **fields):
    fields["event"] = event
    print(json.dumps(fields))


def validate_config():
    required = (
        "WIFI_SSID", "WIFI_PASSWORD", "MQTT_HOST", "MQTT_USERNAME",
        "MQTT_PASSWORD", "DEVICE_ID", "MQTT_TOPIC",
    )
    for name in required:
        value = getattr(config, name, None)
        if not isinstance(value, str) or not value or value.startswith("REPLACE_"):
            raise ValueError("Missing configuration: " + name)
    octets = config.MQTT_HOST.split(".")
    if len(octets) != 4 or not all(
        part.isdigit() and 0 <= int(part) <= 255 for part in octets
    ):
        raise ValueError("MQTT_HOST must be a numeric IPv4 address")
    if config.MQTT_HOST == "192.0.2.1":
        raise ValueError("Replace the example MQTT_HOST")
    if type(config.MQTT_PORT) is not int or not 1 <= config.MQTT_PORT <= 65535:
        raise ValueError("Invalid MQTT_PORT")
    if config.DEVICE_ID != "pico_01":
        raise ValueError("This verified firmware is for pico_01")
    if config.MQTT_TOPIC != "iot/%s/sensor" % config.DEVICE_ID:
        raise ValueError("MQTT_TOPIC must match the device's sensor topic")


def close_client(client):
    # Closing the socket does not depend on successfully sending DISCONNECT.
    if client is not None and client.sock is not None:
        try:
            client.sock.close()
        except Exception:
            pass
        client.sock = None


def wait_until(target):
    while True:
        remaining = time.ticks_diff(target, time.ticks_ms())
        if remaining <= 0:
            return
        time.sleep_ms(min(100, remaining))


def connect_wifi(wlan):
    wlan.active(True)
    if wlan.isconnected():
        return
    wlan.connect(config.WIFI_SSID, config.WIFI_PASSWORD)
    started = time.ticks_ms()
    while not wlan.isconnected():
        if wlan.status() < 0:
            raise OSError("Wi-Fi connection failed")
        if time.ticks_diff(time.ticks_ms(), started) >= WIFI_TIMEOUT_MS:
            raise OSError("Wi-Fi connection timeout")
        time.sleep_ms(100)


def connect_mqtt():
    client = MQTTClient(
        config.DEVICE_ID.encode("utf-8"),
        config.MQTT_HOST,
        port=config.MQTT_PORT,
        user=config.MQTT_USERNAME.encode("utf-8"),
        password=config.MQTT_PASSWORD.encode("utf-8"),
        keepalive=KEEPALIVE_SECONDS,
    )
    try:
        # The bundled official version applies this before TCP connect and CONNACK.
        client.connect(clean_session=True, timeout=SOCKET_TIMEOUT_SECONDS)
        client.sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        return client
    except BaseException:
        close_client(client)
        raise


def build_payload(sequence, uptime_ms, values):
    temperature, humidity, pressure = values
    if not all(math.isfinite(value) for value in values):
        raise ValueError("Non-finite telemetry")
    payload = json.dumps({
        "device_id": config.DEVICE_ID,
        "seq": sequence,
        "uptime_ms": uptime_ms,
        "temperature_c": round(temperature, 2),
        "humidity_pct": round(humidity, 2),
        "pressure_hpa": round(pressure, 2),
    }).encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("Payload exceeds firmware maximum")
    return payload


def main():
    validate_config()
    i2c = I2C(0, sda=Pin(4), scl=Pin(5), freq=100000)
    wlan = network.WLAN(network.STA_IF)
    client = None
    sensor = None
    sequence = 0
    publish_sent = 0
    backoff_ms = 1000
    uptime_ms = 0
    last_tick = time.ticks_ms()
    next_sample = last_tick
    last_send = last_tick
    log("sender_start", device_id=config.DEVICE_ID, interval_ms=INTERVAL_MS,
        qos=0, retain=False, delivery_confirmation="gateway_required")
    try:
        while True:
            now = time.ticks_ms()
            uptime_ms += max(0, time.ticks_diff(now, last_tick))
            last_tick = now
            if client is None:
                try:
                    connect_wifi(wlan)
                    client = connect_mqtt()
                    # A reconnection starts a fresh schedule; no missed samples queue.
                    next_sample = time.ticks_ms()
                    last_send = next_sample
                    log("mqtt_connected", delivery_confirmation="gateway_required")
                except Exception as error:
                    close_client(client)
                    client = None
                    if not wlan.isconnected():
                        try:
                            wlan.disconnect()
                        except Exception:
                            pass
                    log("connection_retry", error_type=type(error).__name__,
                        retry_ms=backoff_ms)
                    time.sleep_ms(backoff_ms)
                    backoff_ms = min(MAX_BACKOFF_MS, backoff_ms * 2)
                    continue
            wait_until(next_sample)
            sequence += 1
            try:
                if sensor is None:
                    sensor = BME280(i2c, address=0x76)
                values, _raw = sensor.measure()
                now = time.ticks_ms()
                elapsed = uptime_ms + max(0, time.ticks_diff(now, last_tick))
                payload = build_payload(sequence, elapsed, values)
            except Exception as error:
                sensor = None
                log("sensor_error", seq=sequence, error_type=type(error).__name__,
                    publish_sent=publish_sent)
                # No fabricated measurement is published when the sensor fails.
                payload = None
            try:
                if not wlan.isconnected():
                    raise OSError("Wi-Fi disconnected")
                client.sock.settimeout(SOCKET_TIMEOUT_SECONDS)
                if payload is not None:
                    client.publish(config.MQTT_TOPIC.encode("utf-8"), payload,
                                   qos=0, retain=False)
                    publish_sent += 1
                    last_send = time.ticks_ms()
                    # QoS 0 returning proves a local send, not broker ingestion.
                    log("publish_sent", seq=sequence, count=publish_sent,
                        payload_bytes=len(payload), delivery_confirmation="gateway_required")
                    backoff_ms = 1000
                elif time.ticks_diff(time.ticks_ms(), last_send) >= 15000:
                    client.ping()
                    last_send = time.ticks_ms()
            except Exception as error:
                close_client(client)
                client = None
                log("publish_retry", seq=sequence, error_type=type(error).__name__,
                    retry_ms=backoff_ms, publish_sent=publish_sent)
                time.sleep_ms(backoff_ms)
                backoff_ms = min(MAX_BACKOFF_MS, backoff_ms * 2)
            # Base each deadline on current time so slow operations never cause bursts.
            next_sample = time.ticks_add(time.ticks_ms(), INTERVAL_MS)
    finally:
        close_client(client)
        log("sender_stopped", publish_sent=publish_sent)


if __name__ == "__main__":
    main()
