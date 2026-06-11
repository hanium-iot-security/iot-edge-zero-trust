# ESP32 펌웨어

ESP32 정상 telemetry 펌웨어와 공격 모드 펌웨어를 이 디렉터리에 둡니다.

권장 분리:

```txt
normal_sender/
attack_sender/
```

## MQTT 설정

```txt
MQTT Broker: 192.168.0.20
MQTT Port: 1883
Topic: iot/esp32_01/sensor
Device ID: esp32_01
```

ESP32는 Raspberry Pi의 Mosquitto broker로 publish하므로 broker 주소는 Raspberry Pi 고정 IP인 `192.168.0.20`을 사용합니다.
