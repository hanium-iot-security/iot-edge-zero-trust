# Mosquitto 참고

이 디렉터리는 Raspberry Pi에서 사용할 Mosquitto 설정 예시를 보관합니다.

MVP에서는 Mosquitto를 Raspberry Pi에 직접 설치해 실행하는 것을 기준으로 합니다.

```bash
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```

`mosquitto.conf`는 참고용 설정입니다. 기본 MVP 구성은 Raspberry Pi에 Mosquitto를 직접 설치해 사용합니다.
