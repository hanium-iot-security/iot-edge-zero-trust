# Save a filled-in copy as config.py on the Pico only after provisioning.
# Example values contain no working network or broker credentials.
WIFI_SSID = "REPLACE_WITH_WIFI_SSID"
WIFI_PASSWORD = "REPLACE_WITH_WIFI_PASSWORD"

# Use the broker's numeric IPv4 address so connection attempts do not need DNS.
MQTT_HOST = "192.0.2.1"
MQTT_PORT = 1883
MQTT_USERNAME = "REPLACE_WITH_DEVICE_MQTT_USERNAME"
MQTT_PASSWORD = "REPLACE_WITH_DEVICE_MQTT_PASSWORD"

DEVICE_ID = "pico_01"
MQTT_TOPIC = "iot/pico_01/sensor"
