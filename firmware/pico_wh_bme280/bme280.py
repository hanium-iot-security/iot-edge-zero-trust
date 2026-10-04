"""BME280 forced measurements using Bosch datasheet compensation formulas.

Humidity follows datasheet revision 1.23, Appendix 8.1, and its integer formula:
H3 is nested inside the H6 factor; it is not another multiplier outside it.
"""
import math
import struct
import time

def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value



class BME280:
    def __init__(self, i2c, address=0x76):
        self.i2c = i2c
        self.address = address
        if self.read(0xD0, 1)[0] != 0x60:
            raise RuntimeError('Expected BME280 chip ID 0x60')
        self.write(0xE0, 0xB6)
        time.sleep_ms(10)
        self.wait_clear(0x01, 100)
        calibration = self.read(0x88, 26)
        self.t1 = struct.unpack_from('<H', calibration, 0)[0]
        self.t2, self.t3 = struct.unpack_from('<hh', calibration, 2)
        self.p1 = struct.unpack_from('<H', calibration, 6)[0]
        self.p = struct.unpack_from('<hhhhhhhh', calibration, 8)
        self.h1 = calibration[25]
        humidity = self.read(0xE1, 7)
        self.h2 = struct.unpack_from('<h', humidity, 0)[0]
        self.h3 = humidity[2]
        self.h4 = signed((humidity[3] << 4) | (humidity[4] & 15), 12)
        self.h5 = signed((humidity[5] << 4) | (humidity[4] >> 4), 12)
        self.h6 = signed(humidity[6], 8)
        if not self.t1 or not self.p1 or not self.h2:
            raise RuntimeError('Invalid factory calibration')
        self.write(0xF2, 0x01)  # Humidity x1; latched by subsequent F4 write.
        self.write(0xF5, 0x00)  # Filter off, configured while asleep.

    def read(self, register, size):
        return self.i2c.readfrom_mem(self.address, register, size)

    def write(self, register, value):
        self.i2c.writeto_mem(self.address, register, bytes([value]))

    def wait_clear(self, mask, timeout_ms):
        started = time.ticks_ms()
        while self.read(0xF3, 1)[0] & mask:
            if time.ticks_diff(time.ticks_ms(), started) >= timeout_ms:
                raise RuntimeError('BME280 status timeout')
            time.sleep_ms(2)

    def compensate(self, raw_t, raw_p, raw_h):
        a = (raw_t / 16384.0 - self.t1 / 1024.0) * self.t2
        b = raw_t / 131072.0 - self.t1 / 8192.0
        fine = a + b * b * self.t3
        temperature = fine / 5120.0

        p2, p3, p4, p5, p6, p7, p8, p9 = self.p
        a = fine / 2.0 - 64000.0
        b = a * a * p6 / 32768.0 + a * p5 * 2.0
        b = b / 4.0 + p4 * 65536.0
        a = (p3 * a * a / 524288.0 + p2 * a) / 524288.0
        a = (1.0 + a / 32768.0) * self.p1
        if a <= 0:
            raise RuntimeError('Invalid pressure denominator')
        pressure = ((1048576.0 - raw_p) - b / 4096.0) * 6250.0 / a
        a = p9 * pressure * pressure / 2147483648.0
        b = pressure * p8 / 32768.0
        pressure += (a + b + p7) / 16.0

        a = fine - 76800.0
        b = self.h4 * 64.0 + (self.h5 / 16384.0) * a
        c = raw_h - b
        d = self.h2 / 65536.0
        e = 1.0 + (self.h3 / 67108864.0) * a
        f = 1.0 + (self.h6 / 67108864.0) * a * e
        humidity = c * d * f
        humidity *= 1.0 - self.h1 * humidity / 524288.0
        if not all(math.isfinite(x) for x in (temperature, pressure, humidity)):
            raise RuntimeError('Non-finite sensor reading')
        humidity = min(100.0, max(0.0, humidity))
        if not -40 <= temperature <= 85 or not 30000 <= pressure <= 110000:
            raise RuntimeError('Reading outside BME280 operating range')
        return temperature, humidity, pressure / 100.0

    def measure(self):
        self.write(0xF4, 0x25)  # Temperature x1, pressure x1, forced one-shot.
        time.sleep_ms(20)
        self.wait_clear(0x09, 100)  # Conversion and NVM copy must both finish.
        ctrl_hum = self.read(0xF2, 1)[0]
        status = self.read(0xF3, 1)[0]
        ctrl_meas = self.read(0xF4, 1)[0]
        if ctrl_hum & 0x07 != 0x01 or ctrl_meas & 0xFC != 0x24:
            raise RuntimeError('BME280 measurement configuration mismatch')
        # A forced measurement returns to sleep, retaining its oversampling bits.
        if status & 0x09 or ctrl_meas & 0x03:
            raise RuntimeError('BME280 conversion incomplete')
        data = self.read(0xF7, 8)
        raw_p = (data[0] << 12) | (data[1] << 4) | (data[2] >> 4)
        raw_t = (data[3] << 12) | (data[4] << 4) | (data[5] >> 4)
        raw_h = (data[6] << 8) | data[7]
        # Skipped channels use midpoint codes, but active ADC readings may also
        # equal those numbers. Validate channel state above, not raw equality.
        return self.compensate(raw_t, raw_p, raw_h), (raw_t, raw_h, raw_p)
