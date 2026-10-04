# 소스와 라이선스

`bme280.py`는 이 프로젝트의 직렬 센서 확인 코드에서 분리한 Python
드라이버다. 보정 식과 레지스터 정의의 근거는 [Bosch BME280 공식 데이터시트](https://www.bosch-sensortec.com/media/boschsensortec/downloads/datasheets/bst-bme280-ds002.pdf)의
4.2.2, 4.2.3, 8.1이다. 현재 PDF 표지는 revision 1.24 (2024-02), 본문
페이지 각주는 revision 1.23으로 표시된다. 여기서 인용한 보정식은 본문의
식이다. 기압 반환 단위는 Pa를 100으로 나눈 hPa다.

습도 계산은 8.1의 double 식 및 4.2.3의 integer 식에 맞춰 `c*d*f`를
사용한다. H3 항은 H6 항 안에만 들어간다. [현재 Bosch SensorAPI double
구현](https://github.com/boschsensortec/BME280_SensorAPI/blob/master/bme280.c#L1195-L1225)의
`c*d*(e*f)`와는 H3가 0이 아닐 때 다르다. 두 공식 자료의 불일치를 숨기지
않고 데이터시트 식을 이 드라이버의 계약으로 정했다. 호스트 테스트는 H3가
0이 아닌 계수와 음수 H4/H5를 독립된 데이터시트 식으로 확인한다. 이는
기준 계측기와 비교한 절대 정확도 교정의 증거는 아니다.

측정 상태의 근거는 데이터시트 3.3.3, 3.4.3, 5.4.3–5.4.5다. forced 변환은
끝나면 sleep으로 돌아가며, status의 measuring/im_update 비트가 완료 상태를
나타낸다. 온도·기압의 `0x80000` 및 습도의 `0x8000`은 skipped 채널의 출력으로
정의되지만 활성 채널에서 예약되어 있다는 규정은 없다. [공식 SensorAPI의
parse/compensate 경로](https://github.com/boschsensortec/BME280_SensorAPI/blob/master/bme280.c#L708-L785)도
이 숫자 자체를 거부하지 않는다. 따라서 이 드라이버는 x1 oversampling과
변환 완료를 실제 레지스터 readback으로 검사한 뒤 raw 숫자를 보정한다.
호스트 sensor-proof 검증도 매 행의 같은 상태 증거를 요구한다. 테스트는
활성 상태의 midpoint 코드 수용과 비활성·미완료 상태 거부를 구분한다.
이 변경은 유효 숫자의 오인 가능성을 제거하며 이전 단발 오류의 원인 확정을
주장하지 않는다.

`lib/umqtt/simple.py`는 공식 `micropython/micropython-lib`의
`micropython/umqtt.simple/umqtt/simple.py`에서 받은 준비본을 변경 없이
보존했다. 원저작자는 upstream manifest에 명시된 Paul Sokolovsky이며,
그 이후 micropython-lib 기여자들의 변경이 포함된다.

| 항목 | 값 |
| --- | --- |
| 원본 URL | <https://raw.githubusercontent.com/micropython/micropython-lib/master/micropython/umqtt.simple/umqtt/simple.py> |
| 준비본 확인일 | 2026-10-04 |
| simple.py SHA256 | `5458b97fc074db01263e82ae898727aee2a15079ea5cff9d2f6d6abbea8ea217` |
| __init__.py | 빈 package 파일 |

위 URL의 `master`는 변할 수 있으므로 재배포한 바이트는 SHA256으로
식별한다. 현재 upstream manifest의 버전만으로 이 준비본을 특정 release와
동일하다고 주장하지 않는다.

공식 배포자의 [umqtt.simple package metadata](https://pypi.org/project/micropython-umqtt.simple/)
는 MIT를 명시한다. [upstream LICENSE](https://github.com/micropython/micropython-lib/blob/master/LICENSE)의
MIT 저작권·허가 문구를 [lib/umqtt/LICENSE.txt](lib/umqtt/LICENSE.txt)에 보존했다.
라이브러리를 복사하거나 배포할 때 이 문구도 함께 유지한다.
