import {
  useCallback,
  useEffect,
  useState,
} from "react";
import {
  getPacketFeatureLogs,
} from "../api/api";

const POLLING_INTERVAL_MS = 10_000;

function formatKST(dateString) {
  if (!dateString) {
    return "-";
  }

  const date = new Date(dateString);

  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function formatNumber(
  value,
  maximumFractionDigits = 2
) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return "-";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "-";
  }

  return number.toLocaleString("ko-KR", {
    maximumFractionDigits,
  });
}

function getDeviceLabel(item) {
  if (item.device_id) {
    return item.device_id;
  }

  return "미매핑 IP";
}

function normalizeSearchValue(value) {
  return String(value ?? "").toLowerCase();
}

export default function PacketTraffic() {
  const [
    packetFeatures,
    setPacketFeatures,
  ] = useState([]);

  const [total, setTotal] =
    useState(0);

  const [direction, setDirection] =
    useState("");

  const [searchText, setSearchText] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const loadPacketFeatures =
    useCallback(async (isManualRefresh = false) => {
      if (isManualRefresh) {
        setRefreshing(true);
      }

      try {
        const data =
          await getPacketFeatureLogs();

        const items =
          Array.isArray(data?.items)
            ? data.items
            : [];

        const responseTotal =
          Number(data?.total);

        setPacketFeatures(items);

        setTotal(
          Number.isFinite(responseTotal)
            ? responseTotal
            : 0
        );

        setError("");
      } catch (err) {
        console.error(
          "Packet feature load failed:",
          err
        );

        setError(
          err instanceof Error
            ? err.message
            : "Packet Traffic 데이터를 불러오지 못했습니다."
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    }, []);

  useEffect(() => {
    loadPacketFeatures();

    const pollingTimer =
      window.setInterval(() => {
        loadPacketFeatures();
      }, POLLING_INTERVAL_MS);

    return () => {
      window.clearInterval(
        pollingTimer
      );
    };
  }, [loadPacketFeatures]);

  const filteredItems =
    packetFeatures.filter((item) => {
      const matchesDirection =
        !direction ||
        item.direction === direction;

      const keyword =
        searchText
          .trim()
          .toLowerCase();

      const matchesSearch =
        !keyword ||
        normalizeSearchValue(
          item.device_id
        ).includes(keyword) ||
        normalizeSearchValue(
          item.peer_ip
        ).includes(keyword) ||
        normalizeSearchValue(
          item.session_id
        ).includes(keyword);

      return (
        matchesDirection &&
        matchesSearch
      );
    });

  const mappedDeviceCount =
    packetFeatures.filter(
      (item) => Boolean(item.device_id)
    ).length;

  const unmappedIpCount =
    packetFeatures.filter(
      (item) => !item.device_id
    ).length;

  function handleRefresh() {
    loadPacketFeatures(true);
  }

  let content;

  if (loading) {
    content = (
      <section className="panel">
        <p>
          Packet Traffic 데이터를 불러오는 중입니다.
        </p>
      </section>
    );
  } else if (error) {
    content = (
      <section className="panel">
        <div className="error-box">
          <span>{error}</span>

          <button
            type="button"
            onClick={() =>
              loadPacketFeatures(true)
            }
            disabled={refreshing}
          >
            {refreshing
              ? "불러오는 중..."
              : "다시 시도"}
          </button>
        </div>
      </section>
    );
  } else if (
    packetFeatures.length === 0
  ) {
    content = (
      <section className="panel">
        <div className="empty-state">
          <h2>
            표시할 Packet Feature가 없습니다.
          </h2>

          <p>
            Packet Capture와 Feature Extractor가
            실행 중인지 확인해주세요.
          </p>
        </div>
      </section>
    );
  } else {
    content = (
      <>
        <div className="card-grid packet-summary-grid">
          <div className="card">
            <span className="card-label">
              전체 Feature
            </span>

            <strong>
              {formatNumber(total, 0)}
            </strong>
          </div>

          <div className="card">
            <span className="card-label">
              현재 표시
            </span>

            <strong>
              {formatNumber(
                filteredItems.length,
                0
              )}
            </strong>
          </div>

          <div className="card">
            <span className="card-label">
              등록 기기
            </span>

            <strong>
              {formatNumber(
                mappedDeviceCount,
                0
              )}
            </strong>
          </div>

          <div className="card warning-card">
            <span className="card-label">
              미매핑 IP
            </span>

            <strong>
              {formatNumber(
                unmappedIpCount,
                0
              )}
            </strong>
          </div>
        </div>

        <section className="panel">
          <div className="filter-row">
            <div className="filter-item">
              <label htmlFor="packet-search">
                기기 또는 IP 검색
              </label>

              <input
                id="packet-search"
                type="text"
                placeholder="device_id, peer_ip, session_id"
                value={searchText}
                onChange={(event) => {
                  setSearchText(
                    event.target.value
                  );
                }}
              />
            </div>

            <div className="filter-item">
              <label htmlFor="direction-filter">
                Direction
              </label>

              <select
                id="direction-filter"
                value={direction}
                onChange={(event) => {
                  setDirection(
                    event.target.value
                  );
                }}
              >
                <option value="">
                  전체
                </option>

                <option value="INBOUND">
                  INBOUND
                </option>

                <option value="OUTBOUND">
                  OUTBOUND
                </option>
              </select>
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>
                Packet Feature 목록
              </h2>

              <p className="panel-description">
                10초 단위로 생성된 Packet
                Feature입니다.
              </p>
            </div>

            <span className="data-count">
              {filteredItems.length}건 표시
            </span>
          </div>

          {filteredItems.length === 0 ? (
            <div className="empty-state">
              <p>
                검색 조건에 맞는 Packet
                Feature가 없습니다.
              </p>
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="wide-table">
                <thead>
                  <tr>
                    <th>Session</th>
                    <th>Device</th>
                    <th>Peer IP</th>
                    <th>Direction</th>
                    <th>분석 Window</th>
                    <th>Packet Count</th>
                    <th>Total Bytes</th>
                    <th>Packets/sec</th>
                    <th>Bytes/sec</th>
                    <th>평균 Packet 크기</th>
                    <th>최대 Packet 크기</th>
                    <th>평균 도착 간격</th>
                    <th>목적지 Port 수</th>
                    <th>TCP SYN</th>
                    <th>MQTT</th>
                    <th>Non-MQTT</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredItems.map(
                    (item) => (
                      <tr key={item.id}>
                        <td
                          className="session-cell"
                          title={
                            item.session_id ||
                            ""
                          }
                        >
                          {item.session_id
                            ? item.session_id.slice(
                                0,
                                8
                              )
                            : "-"}
                        </td>

                        <td>
                          <div className="device-cell">
                            <span
                              className={
                                item.device_id
                                  ? "badge mapped"
                                  : "badge unmapped"
                              }
                            >
                              {getDeviceLabel(
                                item
                              )}
                            </span>

                            {!item.device_id && (
                              <small>
                                {item.peer_ip ||
                                  "-"}
                              </small>
                            )}
                          </div>
                        </td>

                        <td>
                          {item.peer_ip ||
                            "-"}
                        </td>

                        <td>
                          <span
                            className={`badge direction-${normalizeSearchValue(
                              item.direction ||
                                "unknown"
                            )}`}
                          >
                            {item.direction ||
                              "-"}
                          </span>
                        </td>

                        <td className="window-cell">
                          <div>
                            {formatKST(
                              item.window_start
                            )}
                          </div>

                          <div className="window-separator">
                            ~
                          </div>

                          <div>
                            {formatKST(
                              item.window_end
                            )}
                          </div>
                        </td>

                        <td>
                          {formatNumber(
                            item.packet_count,
                            0
                          )}
                        </td>

                        <td>
                          {formatNumber(
                            item.total_bytes,
                            0
                          )}
                        </td>

                        <td>
                          {formatNumber(
                            item.packets_per_second
                          )}
                        </td>

                        <td>
                          {formatNumber(
                            item.bytes_per_second
                          )}
                        </td>

                        <td>
                          {formatNumber(
                            item.avg_packet_size
                          )}
                        </td>

                        <td>
                          {formatNumber(
                            item.max_packet_size,
                            0
                          )}
                        </td>

                        <td>
                          {item.mean_inter_arrival_time ===
                            null ||
                          item.mean_inter_arrival_time ===
                            undefined
                            ? "-"
                            : `${formatNumber(
                                item.mean_inter_arrival_time,
                                4
                              )}초`}
                        </td>

                        <td>
                          {formatNumber(
                            item.distinct_dest_port_count,
                            0
                          )}
                        </td>

                        <td>
                          {formatNumber(
                            item.tcp_syn_count,
                            0
                          )}
                        </td>

                        <td>
                          {formatNumber(
                            item.mqtt_related_packet_count,
                            0
                          )}
                        </td>

                        <td>
                          {formatNumber(
                            item.non_mqtt_tcp_udp_packet_count,
                            0
                          )}
                        </td>
                      </tr>
                    )
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Packet Traffic</h1>

          <p className="page-description">
            Raspberry Pi에서 수집한
            10초 단위 Packet Feature를
            확인합니다.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={handleRefresh}
          disabled={
            loading || refreshing
          }
        >
          {refreshing
            ? "새로고침 중..."
            : "새로고침"}
        </button>
      </div>

      {content}
    </div>
  );
}