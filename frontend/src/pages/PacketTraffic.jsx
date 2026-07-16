import { useEffect, useState } from "react";
import { getPacketFeatureLogs } from "../api/api";

function formatKST(dateString) {
  if (!dateString) return "-";

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
  }).format(date);
}

function formatNumber(value, maximumFractionDigits = 2) {
  if (value === null || value === undefined) return "-";

  const number = Number(value);

  if (Number.isNaN(number)) return "-";

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

export default function PacketTraffic() {
  const [packetFeatures, setPacketFeatures] = useState([]);
  const [total, setTotal] = useState(0);
  const [direction, setDirection] = useState("");
  const [searchText, setSearchText] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadPacketFeatures() {
    try {
      const data = await getPacketFeatureLogs();

      setPacketFeatures(data?.items || []);
      setTotal(data?.total || 0);
      setError("");
    } catch (err) {
      console.error("Packet feature load failed:", err);
      setError("Packet Traffic 데이터를 불러오지 못했습니다.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadPacketFeatures();

    const timer = setInterval(loadPacketFeatures, 3000);

    return () => clearInterval(timer);
  }, []);

  const filteredItems = packetFeatures.filter((item) => {
    const matchesDirection =
      !direction || item.direction === direction;

    const keyword = searchText.trim().toLowerCase();

    const matchesSearch =
      !keyword ||
      item.device_id?.toLowerCase().includes(keyword) ||
      item.peer_ip?.toLowerCase().includes(keyword) ||
      item.session_id?.toLowerCase().includes(keyword);

    return matchesDirection && matchesSearch;
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Packet Traffic</h1>
          <p className="page-description">
            Raspberry Pi에서 수집한 10초 단위 Packet Feature를 확인합니다.
          </p>
        </div>

        <button className="refresh-button" onClick={loadPacketFeatures}>
          새로고침
        </button>
      </div>

      {error && (
        <div className="error-box">
          <span>{error}</span>
          <button onClick={loadPacketFeatures}>다시 시도</button>
        </div>
      )}

      <div className="card-grid packet-summary-grid">
        <div className="card">
          <span className="card-label">전체 Feature</span>
          <strong>{total}</strong>
        </div>

        <div className="card">
          <span className="card-label">현재 표시</span>
          <strong>{filteredItems.length}</strong>
        </div>

        <div className="card">
          <span className="card-label">등록 기기</span>
          <strong>
            {packetFeatures.filter((item) => item.device_id).length}
          </strong>
        </div>

        <div className="card warning-card">
          <span className="card-label">미매핑 IP</span>
          <strong>
            {packetFeatures.filter((item) => !item.device_id).length}
          </strong>
        </div>
      </div>

      <section className="panel">
        <div className="filter-row">
          <div className="filter-item">
            <label htmlFor="packet-search">기기 또는 IP 검색</label>
            <input
              id="packet-search"
              type="text"
              placeholder="device_id, peer_ip, session_id"
              value={searchText}
              onChange={(event) => setSearchText(event.target.value)}
            />
          </div>

          <div className="filter-item">
            <label htmlFor="direction-filter">Direction</label>
            <select
              id="direction-filter"
              value={direction}
              onChange={(event) => setDirection(event.target.value)}
            >
              <option value="">전체</option>
              <option value="INBOUND">INBOUND</option>
              <option value="OUTBOUND">OUTBOUND</option>
            </select>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Packet Feature 목록</h2>
          <span className="data-count">
            {filteredItems.length}건 표시
          </span>
        </div>

        {loading ? (
          <p>Packet Traffic 데이터를 불러오는 중입니다.</p>
        ) : filteredItems.length === 0 ? (
          <div className="empty-state">
            <p>표시할 Packet Feature가 없습니다.</p>
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
                  <th>평균 도착 간격</th>
                  <th>목적지 Port 수</th>
                  <th>TCP SYN</th>
                  <th>MQTT</th>
                  <th>Non-MQTT</th>
                </tr>
              </thead>

              <tbody>
                {filteredItems.map((item) => (
                  <tr key={item.id}>
                    <td
                      className="session-cell"
                      title={item.session_id || ""}
                    >
                      {item.session_id
                        ? item.session_id.slice(0, 8)
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
                          {getDeviceLabel(item)}
                        </span>

                        {!item.device_id && (
                          <small>{item.peer_ip || "-"}</small>
                        )}
                      </div>
                    </td>

                    <td>{item.peer_ip || "-"}</td>

                    <td>
                      <span
                        className={`badge direction-${(
                          item.direction || "unknown"
                        ).toLowerCase()}`}
                      >
                        {item.direction || "-"}
                      </span>
                    </td>

                    <td className="window-cell">
                      <div>{formatKST(item.window_start)}</div>
                      <div className="window-separator">~</div>
                      <div>{formatKST(item.window_end)}</div>
                    </td>

                    <td>{formatNumber(item.packet_count, 0)}</td>
                    <td>{formatNumber(item.total_bytes, 0)}</td>
                    <td>{formatNumber(item.packets_per_second)}</td>
                    <td>{formatNumber(item.bytes_per_second)}</td>
                    <td>
                      {formatNumber(item.mean_inter_arrival_time)}초
                    </td>
                    <td>
                      {formatNumber(
                        item.distinct_dest_port_count,
                        0
                      )}
                    </td>
                    <td>{formatNumber(item.tcp_syn_count, 0)}</td>
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
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}