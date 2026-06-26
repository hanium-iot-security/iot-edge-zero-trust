import { useEffect, useState } from "react";
import { getIsolationHistory, getIsolatedDevices } from "../api/api";

export default function Isolation() {
  const [history, setHistory] = useState([]);
  const [isolatedDevices, setIsolatedDevices] = useState([]);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      const [historyData, isolatedDeviceData] = await Promise.all([
        getIsolationHistory(),
        getIsolatedDevices(),
      ]);

      setHistory(historyData?.items || []);
      setIsolatedDevices(isolatedDeviceData?.items || []);
      setError("");
    } catch (err) {
      console.error("Isolation data load failed:", err);
      setHistory([]);
      setIsolatedDevices([]);
      setError("격리 데이터를 불러오지 못했습니다.");
    }
  }

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 3000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div>
      <h1>Isolation Page</h1>

      {error && <p className="error-message">{error}</p>}

      <section className="panel">
        <h2>현재 격리된 기기</h2>

        {isolatedDevices.length === 0 ? (
          <p>현재 격리된 기기가 없습니다.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>Trust Score</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {isolatedDevices.map((device) => (
                <tr key={device.device_id}>
                  <td>{device.device_id || "-"}</td>
                  <td>{device.ip_address || "-"}</td>
                  <td>
                    <span className={`badge ${device.status || "unknown"}`}>
                      {device.status || "-"}
                    </span>
                  </td>
                  <td>{device.trust_score ?? "-"}</td>
                  <td>{device.last_seen_at || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h2>격리 이력</h2>

        {history.length === 0 ? (
          <p>표시할 격리 이력이 없습니다.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Device</th>
                <th>Action</th>
                <th>Reason</th>
                <th>Trust Score</th>
                <th>Trigger Event</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item) => (
                <tr key={item.id}>
                  <td>{item.id ?? "-"}</td>
                  <td>{item.device_id || "-"}</td>
                  <td>{item.action || "-"}</td>
                  <td>{item.reason || "-"}</td>
                  <td>{item.trust_score ?? "-"}</td>
                  <td>{item.trigger_event_id ?? "-"}</td>
                  <td>{item.created_at || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}