import { useEffect, useState } from "react";
import { getDevices } from "../api/api";

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      const data = await getDevices();
      setDevices(data?.items || []);
      setError("");
    } catch (err) {
      console.error("Devices data load failed:", err);
      setDevices([]);
      setError("기기 목록을 불러오지 못했습니다.");
    }
  }

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 3000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div>
      <h1>Devices Page</h1>

      {error && <p className="error-message">{error}</p>}

      {devices.length === 0 ? (
        <p>표시할 기기가 없습니다.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Device ID</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>Trust Score</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((device) => (
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
    </div>
  );
}