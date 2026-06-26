import { useEffect, useState } from "react";
import { getMqttLogs } from "../api/api";

export default function Logs() {
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      const data = await getMqttLogs();
      setLogs(data?.items || []);
      setError("");
    } catch (err) {
      console.error("MQTT logs load failed:", err);
      setLogs([]);
      setError("MQTT 로그를 불러오지 못했습니다.");
    }
  }

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 3000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div>
      <h1>MQTT Logs Page</h1>

      {error && <p className="error-message">{error}</p>}

      {logs.length === 0 ? (
        <p>표시할 MQTT 로그가 없습니다.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Device</th>
              <th>Topic</th>
              <th>Payload</th>
              <th>Size</th>
              <th>JSON</th>
              <th>Topic Valid</th>
              <th>Error</th>
              <th>Received At</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id}>
                <td>{log.id ?? "-"}</td>
                <td>{log.device_id || "-"}</td>
                <td>{log.topic || "-"}</td>
                <td>{log.payload || "-"}</td>
                <td>{log.payload_size ?? "-"}</td>
                <td>{log.is_json_valid ? "valid" : "invalid"}</td>
                <td>{log.is_topic_valid ? "valid" : "invalid"}</td>
                <td>{log.error_message || "-"}</td>
                <td>{log.received_at || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}