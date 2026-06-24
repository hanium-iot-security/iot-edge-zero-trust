import { useEffect, useState } from "react";
import { getMqttLogs } from "../api/api";

export default function Logs() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    async function loadData() {
      const data = await getMqttLogs();
      setLogs(data.items);
    }

    loadData();
  }, []);

  return (
    <div>
      <h1>MQTT Logs Page</h1>

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
            <th>Received At</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.id}>
              <td>{log.id}</td>
              <td>{log.device_id}</td>
              <td>{log.topic}</td>
              <td>{log.payload}</td>
              <td>{log.payload_size}</td>
              <td>{log.is_json_valid ? "valid" : "invalid"}</td>
              <td>{log.is_topic_valid ? "valid" : "invalid"}</td>
              <td>{log.received_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}