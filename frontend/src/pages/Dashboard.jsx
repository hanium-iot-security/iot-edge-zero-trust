import { useEffect, useState } from "react";
import { getSummary, getMqttLogs, getFeatureLogs, getEvents } from "../api/api";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from "recharts";

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [logs, setLogs] = useState([]);
  const [features, setFeatures] = useState([]);
  const [events, setEvents] = useState([]);

  async function loadData() {
    const summaryData = await getSummary();
    const logData = await getMqttLogs();
    const featureData = await getFeatureLogs();
    const eventData = await getEvents();

    setSummary(summaryData);
    setLogs(logData.items);
    setFeatures(featureData.items);
    setEvents(eventData.items);
  }

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 3000);
    return () => clearInterval(timer);
  }, []);

  if (!summary) return <p>Loading...</p>;

  return (
    <div>
      <h1>Dashboard Home</h1>

      <div className="card-grid">
        <div className="card">전체 기기: {summary.total_devices}</div>
        <div className="card">정상: {summary.normal_devices}</div>
        <div className="card">주의: {summary.warning_devices}</div>
        <div className="card danger">격리: {summary.isolated_devices}</div>
      </div>

      <section className="panel">
        <h2>Feature Graph</h2>
        <LineChart width={600} height={250} data={features}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="window_start" />
          <YAxis />
          <Tooltip />
          <Legend />

          <Line
            type="monotone"
            dataKey="publish_count"
            stroke="#2563eb"
            strokeWidth={3}
            name="Publish Count"
          />

          <Line
            type="monotone"
            dataKey="max_payload_size"
            stroke="#ef4444"
            strokeWidth={3}
            name="Max Payload Size"
          />
        </LineChart>
      </section>

      <section className="panel">
        <h2>최근 탐지 이벤트</h2>
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Detector</th>
              <th>Event</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id}>
                <td>{event.device_id}</td>
                <td>{event.detector_type}</td>
                <td>{event.event_type}</td>
                <td>{event.severity}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>최근 MQTT 로그</h2>
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Topic</th>
              <th>Payload Size</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id}>
                <td>{log.device_id}</td>
                <td>{log.topic}</td>
                <td>{log.payload_size}</td>
                <td>{log.received_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}