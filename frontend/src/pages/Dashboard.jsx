import { useEffect, useState } from "react";
import {
  getSummary,
  getMqttLogs,
  getFeatureLogs,
  getEvents,
  getTrustScoreSummary,
} from "../api/api";
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
  const [trustScores, setTrustScores] = useState([]);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      const [
        summaryData,
        logData,
        featureData,
        eventData,
        trustScoreData,
      ] = await Promise.all([
        getSummary(),
        getMqttLogs(),
        getFeatureLogs(),
        getEvents(),
        getTrustScoreSummary(),
      ]);

      setSummary(summaryData || {});
      setLogs(logData?.items || []);
      setFeatures(featureData?.items || []);
      setEvents(eventData?.items || []);
      setTrustScores(trustScoreData?.items || []);
      setError("");
    } catch (err) {
      console.error("Dashboard data load failed:", err);
      setError("대시보드 데이터를 불러오지 못했습니다.");
      setSummary((prev) => prev || {});
      setLogs([]);
      setFeatures([]);
      setEvents([]);
      setTrustScores([]);
    }
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

      {error && <p className="error-message">{error}</p>}

      <div className="card-grid">
        <div className="card">전체 기기: {summary.total_devices ?? 0}</div>
        <div className="card">정상: {summary.normal_devices ?? 0}</div>
        <div className="card">주의: {summary.warning_devices ?? 0}</div>
        <div className="card">위험: {summary.danger_devices ?? 0}</div>
        <div className="card danger">격리: {summary.isolated_devices ?? 0}</div>
      </div>

      <section className="panel">
        <h2>Trust Score Summary</h2>

        {trustScores.length === 0 ? (
          <p>표시할 Trust Score 데이터가 없습니다.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Trust Score</th>
                <th>Status</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {trustScores.map((item) => (
                <tr key={item.device_id}>
                  <td>{item.device_id || "-"}</td>
                  <td>{item.trust_score ?? "-"}</td>
                  <td>
                    <span className={`badge ${item.status || "unknown"}`}>
                      {item.status || "-"}
                    </span>
                  </td>
                  <td>{item.last_seen_at || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h2>Feature Graph</h2>

        {features.length === 0 ? (
          <p>표시할 feature log가 없습니다.</p>
        ) : (
          <LineChart width={700} height={300} data={features}>
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
              dataKey="avg_payload_size"
              stroke="#16a34a"
              strokeWidth={2}
              name="Avg Payload Size"
            />

            <Line
              type="monotone"
              dataKey="max_payload_size"
              stroke="#ef4444"
              strokeWidth={3}
              name="Max Payload Size"
            />

            <Line
              type="monotone"
              dataKey="avg_message_interval"
              stroke="#9333ea"
              strokeWidth={2}
              name="Avg Message Interval"
            />

            <Line
              type="monotone"
              dataKey="min_message_interval"
              stroke="#f97316"
              strokeWidth={2}
              name="Min Message Interval"
            />
          </LineChart>
        )}
      </section>

      <section className="panel">
        <h2>최근 탐지 이벤트</h2>

        {events.length === 0 ? (
          <p>표시할 탐지 이벤트가 없습니다.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Detector</th>
                <th>Event</th>
                <th>Severity</th>
                <th>Score Delta</th>
                <th>Applied</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr
                  key={event.id}
                  className={
                    event.detector_type === "AI" ||
                    event.event_type === "AI_ANOMALY"
                      ? "ai-event"
                      : ""
                  }
                >
                  <td>{event.device_id || "-"}</td>
                  <td>{event.detector_type || "-"}</td>
                  <td>{event.event_type || "-"}</td>
                  <td>{event.severity || "-"}</td>
                  <td>{event.score_delta ?? "-"}</td>
                  <td>{event.applied_to_score ? "Y" : "N"}</td>
                  <td>{event.detected_at || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h2>최근 MQTT 로그</h2>

        {logs.length === 0 ? (
          <p>표시할 MQTT 로그가 없습니다.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Topic</th>
                <th>Payload Size</th>
                <th>JSON</th>
                <th>Topic Valid</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td>{log.device_id || "-"}</td>
                  <td>{log.topic || "-"}</td>
                  <td>{log.payload_size ?? "-"}</td>
                  <td>{log.is_json_valid ? "Y" : "N"}</td>
                  <td>{log.is_topic_valid ? "Y" : "N"}</td>
                  <td>{log.received_at || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}