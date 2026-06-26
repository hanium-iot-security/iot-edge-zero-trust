import { useEffect, useState } from "react";
import { getEvents } from "../api/api";

export default function Events() {
  const [events, setEvents] = useState([]);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      const data = await getEvents();
      setEvents(data?.items || []);
      setError("");
    } catch (err) {
      console.error("Events data load failed:", err);
      setEvents([]);
      setError("탐지 이벤트를 불러오지 못했습니다.");
    }
  }

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 3000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div>
      <h1>Detection Events Page</h1>

      {error && <p className="error-message">{error}</p>}

      {events.length === 0 ? (
        <p>표시할 탐지 이벤트가 없습니다.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Device</th>
              <th>Detector</th>
              <th>Event Type</th>
              <th>Severity</th>
              <th>Score Delta</th>
              <th>Applied</th>
              <th>Description</th>
              <th>Detected At</th>
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
                <td>{event.id ?? "-"}</td>
                <td>{event.device_id || "-"}</td>
                <td>{event.detector_type || "-"}</td>
                <td>{event.event_type || "-"}</td>
                <td>{event.severity || "-"}</td>
                <td>{event.score_delta ?? "-"}</td>
                <td>{event.applied_to_score ? "yes" : "no"}</td>
                <td>{event.description || "-"}</td>
                <td>{event.detected_at || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}