import { useEffect, useState } from "react";
import { getEvents } from "../api/api";

export default function Events() {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    async function loadData() {
      const data = await getEvents();
      setEvents(data.items);
    }

    loadData();
  }, []);

  return (
    <div>
      <h1>Detection Events Page</h1>

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
            <th>Detected At</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>{event.id}</td>
              <td>{event.device_id}</td>
              <td>{event.detector_type}</td>
              <td>{event.event_type}</td>
              <td>{event.severity}</td>
              <td>{event.score_delta}</td>
              <td>{event.applied_to_score ? "yes" : "no"}</td>
              <td>{event.detected_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}