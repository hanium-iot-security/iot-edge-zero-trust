import { useEffect, useState } from "react";
import { getIsolationHistory } from "../api/api";

export default function Isolation() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    async function loadData() {
      const data = await getIsolationHistory();
      setHistory(data.items);
    }

    loadData();
  }, []);

  return (
    <div>
      <h1>Isolation Page</h1>

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
              <td>{item.id}</td>
              <td>{item.device_id}</td>
              <td>{item.action}</td>
              <td>{item.reason}</td>
              <td>{item.trust_score}</td>
              <td>{item.trigger_event_id}</td>
              <td>{item.created_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}