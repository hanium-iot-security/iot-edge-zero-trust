import { useEffect, useState } from "react";
import { getDevices } from "../api/api";

export default function Devices() {
  const [devices, setDevices] = useState([]);

  useEffect(() => {
    async function loadData() {
      const data = await getDevices();
      setDevices(data.items);
    }

    loadData();
  }, []);

  return (
    <div>
      <h1>Devices Page</h1>

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
              <td>{device.device_id}</td>
              <td>{device.ip_address}</td>
              <td>
                <span className={`badge ${device.status}`}>
                  {device.status}
                </span>
              </td>
              <td>{device.trust_score}</td>
              <td>{device.last_seen_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}