import {
  BrowserRouter,
  Routes,
  Route,
  NavLink,
} from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Logs from "./pages/Logs";
import Events from "./pages/Events";
import Isolation from "./pages/Isolation";
import PacketTraffic from "./pages/PacketTraffic";
import GatewayStatus from "./pages/GatewayStatus";


export default function App() {
  return (
    <BrowserRouter>
      <div className="layout">
        <aside className="sidebar">
          <h2>IoT Zero Trust</h2>

          <NavLink to="/">Dashboard</NavLink>
          <NavLink to="/devices">Devices</NavLink>
          <NavLink to="/logs">MQTT Logs</NavLink>
          <NavLink to="/events">Detection Events</NavLink>
          <NavLink to="/isolation">Isolation</NavLink>

          <div className="sidebar-divider" />

          <p className="sidebar-section-title">Packet / Gateway</p>
          <NavLink to="/packet-traffic">통신 분석</NavLink>
          <NavLink to="/gateway-status">Gateway Status</NavLink>
        </aside>

        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/events" element={<Events />} />
            <Route path="/isolation" element={<Isolation />} />

            <Route
              path="/packet-traffic"
              element={<PacketTraffic />}
            />
            <Route
              path="/gateway-status"
              element={<GatewayStatus />}
            />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
