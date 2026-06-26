import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Logs from "./pages/Logs";
import Events from "./pages/Events";
import Isolation from "./pages/Isolation";
import "../src/styles/style.css";

export default function App() {
  return (
    <BrowserRouter>
      <div className="layout">
        <aside className="sidebar">
          <h2>IoT Zero Trust</h2>
          <NavLink to="/">Dashboard</NavLink>
          <NavLink to="/devices">Devices</NavLink>
          <NavLink to="/logs">MQTT Logs</NavLink>
          <NavLink to="/events">Events</NavLink>
          <NavLink to="/isolation">Isolation</NavLink>
        </aside>

        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/events" element={<Events />} />
            <Route path="/isolation" element={<Isolation />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}