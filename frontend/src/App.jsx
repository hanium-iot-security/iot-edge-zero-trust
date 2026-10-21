import {
  BrowserRouter,
  Routes,
  Route,
  NavLink,
} from "react-router-dom";
import NavigationIcon from "./components/NavigationIcon";
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

          <NavLink to="/"><NavigationIcon name="overview" /><span>종합 현황</span></NavLink>
          <NavLink to="/devices"><NavigationIcon name="devices" /><span>기기 관리</span></NavLink>
          <NavLink to="/logs"><NavigationIcon name="logs" /><span>MQTT 수신 로그</span></NavLink>
          <NavLink to="/events"><NavigationIcon name="events" /><span>탐지 이벤트</span></NavLink>
          <NavLink to="/isolation"><NavigationIcon name="isolation" /><span>격리·복구</span></NavLink>

          <div className="sidebar-divider" />

          <p className="sidebar-section-title">통신·게이트웨이</p>
          <NavLink to="/packet-traffic"><NavigationIcon name="traffic" /><span>통신 분석</span></NavLink>
          <NavLink to="/gateway-status"><NavigationIcon name="gateway" /><span>게이트웨이 상태</span></NavLink>
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
