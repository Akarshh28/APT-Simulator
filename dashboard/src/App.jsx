/**
 * APT Simulator — Main Application Layout
 * 
 * Full-screen dark SOC dashboard with:
 * - Top: Control bar
 * - Left: Attacker kill-chain panel
 * - Center: City grid map + risk timeline
 * - Right: SOC/Defender panel
 * - Bottom-right: Network graph
 */

import { useEffect } from 'react';
import useWebSocket from './hooks/useWebSocket';
import ControlBar from './components/ControlBar';
import AttackerPanel from './components/AttackerPanel';
import DefenderPanel from './components/DefenderPanel';
import CityGridMap from './components/CityGridMap';
import RiskScoreChart from './components/RiskScoreChart';
import NetworkGraph from './components/NetworkGraph';

export default function App() {
  // Initialize WebSocket connections
  useWebSocket();

  return (
    <div className="w-full h-full flex flex-col bg-[var(--color-bg-primary)]">
      {/* Top Control Bar */}
      <ControlBar />

      {/* Main Content */}
      <div className="flex-1 flex gap-2 p-2 pt-1 min-h-0">
        {/* Left Column: Attacker Panel */}
        <div className="w-[260px] shrink-0">
          <AttackerPanel />
        </div>

        {/* Center Column: Map + Timeline */}
        <div className="flex-1 flex flex-col gap-2 min-w-0">
          {/* City Grid Map — visual centerpiece */}
          <div className="flex-1 min-h-0">
            <CityGridMap />
          </div>

          {/* Risk Score Timeline */}
          <div className="h-[160px] shrink-0">
            <RiskScoreChart />
          </div>
        </div>

        {/* Right Column: Defender Panel + Network Graph */}
        <div className="w-[280px] shrink-0 flex flex-col gap-2">
          <div className="flex-1 min-h-0">
            <DefenderPanel />
          </div>
          <div className="h-[220px] shrink-0">
            <NetworkGraph />
          </div>
        </div>
      </div>
    </div>
  );
}
