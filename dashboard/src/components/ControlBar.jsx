/**
 * APT Simulator — Control Bar Component
 * 
 * Top control bar with scenario controls, detection toggle,
 * and system status indicators.
 */

import { useState, useEffect } from 'react';
import useSimulationStore from '../store/simulationStore';
import useActiveState from '../hooks/useActiveState';

const API_BASE = 'http://localhost:8003';

export default function ControlBar() {
  const {
    connected, isRunning, detectionEnabled,
    riskScore, setDetectionEnabled, setRunning, reset,
  } = useSimulationStore();
  
  const { simulationState } = useActiveState();

  const [loading, setLoading] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('app-theme') || 'current');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('app-theme', theme);
  }, [theme]);

  const startSimulation = async () => {
    setLoading(true);
    try {
      reset();
      const resp = await fetch(`${API_BASE}/api/simulation/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ detection_enabled: detectionEnabled }),
      });
      if (resp.ok) setRunning(true);
    } catch (e) {
      console.error('Failed to start:', e);
    }
    setLoading(false);
  };

  const resetSimulation = async () => {
    try {
      await fetch(`${API_BASE}/api/simulation/reset`, { method: 'POST' });
    } catch (e) {
      console.error('Failed to reset backend:', e);
    } finally {
      // Always reset local state so the UI doesn't get stuck if the backend is down
      reset();
    }
  };

  const toggleDetection = async () => {
    const newVal = !detectionEnabled;
    try {
      await fetch(`${API_BASE}/api/detection/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newVal }),
      });
      setDetectionEnabled(newVal);
    } catch (e) {
      console.error('Toggle failed:', e);
    }
  };

  return (
    <div className="flex items-center justify-between px-6 py-3 glass-panel m-2 mb-0" style={{ borderRadius: '12px' }}>
      {/* Left: Title & Status */}
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center text-white font-bold text-sm shadow-lg">
            ⚡
          </div>
          <div>
            <h1 className="text-base font-extrabold text-white tracking-tight leading-none mb-1">APT Simulator</h1>
            <p className="text-xs text-[var(--color-text-dim)] leading-none">
              {simulationState === 'blocked' ? <span className="bg-green-500/20 text-green-400 px-2 py-0.5 rounded font-bold">🛡️ Attack Blocked</span> : 
               simulationState === 'failed' ? <span className="bg-orange-500/20 text-orange-400 px-2 py-0.5 rounded font-bold">❌ Attack Failed</span> : 
               simulationState === 'succeeded' ? <span className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded font-bold animate-pulse">🚨 Attack Successful</span> : 
               simulationState === 'running' ? <span className="text-blue-400 font-bold">⚡ Running...</span> : 
               'Smart Grid Security • C3iHub'}
            </p>
          </div>
        </div>

        <div className="h-6 w-px bg-[var(--color-border)]" />

        {/* Connection indicator */}
        <div className="flex items-center gap-1.5 text-xs">
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-[var(--color-safe)]' : 'bg-[var(--color-danger)]'}`}
               style={{ boxShadow: connected ? '0 0 6px var(--color-safe)' : '0 0 6px var(--color-danger)' }} />
          <span className="text-[var(--color-text-dim)]">{connected ? 'Connected' : 'Disconnected'}</span>
        </div>
      </div>

      {/* Center: Controls */}
      <div className="flex items-center gap-3">
        <button
          onClick={startSimulation}
          disabled={loading || isRunning || !connected}
          className="px-4 py-1.5 text-sm font-medium rounded-lg transition-all
                     bg-[var(--color-accent)] hover:bg-blue-500 text-white
                     disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {loading ? '...' : isRunning ? '● Running' : !connected ? '❌ Disconnected' : '▶ Start Attack'}
        </button>

        <button
          onClick={() => useSimulationStore.getState().triggerDemoMode()}
          disabled={isRunning || !connected}
          className="px-4 py-1.5 text-sm font-bold rounded-lg transition-all
                     bg-[var(--color-danger)] hover:bg-red-600 text-white shadow-[0_0_10px_rgba(239,68,68,0.5)]
                     disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
        >
          ⚡ Launch Full Attack (Demo)
        </button>

        <button
          onClick={resetSimulation}
          className="px-4 py-1.5 text-sm font-medium rounded-lg transition-all
                     bg-[var(--color-bg-hover)] hover:bg-[var(--color-border)] text-[var(--color-text-dim)]"
        >
          ↺ Reset
        </button>
      </div>

      {/* Right: Detection Toggle */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-[var(--color-text-dim)] uppercase tracking-wider">
            Detection
          </span>
          <div
            className={`toggle-track ${detectionEnabled ? 'on' : 'off'}`}
            onClick={toggleDetection}
            role="switch"
            aria-checked={detectionEnabled}
          >
            <div className="toggle-thumb" />
          </div>
          <span className={`text-xs font-bold ${detectionEnabled ? 'text-[var(--color-safe)]' : 'text-[var(--color-danger)]'}`}>
            {detectionEnabled ? 'ON' : 'OFF'}
          </span>
        </div>

        <div className="h-6 w-px bg-[var(--color-border)]" />

        {/* Risk badge */}
        <div className={`px-3 py-1 rounded-full text-xs font-bold ${
          riskScore > 85 ? 'bg-red-500/20 text-red-400' :
          riskScore > 65 ? 'bg-yellow-500/20 text-yellow-400' :
          riskScore > 30 ? 'bg-blue-500/20 text-blue-400' :
          'bg-green-500/20 text-green-400'
        }`}>
          Risk: {Math.round(riskScore)}
        </div>
      </div>
    </div>
  );
}
