/**
 * APT Simulator — Control Bar Component
 * 
 * Top control bar with scenario controls, detection toggle,
 * and system status indicators.
 */

import { useState, useEffect } from 'react';
import useSimulationStore from '../store/simulationStore';
import useActiveState from '../hooks/useActiveState';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8003';

export default function ControlBar() {
  const {
    connected, isRunning, detectionEnabled,
    riskScore, setDetectionEnabled, setRunning, reset,
    selectedScenario, setSelectedScenario,
  } = useSimulationStore();
  
  const { simulationState } = useActiveState();

  const [loading, setLoading] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('app-theme') || 'current');

  // Fallback metadata for offline Demo Mode
  const fallbackMetadata = {
    'credential_intrusion': {
      name: 'Credential Intrusion (Default)',
      description: 'An external attacker steals employee credentials to gain initial access, move laterally, and eventually disrupt the power grid.',
    },
    'insider_threat': {
      name: 'Insider Threat',
      description: 'A rogue employee with physical access tampers with a substation and establishes a C2 beacon for remote sabotage.',
    },
    'slow_burn_apt': {
      name: 'Slow-Burn APT',
      description: 'A highly sophisticated nation-state actor quietly persists in the network for months before launching a coordinated grid shutdown.',
    },
    'false_positive': {
      name: 'False Positive (Normal Ops)',
      description: 'Simulates completely normal administrative activity to test if the detection engine incorrectly flags legitimate operations.',
    }
  };

  // Fetch scenario metadata whenever it changes
  useEffect(() => {
    if (!selectedScenario) return;
    
    // Try to fetch from backend, but fallback to local data if disconnected (e.g. on Vercel)
    fetch(`${API_BASE}/api/scenario/${selectedScenario}`)
      .then(res => res.json())
      .then(data => {
        useSimulationStore.setState({ scenarioMetadata: data });
      })
      .catch(e => {
        console.warn("Backend disconnected, using offline scenario metadata.");
        useSimulationStore.setState({ 
          scenarioMetadata: fallbackMetadata[selectedScenario] 
        });
      });
  }, [selectedScenario]);

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
        body: JSON.stringify({ detection_enabled: detectionEnabled, scenario: `scenarios/${selectedScenario}.yaml` }),
      });
      if (resp.ok) setRunning(true);
    } catch (e) {
      console.error('Failed to start:', e);
    }
    setLoading(false);
  };

  const resetSimulation = async () => {
    // Always reset local state immediately so the UI works offline
    reset();
    if (connected) {
      try {
        await fetch(`${API_BASE}/api/simulation/reset`, { method: 'POST' });
      } catch (e) {
        console.error('Failed to reset backend:', e);
      }
    }
  };

  const toggleDetection = async () => {
    const newVal = !detectionEnabled;
    // Optimistically update UI so the toggle works in Vercel/Demo mode
    setDetectionEnabled(newVal);
    
    if (connected) {
      try {
        await fetch(`${API_BASE}/api/detection/toggle`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: newVal }),
        });
      } catch (e) {
        console.error('Toggle failed:', e);
      }
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
               simulationState === 'normal_ops' ? <span className="bg-slate-500/20 text-slate-300 px-2 py-0.5 rounded font-bold">✅ Normal Activity — No Threat Detected</span> :
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
        <select
          value={selectedScenario}
          onChange={(e) => {
            setSelectedScenario(e.target.value);
            resetSimulation();
          }}
          disabled={loading || isRunning}
          className="bg-[var(--color-bg-hover)] border border-[var(--color-border)] text-[var(--color-text-dim)] text-xs rounded-lg px-2 py-1.5 focus:outline-none focus:border-blue-500"
        >
          <option value="credential_intrusion">Credential Intrusion (Default)</option>
          <option value="insider_threat">Insider Threat</option>
          <option value="slow_burn_apt">Slow-Burn APT</option>
          <option value="false_positive">False Positive (Normal Ops)</option>
        </select>

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
          disabled={isRunning}
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
