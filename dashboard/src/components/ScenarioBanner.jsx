import React from 'react';
import useSimulationStore from '../store/simulationStore';
import { scenarios } from '../config/scenarios';

export default function ScenarioBanner() {
  const { selectedScenario } = useSimulationStore();
  const scenario = scenarios[selectedScenario];

  if (!scenario) return null;

  return (
    <div className="glass-panel p-4 mb-2 border-l-4 border-l-[var(--color-accent)]" style={{ borderRadius: '8px' }}>
      <div className="flex items-center gap-2 mb-1">
        <h2 className="text-sm font-bold text-[var(--color-text)] tracking-wide">{scenario.name}</h2>
        <span className="text-xs text-[var(--color-text-dim)] px-2 py-0.5 rounded bg-[var(--color-bg-hover)]">
          {scenario.description}
        </span>
      </div>
      <p className="text-sm text-[var(--color-text-muted)] italic leading-relaxed">
        {scenario.narrative}
      </p>
    </div>
  );
}
