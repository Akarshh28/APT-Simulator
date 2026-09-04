/**
 * APT Simulator — Attacker Panel Component
 * 
 * Shows the MITRE ATT&CK kill-chain stages as a vertical timeline.
 * Each stage shows its status (pending/active/complete/prevented) and technique ID.
 */

import { ATTACK_STAGES } from '../store/simulationStore';
import useActiveState from '../hooks/useActiveState';
import useSimulationStore from '../store/simulationStore';
import { scenarios } from '../config/scenarios';

export default function AttackerPanel() {
  const { stageStatuses, attackEvents, hasBlocked } = useActiveState();
  const selectedScenario = useSimulationStore(s => s.selectedScenario);
  const simulationState = useSimulationStore(s => s.simulationState);
  const scenarioMetadata = useSimulationStore(s => s.scenarioMetadata);
  const scenario = scenarios[selectedScenario];
  const storeActiveStages = useSimulationStore(s => s.activeStages);
  const activeStages = storeActiveStages || scenario?.stages?.map(id => ATTACK_STAGES.find(st => st.id === id)).filter(Boolean); // Handle both

  const getStageStatus = (stageId) => {
    let status = stageStatuses[stageId] || 'pending';
    if (hasBlocked && stageId === 'impact') {
      status = 'prevented';
    }
    return status;
  };

  const getStageClass = (status) => {
    const base = 'backdrop-blur-md transition-all duration-500';
    if (status === 'prevented') return `${base} border-teal-500/50 bg-teal-500/10 shadow-[0_4px_20px_rgba(20,184,166,0.15)]`;
    if (status === 'active') return `${base} border-[var(--color-accent)] bg-[var(--color-accent)]/10 shadow-[0_4px_20px_rgba(59,130,246,0.15)]`;
    if (status === 'retrying') return `${base} border-orange-500/50 bg-orange-500/10 shadow-[0_4px_20px_rgba(249,115,22,0.15)]`;
    if (status === 'complete') return `${base} border-[var(--color-border)] bg-[var(--color-bg-card)] shadow-[0_4px_15px_rgba(0,0,0,0.05)]`;
    if (status === 'blocked') return `${base} border-red-500/80 bg-red-500/20 shadow-[0_4px_20px_rgba(239,68,68,0.2)]`;
    if (status === 'error') return `${base} border-red-500/50 bg-red-500/10`;
    if (status === 'halted') return `${base} border-orange-500/30 bg-orange-500/5 opacity-80`;
    return `${base} border-transparent bg-transparent opacity-50 hover:bg-[var(--color-bg-hover)]`;
  };

  const getStatusDot = (status) => {
    if (status === 'prevented') return 'bg-teal-500';
    if (status === 'active') return 'bg-[var(--color-accent)] animate-pulse';
    if (status === 'retrying') return 'bg-orange-500 animate-pulse';
    if (status === 'complete') return 'bg-[var(--color-safe)]';
    if (status === 'blocked') return 'bg-red-500';
    if (status === 'error') return 'bg-[var(--color-danger)]';
    if (status === 'halted') return 'bg-orange-500';
    return 'bg-[var(--color-text-muted)]';
  };

  // Special UI: False Positive (Activity Log)
  if (selectedScenario === 'false_positive') {
    return (
      <div className="glass-panel p-4 h-full flex flex-col">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-lg">🗡️</span>
          <h2 className="text-sm font-bold text-[var(--color-danger)] uppercase tracking-wider">
            Attacker Kill-Chain
          </h2>
        </div>
        
        <div className="mb-4 p-3 border border-blue-500/30 bg-blue-500/10 rounded-lg shrink-0">
           <div className="text-xs font-semibold text-blue-300 flex items-center gap-2">
             <span className="text-xs">ℹ️</span>
             No Attacker Stages
           </div>
           <div className="text-[10px] text-blue-200/70 mt-1">
             This scenario represents normal operations with benign anomalies. Therefore, no attacker kill-chain is executed.
           </div>
        </div>
        <div className="flex-1 overflow-y-auto space-y-3">
          {attackEvents.map((ev, i) => (
            <div key={i} className="border border-blue-500/20 bg-blue-500/5 rounded-lg p-3">
              <div className="text-[var(--color-text-muted)] mb-1 font-mono text-[9px]">
                {new Date(ev.timestamp).toLocaleTimeString()}
              </div>
              <div className="text-[var(--color-text-dim)] text-[10px] leading-tight">
                {ev.action}
              </div>
            </div>
          ))}
          {simulationState === 'normal_ops' && (
            <div className="mt-4 p-3 border border-[var(--color-border)] bg-[var(--color-bg-card)] rounded-lg text-center shadow-[0_0_15px_rgba(100,116,139,0.2)]">
               <span className="text-xs font-bold text-blue-300 uppercase tracking-wider">
                 Normal Activity — No Threat Detected
               </span>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Normal Kill-Chain UI
  const stageEvents = {};
  attackEvents.forEach((ev) => {
    stageEvents[ev.stage] = ev;
  });

  return (
    <div className="glass-panel p-4 h-full flex flex-col">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-lg">🗡️</span>
        <h2 className="text-sm font-bold text-[var(--color-danger)] uppercase tracking-wider">
          Attacker Kill-Chain
        </h2>
      </div>



      <div className="flex-1 overflow-y-auto space-y-2">
        {selectedScenario === 'insider_threat' && (
           <div className="relative mb-2">
             <div className="border border-[var(--color-border)] bg-[var(--color-bg-card)] opacity-60 rounded-lg p-3 flex items-center gap-3">
                <div className="w-[10px] h-[10px] rounded-full shrink-0 bg-[var(--color-border-dim)]" />
                <div className="flex-1">
                   <div className="text-xs font-semibold text-[var(--color-text-muted)] flex items-center gap-2">
                     <span className="text-xs">ℹ️</span>
                     N/A — Attacker Already Has Access
                   </div>
                   <div className="text-[9px] text-[var(--color-text-muted)] mt-0.5">
                     Reconnaissance & Initial Access skipped.
                   </div>
                </div>
             </div>
             {/* connector to first actual stage */}
             <div className="absolute left-[17px] top-[48px] w-0.5 h-[16px] bg-[var(--color-border-dim)]" />
           </div>
        )}
        {activeStages.map((stage, idx) => {
          const status = getStageStatus(stage.id);
          const latestEvent = stageEvents[stage.id];
          const isLast = idx === activeStages.length - 1;

          return (
            <div key={stage.id} className="relative">
              {/* Connector line */}
              {idx < activeStages.length - 1 && (
                <div className={`absolute left-[17px] top-[36px] w-0.5 h-[calc(100%-8px)] transition-colors duration-500
                  ${status === 'complete' ? 'bg-[var(--color-safe)]' : 'bg-[var(--color-border-dim)]'}`} />
              )}

              <div className={`${getStageClass(status)} border rounded-lg p-3 transition-all duration-500`}>
                <div className="flex items-center gap-3">
                  {/* Status dot */}
                  <div className={`w-[10px] h-[10px] rounded-full shrink-0 ${getStatusDot(status)}`}
                       style={status === 'active' ? { boxShadow: '0 0 8px var(--color-accent-glow)' } : {}} />

                  {/* Stage info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="w-4 flex justify-center shrink-0">
                        <span className="text-xs">{stage.icon}</span>
                      </div>
                      <span className={`text-xs font-semibold ${status === 'active' || status === 'complete' ? 'text-[var(--color-text)]' : 'text-[var(--color-text-dim)]'}`}>
                        {stage.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[9px] font-mono font-bold text-[var(--color-accent)] bg-[var(--color-accent)]/10 px-1.5 py-0.5 rounded border border-[var(--color-accent)]/20 shadow-sm">
                        {stage.technique}
                      </span>
                      <span className="text-[10px] text-[var(--color-text-muted)] font-medium tracking-wide">{stage.tactic}</span>
                    </div>
                    {stage.description && (
                      <div className="mt-1 text-[9px] text-slate-400 leading-tight">
                        {stage.description}
                      </div>
                    )}
                  </div>

                  {/* Status label */}
                  <span className={`text-[10px] font-bold uppercase tracking-wider ${
                    status === 'prevented' ? 'text-teal-400 animate-pulse' :
                    status === 'active' ? 'text-[var(--color-accent)]' :
                    status === 'retrying' ? 'text-orange-500 animate-pulse' :
                    status === 'complete' ? 'text-[var(--color-safe)]' :
                    status === 'blocked' ? 'text-red-500 font-extrabold' :
                    status === 'error' ? 'text-[var(--color-danger)]' :
                    status === 'halted' ? 'text-orange-500' :
                    'text-[var(--color-text-muted)]'
                  }`}>
                    {status === 'blocked' ? 'BLOCKED BY DETECTION' : status}
                  </span>
                </div>

                {/* Latest event detail Content */}
                <div className="mt-3 pl-[22px] min-h-[28px]">
                  {latestEvent && status !== 'pending' && (
                    <div className="bg-[var(--color-bg-primary)]/50 p-2.5 rounded-lg border border-[var(--color-border-dim)] backdrop-blur-sm">
                      <div className="text-[var(--color-text-muted)] mb-1 font-mono text-[8px] tracking-wider uppercase">
                        {new Date(latestEvent.timestamp).toLocaleTimeString()}
                      </div>
                      <div className="killchain-card-desc whitespace-normal break-words leading-relaxed text-[var(--color-text)] font-medium" title={latestEvent.action}>
                        {latestEvent.action}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Event count */}
      <div className="mt-3 pt-3 border-t border-[var(--color-border-dim)] text-center">
        <span className="text-[10px] text-[var(--color-text-muted)]">
          {attackEvents.length} events logged
        </span>
      </div>
    </div>
  );
}
