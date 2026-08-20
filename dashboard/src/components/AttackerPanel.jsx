/**
 * APT Simulator — Attacker Panel Component
 * 
 * Shows the MITRE ATT&CK kill-chain stages as a vertical timeline.
 * Each stage shows its status (pending/active/complete/prevented) and technique ID.
 */

import { ATTACK_STAGES } from '../store/simulationStore';
import useActiveState from '../hooks/useActiveState';

export default function AttackerPanel() {
  const { stageStatuses, attackEvents, hasBlocked } = useActiveState();

  const getStageStatus = (stageId) => {
    let status = stageStatuses[stageId] || 'pending';
    if (hasBlocked && stageId === 'impact') {
      status = 'prevented';
    }
    return status;
  };

  const getStageClass = (status) => {
    if (status === 'prevented') return 'border-green-500/50 bg-green-500/10 shadow-[0_0_15px_rgba(34,197,94,0.2)]';
    if (status === 'active') return 'border-blue-500/50 bg-blue-500/10 shadow-[0_0_15px_rgba(59,130,246,0.2)]';
    if (status === 'retrying') return 'border-orange-500/50 bg-orange-500/10 shadow-[0_0_15px_rgba(249,115,22,0.2)]';
    if (status === 'complete') return 'border-[var(--color-border)] bg-[var(--color-bg-hover)]';
    if (status === 'blocked') return 'border-red-500/80 bg-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.3)]';
    if (status === 'error') return 'border-red-500/50 bg-red-500/10';
    if (status === 'halted') return 'border-orange-500/30 bg-orange-500/5 opacity-80';
    return 'border-transparent bg-transparent opacity-60';
  };

  const getStatusDot = (status) => {
    if (status === 'prevented') return 'bg-[var(--color-safe)]';
    if (status === 'active') return 'bg-[var(--color-accent)] animate-pulse';
    if (status === 'retrying') return 'bg-orange-500 animate-pulse';
    if (status === 'complete') return 'bg-[var(--color-safe)]';
    if (status === 'blocked') return 'bg-red-500';
    if (status === 'error') return 'bg-[var(--color-danger)]';
    if (status === 'halted') return 'bg-orange-500';
    return 'bg-[var(--color-text-muted)]';
  };

  // Get the latest event for each stage
  const stageEvents = {};
  attackEvents.forEach((ev) => {
    stageEvents[ev.stage] = ev;
  });

  return (
    <div className="glass-panel p-4 h-full flex flex-col">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-lg">🗡️</span>
        <h2 className="text-sm font-bold text-[var(--color-danger)] uppercase tracking-wider">
          Attacker Kill-Chain
        </h2>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2">
        {ATTACK_STAGES.map((stage, idx) => {
          const status = getStageStatus(stage.id);
          const latestEvent = stageEvents[stage.id];

          return (
            <div key={stage.id} className="relative">
              {/* Connector line */}
              {idx < ATTACK_STAGES.length - 1 && (
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
                      <span className={`text-xs font-semibold ${status === 'active' || status === 'complete' ? 'text-white' : 'text-slate-300'}`}>
                        {stage.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] font-mono text-slate-400 bg-[var(--color-bg-primary)] px-1.5 py-0.5 rounded border border-[var(--color-border)]">
                        {stage.technique}
                      </span>
                      <span className="text-[10px] text-slate-400 font-medium">{stage.tactic}</span>
                    </div>
                  </div>

                  {/* Status label */}
                  <span className={`text-[10px] font-bold uppercase tracking-wider ${
                    status === 'prevented' ? 'text-[var(--color-safe)] animate-pulse' :
                    status === 'active' ? 'text-[var(--color-accent)]' :
                    status === 'retrying' ? 'text-orange-500 animate-pulse' :
                    status === 'complete' ? 'text-[var(--color-safe)]' :
                    status === 'blocked' ? 'text-red-500 font-extrabold' :
                    status === 'error' ? 'text-[var(--color-danger)]' :
                    status === 'halted' ? 'text-orange-500' :
                    'text-slate-500'
                  }`}>
                    {status === 'blocked' ? 'BLOCKED BY DETECTION' : status}
                  </span>
                </div>

                {/* Latest event detail Placeholder / Content */}
                <div className="mt-2 text-[10px] pl-[22px] min-h-[28px]">
                  {latestEvent && status !== 'pending' && (
                    <>
                      <div className="text-[var(--color-text-muted)] mb-0.5 font-mono text-[9px]">
                        {new Date(latestEvent.timestamp).toLocaleTimeString()}
                      </div>
                      <div className="killchain-card-desc whitespace-normal break-words leading-tight text-slate-300" title={latestEvent.action}>
                        {latestEvent.action}
                      </div>
                    </>
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
