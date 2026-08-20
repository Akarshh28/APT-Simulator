/**
 * APT Simulator — Defender (SOC) Panel
 * 
 * Shows the SOC analyst view: risk gauge, alert feed, signal breakdown.
 */

import { useMemo } from 'react';
import useActiveState from '../hooks/useActiveState';

const SIGNAL_DESCRIPTIONS = {
  'isolation forest': "Flags statistical outliers in login timing, command frequency, and data volume compared to the baseline profile.",
  'graph anomaly': "Detects new or unusual connections between accounts and systems that don't exist in the normal access graph — e.g. an operator account directly accessing MDMS.",
  'beacon detection': "Identifies periodic, low-volume 'check-in' traffic patterns typical of C2 beaconing, distinct from normal telemetry polling intervals.",
  'login anomaly': "Flags logins at unusual times, from unusual sources, or with unusual frequency compared to the operator's baseline.",
  'mass command': "Detects an abnormal spike in the volume of remote commands (e.g. disconnect) issued in a short time window.",
};

const getSeverityStyles = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return { border: 'border-red-500/50', bg: 'bg-red-500/10', text: 'text-red-400' };
    case 'high':
      return { border: 'border-orange-500/50', bg: 'bg-orange-500/10', text: 'text-orange-400' };
    default:
      return { border: 'border-yellow-500/30', bg: 'bg-yellow-500/5', text: 'text-yellow-400' };
  }
};

export default function DefenderPanel() {
  const { riskScore, signals, alerts, hasAlerted, hasBlocked, detectionEnabled } = useActiveState();

  // SVG gauge parameters
  const gaugeRadius = 54;
  const gaugeStroke = 8;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius;
  const gaugeProgress = (riskScore / 100) * gaugeCircumference;

  const gaugeColor = riskScore > 85 ? 'var(--color-danger)' :
                     riskScore > 65 ? 'var(--color-orange-500)' :
                     riskScore > 30 ? 'var(--color-warning)' :
                     'var(--color-safe)';

  const signalEntries = useMemo(() =>
    Object.entries(signals || {}).map(([name, value]) => ({
      name: name.replace(/_/g, ' '),
      value: Math.round(value),
      color: value > 75 ? 'var(--color-danger)' : value > 40 ? 'var(--color-warning)' : value > 20 ? 'var(--color-warning)' : 'var(--color-safe)',
    })).sort((a, b) => b.value - a.value),
  [signals]);

  const pulseClass = riskScore > 85 ? 'animate-[pulse_2s_ease-in-out_infinite] shadow-[0_0_20px_rgba(239,68,68,0.3)] border-red-500/50' : 
                     riskScore > 65 ? 'animate-[pulse_2s_ease-in-out_infinite] shadow-[0_0_20px_rgba(249,115,22,0.3)] border-orange-500/50' : '';

  return (
    <div className={`glass-panel p-4 h-full flex flex-col relative transition-all duration-500 ${pulseClass}`}>
      <div className="flex items-center gap-2 mb-4 shrink-0">
        <span className="text-lg">🛡️</span>
        <h2 className="text-sm font-bold text-[var(--color-accent)] uppercase tracking-wider">
          SOC / Defender
        </h2>
        {!detectionEnabled && (
          <span className="text-[10px] bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full font-bold ml-auto">
            DETECTION OFF
          </span>
        )}
      </div>

      {/* Risk Gauge */}
      <div className="flex justify-center mb-4">
        <div className="relative">
          <svg width="130" height="130" viewBox="0 0 130 130">
            {/* Background ring */}
            <circle cx="65" cy="65" r={gaugeRadius} fill="none"
              stroke="var(--color-bg-hover)" strokeWidth={gaugeStroke}
              strokeLinecap="round" transform="rotate(-90 65 65)" />
            {/* Progress ring */}
            <circle cx="65" cy="65" r={gaugeRadius} fill="none"
              stroke={gaugeColor} strokeWidth={gaugeStroke}
              strokeLinecap="round" transform="rotate(-90 65 65)"
              strokeDasharray={gaugeCircumference}
              strokeDashoffset={gaugeCircumference - gaugeProgress}
              className="risk-gauge-ring transition-all duration-1000"
              style={{ filter: `drop-shadow(0 0 6px ${gaugeColor})` }} />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-bold transition-colors duration-1000" style={{ color: gaugeColor }}>
              {Math.round(riskScore)}
            </span>
            <span className="text-[10px] text-[var(--color-text-muted)] uppercase">Risk Score</span>
          </div>
        </div>
      </div>

      {/* Status badges */}
      <div className="flex justify-center gap-2 mb-4 h-6">
        {hasBlocked ? (
          <span className="text-[10px] bg-red-500/20 text-red-400 px-3 py-1 rounded-full font-bold animate-pulse shadow-[0_0_10px_rgba(239,68,68,0.3)]">
            🛡️ ATTACK BLOCKED
          </span>
        ) : hasAlerted ? (
          <span className="text-[10px] bg-orange-500/20 text-orange-400 px-3 py-1 rounded-full font-bold animate-pulse shadow-[0_0_10px_rgba(249,115,22,0.3)]">
            ⚠️ ALERT TRIGGERED
          </span>
        ) : null}
      </div>

      {/* Signal Breakdown */}
      <div className="mb-4">
        <h3 className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider mb-2 font-semibold">
          Signal Breakdown
        </h3>
        <div className="space-y-1.5">
          {signalEntries.map((signal) => (
            <div key={signal.name} className="flex items-center gap-2 group relative cursor-help">
              <div className="absolute right-full top-1/2 -translate-y-1/2 mr-3 w-48 p-2 bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-md shadow-xl opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50">
                <p className="text-[10px] text-[var(--color-text-dim)] font-medium leading-relaxed normal-case">
                  {SIGNAL_DESCRIPTIONS[signal.name] || 'Detection signal strength'}
                </p>
                {/* Tooltip Arrow */}
                <div className="absolute right-[-5px] top-1/2 -translate-y-1/2 border-[5px] border-transparent border-l-[var(--color-border)]" />
                <div className="absolute right-[-4px] top-1/2 -translate-y-1/2 border-[5px] border-transparent border-l-[var(--color-bg-card)]" />
              </div>
              <span className="text-[10px] text-[var(--color-text-dim)] w-24 truncate capitalize group-hover:text-[var(--color-text)] transition-colors">
                {signal.name}
              </span>
              <div className="flex-1 h-1.5 bg-[var(--color-bg-hover)] rounded-full overflow-hidden">
                <div className="h-full rounded-full transition-all duration-1000"
                  style={{ width: `${signal.value}%`, backgroundColor: signal.color }} />
              </div>
              <span className="text-[10px] font-mono w-6 text-right transition-colors duration-1000" style={{ color: signal.color }}>
                {signal.value}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Alert Feed */}
      <div className="flex-1 overflow-hidden flex flex-col">
        <h3 className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider mb-2 font-semibold">
          Alerts ({alerts.length})
        </h3>
        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {alerts.length === 0 ? (
            <p className="text-[10px] text-[var(--color-text-muted)] text-center py-4">
              No alerts — {detectionEnabled ? 'monitoring...' : 'detection disabled'}
            </p>
          ) : (
            alerts.slice().reverse().map((alert, i) => {
              const styles = getSeverityStyles(alert.severity);
              return (
                <div key={alert.id || i}
                  className={`p-2 rounded-lg border text-[10px] transition-all duration-300 ${styles.border} ${styles.bg}`}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className={`font-bold uppercase ${styles.text}`}>
                        {alert.severity}
                      </span>
                      {alert.technique_id && (
                        <span className="font-mono text-[var(--color-accent)] bg-blue-500/10 px-1 py-0.5 rounded">
                          {alert.technique_id}
                        </span>
                      )}
                    </div>
                    {alert.timestamp && (
                      <span className="font-mono text-[8px] text-[var(--color-text-muted)]">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    )}
                  </div>
                  <p className="text-[var(--color-text-dim)] leading-relaxed">{alert.title}</p>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
