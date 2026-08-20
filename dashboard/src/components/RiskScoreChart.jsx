/**
 * APT Simulator — Risk Score Chart
 * 
 * Line chart showing risk score over time with threshold lines.
 * Features a custom tooltip that acts as a timeline scrubber.
 */

import { useMemo, useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, ReferenceLine, ResponsiveContainer, Tooltip } from 'recharts';
import useSimulationStore from '../store/simulationStore';

const CustomTooltip = ({ active, payload, label, alerts }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    // Find alerts around this time
    const timeThreshold = 2000; // 2 seconds
    const relevantAlerts = alerts.filter(a => Math.abs(new Date(a.timestamp).getTime() - data.rawTime) < timeThreshold);

    return (
      <div className="bg-[var(--color-bg-card)] border border-[var(--color-border)] p-2 rounded-lg shadow-xl" style={{ minWidth: '150px' }}>
        <p className="text-[10px] text-[var(--color-text-muted)] font-mono mb-1">
          {new Date(data.rawTime).toLocaleTimeString()}
        </p>
        <p className="text-sm font-bold" style={{ color: payload[0].color }}>
          Risk Score: {data.score}
        </p>
        {relevantAlerts.length > 0 && (
          <div className="mt-2 pt-2 border-t border-[var(--color-border-dim)] space-y-1">
            {relevantAlerts.map((a, i) => (
              <div key={i} className="text-[9px] text-[var(--color-text-dim)]">
                <span className={a.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}>
                  ⚠️ {a.title}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }
  return null;
};

export default function RiskScoreChart() {
  const { 
    riskHistory, alerts,
    isScrubbing, setScrubbing, scrubIndex, setScrubIndex 
  } = useSimulationStore();
  
  const [theme, setTheme] = useState(() => localStorage.getItem('app-theme') || 'current');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('app-theme', theme);
  }, [theme]);

  const chartData = useMemo(() => {
    return riskHistory.map((point, i) => ({
      time: i,
      rawTime: point.time,
      score: Math.round(point.score * 10) / 10,
    }));
  }, [riskHistory]);

  const lastScore = chartData.length > 0 ? chartData[chartData.length - 1].score : 0;
  const strokeColor = lastScore > 85 ? 'var(--color-danger)' : lastScore > 65 ? 'var(--color-warning)' : lastScore > 30 ? 'var(--color-accent)' : 'var(--color-safe)';
  const pulseClass = lastScore > 85 ? 'animate-[pulse_2s_ease-in-out_infinite] shadow-[0_0_20px_rgba(239,68,68,0.3)] border-red-500/50' : 
                     lastScore > 65 ? 'animate-[pulse_2s_ease-in-out_infinite] shadow-[0_0_20px_rgba(249,115,22,0.3)] border-orange-500/50' : '';

  return (
    <div className={`glass-panel p-4 h-full flex flex-col transition-all duration-500 ${pulseClass}`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-sm">📊</span>
          <h2 className="text-xs font-bold text-[var(--color-text)] uppercase tracking-wider">
            Risk Score Timeline
          </h2>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-[var(--color-text-muted)]">
            {chartData.length} data points
          </span>
          <select 
            value={theme} 
            onChange={(e) => setTheme(e.target.value)}
            className="bg-[var(--color-bg-hover)] text-[var(--color-text-dim)] border border-[var(--color-border)] rounded-md text-xs py-1 px-2 outline-none cursor-pointer"
          >
            <option value="current">Current</option>
            <option value="day">Day</option>
            <option value="night">Night</option>
          </select>
        </div>
      </div>

      <div className="flex-1 min-h-0 relative">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={strokeColor} stopOpacity={0.3} />
                <stop offset="95%" stopColor={strokeColor} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" hide />
            <YAxis domain={[0, 100]} tick={{ fill: 'var(--color-text-muted)', fontSize: 9 }}
              tickLine={false} axisLine={false} />
            <Tooltip content={<CustomTooltip alerts={alerts} />} cursor={{ stroke: 'var(--color-border)', strokeWidth: 1, strokeDasharray: '4 4' }} />
            <ReferenceLine y={65} stroke="var(--color-warning)" strokeDasharray="4 3" strokeWidth={1}
              label={{ value: 'Alert (65)', fill: 'var(--color-warning)', fontSize: 9, position: 'right' }} />
            <ReferenceLine y={75} stroke="var(--color-danger)" strokeDasharray="4 3" strokeWidth={1}
              label={{ value: 'Block (75)', fill: 'var(--color-danger)', fontSize: 9, position: 'right' }} />
            <Area type="monotone" dataKey="score" stroke={strokeColor} strokeWidth={2}
              fill="url(#riskGradient)" dot={false} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Timeline Scrubber */}
      {riskHistory.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--color-border-dim)] flex items-center gap-3">
          <button 
            onClick={() => {
              if (isScrubbing) {
                setScrubbing(false);
              }
            }}
            className={`px-3 py-1 text-[10px] font-bold rounded uppercase tracking-wider transition-colors ${
              !isScrubbing 
                ? 'bg-blue-500/20 text-blue-400 border border-blue-500/50' 
                : 'bg-[var(--color-bg-hover)] text-[var(--color-text-dim)] border border-[var(--color-border)] hover:bg-[var(--color-bg-card)]'
            }`}
          >
            Live
          </button>
          
          <div className="flex-1 flex items-center gap-2">
            <input 
              type="range" 
              min={0} 
              max={Math.max(0, riskHistory.length - 1)} 
              value={isScrubbing ? scrubIndex : riskHistory.length - 1}
              onChange={(e) => {
                if (!isScrubbing) setScrubbing(true);
                setScrubIndex(Number(e.target.value));
              }}
              className="flex-1 h-1.5 bg-[var(--color-bg-hover)] rounded-full appearance-none outline-none cursor-ew-resize accent-[var(--color-accent)]"
            />
          </div>
          
          <div className="w-16 text-right">
            <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
              {isScrubbing && riskHistory[scrubIndex] 
                ? new Date(riskHistory[scrubIndex].time).toLocaleTimeString([], { hour12: false })
                : new Date(riskHistory[riskHistory.length - 1].time).toLocaleTimeString([], { hour12: false })
              }
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
