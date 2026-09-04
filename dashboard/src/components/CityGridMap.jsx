/**
 * APT Simulator — City Grid Map (Redesigned with D3 Treemap)
 * 
 * Uses D3 treemap to fully utilize the panel space, scaling zones proportionally
 * to their meter counts. Includes rich hover states and tooltips.
 */

import { useMemo, useState, useEffect } from 'react';
import useActiveState from '../hooks/useActiveState';
import useSimulationStore from '../store/simulationStore';
import * as d3 from 'd3';

const ZONE_LABELS = {
  A: '🏠 Zone A — Res. North',
  B: '🏢 Zone B — Com. Center',
  C: '🏠 Zone C — Res. East',
  D: '🏭 Zone D — Ind. West',
  E: '🏠 Zone E — Res. South',
  F: '🏢 Zone F — Mixed East',
};

export default function CityGridMap() {
  const { meterStatuses, meterTelemetry, meterEvents, totalMeters, disconnectedCount, hasBlocked, stageStatuses, simulationState } = useActiveState();
  const scenarioMetadata = useSimulationStore(s => s.scenarioMetadata);
  const isAttackActive = simulationState !== 'idle';
  const [hoveredZone, setHoveredZone] = useState(null);
  const [hoveredMeter, setHoveredMeter] = useState(null);
  const [selectedMeter, setSelectedMeter] = useState(null);

  const totalConnected = useMemo(() => {
    const hasData = Object.keys(meterStatuses).length > 0;
    if (!hasData) return totalMeters;
    return Object.values(meterStatuses).reduce((sum, z) => sum + (z?.connected || 0), 0);
  }, [meterStatuses, totalMeters]);

  const totalDisconnected = useMemo(() => {
    return Object.values(meterStatuses).reduce((sum, z) => sum + (z?.disconnected || 0), 0);
  }, [meterStatuses]);

  // Ensure total consistency across all simulation states
  useEffect(() => {
    const total = totalConnected + totalDisconnected;
    if (total !== totalMeters) {
      console.warn(`[Data Consistency] Total meters sum (${total}) != ${totalMeters}. Online: ${totalConnected}, Offline: ${totalDisconnected}`);
    }

    Object.keys(ZONE_LABELS).forEach((zoneId, index) => {
      const stats = meterStatuses[zoneId];
      if (stats) {
        const expectedTotal = Math.floor(totalMeters / 6) + (index < (totalMeters % 6) ? 1 : 0);
        if (stats.total !== expectedTotal) {
          console.warn(`[Data Consistency] Zone ${zoneId} total (${stats.total}) != expected (${expectedTotal}).`);
        }
      }
    });
  }, [totalConnected, totalDisconnected, totalMeters, meterStatuses]);

  // Generate Fixed 3x2 Grid layout (paralleling center columns)
  const { leaves, mapWidth, mapHeight } = useMemo(() => {
    const width = 800;
    const height = 400;
    const paddingOuter = 8;
    const paddingInner = 10;
    
    const colWidth = (width - paddingOuter * 2 - paddingInner * 2) / 3;
    const hubLaneHeight = 84;
    const rowHeight = (height - paddingOuter * 2 - paddingInner - hubLaneHeight) / 2;

    const leaves = Object.keys(ZONE_LABELS).map((zoneId, index) => {
      const col = index % 3;
      const row = Math.floor(index / 3);
      
      const x0 = paddingOuter + col * (colWidth + paddingInner);
      const y0 = row === 0 ? paddingOuter : paddingOuter + rowHeight + paddingInner + hubLaneHeight;
      
      const fallbackCount = Math.floor(totalMeters / 6) + (index < (totalMeters % 6) ? 1 : 0);
      return {
        data: {
          id: zoneId,
          name: ZONE_LABELS[zoneId],
          value: meterStatuses[zoneId]?.total || fallbackCount
        },
        x0,
        y0,
        x1: x0 + colWidth,
        y1: y0 + rowHeight
      };
    });

    return { leaves, mapWidth: width, mapHeight: height };
  }, [meterStatuses]);

  // Generate meter dots inside each zone's bounding box
  const meterDots = useMemo(() => {
    const dots = [];
    
    leaves.forEach(leaf => {
      const zoneId = leaf.data.id;
      const count = leaf.data.value;
      const stats = meterStatuses[zoneId];
      const offlineCount = stats?.disconnected || 0;
      
      const w = leaf.x1 - leaf.x0;
      const h = leaf.y1 - leaf.y0;
      
      const ratio = w / h;
      const cols = Math.ceil(Math.sqrt(count * ratio));
      const rows = Math.ceil(count / cols);
      
      const padX = 16;
      const padY = 32; // Top padding for label
      
      const stepX = Math.max(1, (w - padX * 2) / Math.max(1, cols - 1));
      const stepY = Math.max(1, (h - padY - 12) / Math.max(1, rows - 1));
      
      // Calculate centering offsets if the grid doesn't fill the padding perfectly
      const actualW = stepX * (cols - 1);
      const actualH = stepY * (rows - 1);
      const offsetX = (w - actualW) / 2;
      const offsetY = padY + (h - padY - actualH) / 2;

      const subX = leaf.x1 - 16;
      const subY = leaf.y0 + 12;

      const zoneDots = [];
      for (let i = 0; i < count; i++) {
        const c = i % cols;
        const r = Math.floor(i / cols);
        
        const x = leaf.x0 + offsetX + c * stepX;
        const y = leaf.y0 + offsetY + r * stepY;
        const dist = Math.sqrt(Math.pow(x - subX, 2) + Math.pow(y - subY, 2));

        zoneDots.push({
          id: `${zoneId}-${i}`,
          displayId: `SM-${zoneId}-${String(i + 1).padStart(3, '0')}`,
          zone: zoneId,
          x, y, dist
        });
      }

      // Sort radially so the impact cascades outward from the substation
      zoneDots.sort((a, b) => a.dist - b.dist);
      zoneDots.forEach((dot, i) => {
        dot.isOffline = i < offlineCount;
        dots.push(dot);
      });
    });
    return dots;
  }, [leaves, meterStatuses]);

  const getZoneStatus = (zone) => {
    const stats = meterStatuses[zone];
    if (!stats) return 'connected';
    if (stats.disconnected > 0 && stats.disconnected >= stats.total) return 'disconnected';
    if (stats.disconnected > 0) return 'partial';
    return 'connected';
  };

  return (
    <div className="glass-panel p-4 h-full flex flex-col relative">
      {/* Header */}
      <div className="flex items-center justify-between mb-3 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-lg">🏙️</span>
          <h2 className="text-sm font-bold text-[var(--color-text)] uppercase tracking-wider">
            Smart Grid — City View
          </h2>
        </div>
        <div className="flex items-center gap-3 text-[10px]">
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-[var(--color-safe)] shadow-[0_0_8px_var(--color-safe-glow)]" />
            <span className="text-[var(--color-text-dim)] font-medium">Online: {totalConnected}</span>
          </div>
          <span className="text-[var(--color-text-muted)]">•</span>
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-[var(--color-danger)] shadow-[0_0_8px_var(--color-danger-glow)]" />
            <span className="text-[var(--color-text-dim)] font-medium">Offline: {totalDisconnected || 0}</span>
          </div>
        </div>
      </div>

      {/* Blocked Banner - Now a flex sibling so it pushes the map down without overlapping */}
      {hasBlocked && (
        <div className="flex justify-center mb-3 shrink-0 animate-in fade-in slide-in-from-top-2 duration-500">
          <div className="bg-[color-mix(in_srgb,var(--color-safe)_15%,transparent)] border border-[color-mix(in_srgb,var(--color-safe)_40%,transparent)] rounded-lg px-8 py-2.5 backdrop-blur-sm w-full max-w-lg text-center"
               style={{ boxShadow: '0 0 20px color-mix(in srgb, var(--color-safe) 20%, transparent)' }}>
            <span className="text-sm font-bold text-[var(--color-safe)] tracking-wider">
              🛡️ ATTACK BLOCKED — Grid Protected
            </span>
          </div>
        </div>
      )}

      {/* Map SVG Container */}
      <div className="flex-1 relative overflow-hidden rounded-lg bg-[var(--color-bg-primary)] border border-[var(--color-border-dim)] shadow-inner">
        <svg viewBox={`0 0 ${mapWidth} ${mapHeight}`} className="w-full h-full" preserveAspectRatio="none">
          <defs>
            <filter id="glow-red-map" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <pattern id="city-blocks" width="24" height="24" patternUnits="userSpaceOnUse">
              <path d="M 24 0 L 0 0 0 24" fill="none" stroke="var(--color-border)" strokeWidth="0.5" opacity="0.15" />
            </pattern>
            <marker id="arrow-red" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--color-danger)" />
            </marker>
            <marker id="arrow-blue" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--color-accent)" />
            </marker>
          </defs>

          {/* Persistent Feeder Lines (HES to Zones) */}
          <g className="feeder-paths pointer-events-none">
            {leaves.map(leaf => {
              const zoneDisconnected = meterStatuses[leaf.data.id]?.disconnected || 0;
              const impactStatus = stageStatuses['impact'];
              // Only show attack-styled lines for zones that actually suffered disconnects
              // during an active or completed Impact stage — not during blocked/halted
              const isUnderAttack = (impactStatus === 'active' || impactStatus === 'complete') && zoneDisconnected > 0;
              return (
                <path 
                  key={`feeder-${leaf.data.id}`}
                  d={`M 430 200 L ${leaf.x1 - 16} ${leaf.y0 + 12}`} 
                  fill="none" 
                  stroke={isUnderAttack ? "var(--color-danger)" : "var(--color-border-dim)"}
                  strokeWidth={isUnderAttack ? "3" : "1.5"}
                  strokeDasharray={isUnderAttack ? "10 10" : "none"}
                  className={isUnderAttack ? "animate-flow-dash" : ""}
                  markerEnd={isUnderAttack ? "url(#arrow-red)" : "none"}
                />
              );
            })}
          </g>

          {/* Central HES Hub and Attack Paths Layer */}
          <g className="attack-paths pointer-events-none">
            {/* Recon / Initial Access Path */}
            {(stageStatuses['reconnaissance'] === 'active' || stageStatuses['reconnaissance'] === 'complete' || stageStatuses['initial_access'] === 'active' || stageStatuses['initial_access'] === 'complete' || (scenarioMetadata?.graph_config?.origin !== 'external' && stageStatuses['persistence'] === 'active')) && (
              <path 
                d={
                  scenarioMetadata?.graph_config?.origin === 'MDMS' ? "M 370 200 L 430 200" :
                  ['A','B','C','D','E','F'].includes(scenarioMetadata?.graph_config?.origin) ?
                    `M ${leaves.find(l => l.data.id === scenarioMetadata.graph_config.origin)?.x1 - 16 || 60} ${leaves.find(l => l.data.id === scenarioMetadata.graph_config.origin)?.y0 + 12 || 340} L 430 200` :
                    "M 60 340 L 430 200"
                }
                fill="none" 
                stroke={stageStatuses['initial_access'] || stageStatuses['persistence'] ? "var(--color-danger)" : "var(--color-warning)"}
                strokeWidth={(stageStatuses['initial_access'] === 'active' || stageStatuses['persistence'] === 'active') ? "3" : "1.5"}
                strokeDasharray={(stageStatuses['initial_access'] === 'active' || stageStatuses['persistence'] === 'active') ? "6 6" : "4 4"}
                className="animate-flow-dash"
                markerEnd="url(#arrow-red)"
              />
            )}

            {/* Persistence / Lateral Movement Internal Activity */}
            {(stageStatuses['persistence'] === 'active' || stageStatuses['lateral_movement'] === 'active') && (
              <circle cx="430" cy="200" r="45" fill="none" stroke="var(--color-danger)" strokeWidth="1.5" strokeDasharray="4 8" className="animate-[spin_4s_linear_infinite]" opacity="0.6" />
            )}

            {/* Command & Control Path */}
            {(stageStatuses['command_control'] === 'active' || stageStatuses['command_control'] === 'complete') && (
              <path 
                d={
                  scenarioMetadata?.graph_config?.origin === 'MDMS' ? "M 370 200 L 60 340" :
                  ['A','B','C','D','E','F'].includes(scenarioMetadata?.graph_config?.origin) ?
                    `M 430 200 L ${leaves.find(l => l.data.id === scenarioMetadata.graph_config.origin)?.x1 - 16 || 200} ${leaves.find(l => l.data.id === scenarioMetadata.graph_config.origin)?.y0 + 12 || 300}` :
                    "M 430 200 L 60 340"
                }
                fill="none" stroke="var(--color-danger)" strokeWidth="2" strokeDasharray="2 4"
                className="animate-flow-dash-reverse" markerStart="url(#arrow-red)"
              />
            )}
          </g>


          {/* Zones */}
          {leaves.map(leaf => {
            const zoneId = leaf.data.id;
            const zoneStatus = getZoneStatus(zoneId);
            const isHovered = hoveredZone === zoneId;
            
            return (
              <g 
                key={zoneId} 
                onMouseEnter={() => setHoveredZone(zoneId)}
                onMouseLeave={() => setHoveredZone(null)}
                className="cursor-pointer transition-opacity duration-300"
              >
                {/* Zone Background & Pattern */}
                <rect
                  x={leaf.x0} y={leaf.y0} width={leaf.x1 - leaf.x0} height={leaf.y1 - leaf.y0}
                  fill="url(#city-blocks)"
                  rx="6"
                  opacity={isHovered ? 0.6 : 0.3}
                />
                
                {/* Zone Border */}
                <rect
                  x={leaf.x0} y={leaf.y0} width={leaf.x1 - leaf.x0} height={leaf.y1 - leaf.y0}
                  fill={isHovered ? 'var(--color-bg-hover)' : 'var(--color-bg-panel)'}
                  opacity={0.4}
                  rx="6"
                  stroke={zoneStatus === 'disconnected' ? 'var(--color-danger)' : zoneStatus === 'partial' ? 'var(--color-warning)' : 'var(--color-border)'}
                  strokeWidth={isHovered || zoneStatus !== 'connected' ? 2 : 1}
                  className={zoneStatus !== 'connected' ? 'transition-colors duration-1000' : ''}
                />

                {/* Zone Label Background */}
                <rect 
                  x={leaf.x0} y={leaf.y0} 
                  width={leaf.x1 - leaf.x0} height="24" 
                  fill="var(--color-bg-card)" opacity="0.8" rx="6"
                  style={{ borderBottomLeftRadius: 0, borderBottomRightRadius: 0 }}
                />

                {/* Zone Text with CSS Truncation */}
                <foreignObject x={leaf.x0 + 10} y={leaf.y0} width={leaf.x1 - leaf.x0 - 45} height="24">
                  <div className="zone-header-title h-full text-[var(--color-text)]">
                    {leaf.data.name}
                  </div>
                </foreignObject>
                
                {/* Substation Icon */}
                <circle 
                  cx={leaf.x1 - 16} cy={leaf.y0 + 12} r="6"
                  fill={zoneStatus === 'disconnected' ? 'var(--color-danger)' : 'var(--color-accent)'}
                  opacity={zoneStatus === 'disconnected' ? 0.9 : 0.6}
                  className={zoneStatus === 'disconnected' ? 'animate-pulse' : ''}
                />
                <text x={leaf.x1 - 18.5} y={leaf.y0 + 14.5} fill="white" fontSize="7" fontWeight="bold">⚡</text>
              </g>
            );
          })}

          {/* Meter Dots */}
          {meterDots.map((dot) => {
            const isHovered = hoveredMeter?.id === dot.id;
            const r = isHovered ? 3 : dot.isOffline ? 2.5 : 2;
            
            return (
              <circle
                key={dot.id}
                cx={dot.x}
                cy={dot.y}
                r={r}
                fill={dot.isOffline ? 'var(--color-danger)' : 'var(--color-safe)'}
                opacity={dot.isOffline ? 0.95 : 0.5}
                className={`transition-all duration-700 cursor-pointer ${
                  selectedMeter?.id === dot.id ? 'stroke-[var(--color-text)] stroke-[1.5px]' : ''
                } ${
                  dot.isOffline ? 'meter-red' : 'animate-pulse-slow'
                }`}
                onMouseEnter={() => setHoveredMeter(dot)}
                onMouseLeave={() => setHoveredMeter(null)}
                onClick={() => setSelectedMeter(dot)}
              />
            );
          })}

          {/* Central SOC Hub (HES & MDMS) */}
          <g className="central-hub">
            {/* Link between HES and MDMS */}
            <path d="M 430 200 L 370 200" stroke="var(--color-border)" strokeWidth="2" strokeDasharray="2 2" className="animate-[flow-dash_2s_linear_infinite]" />

            {/* MDMS Node */}
            <g transform="translate(370, 200)" className="cursor-pointer transition-all duration-300 hover:scale-110">
              <circle cx="0" cy="0" r="18" fill="var(--color-bg-panel)" 
                      stroke={stageStatuses['lateral_movement'] === 'complete' || stageStatuses['impact'] ? 'var(--color-danger)' : 'var(--color-accent)'} 
                      strokeWidth="1.5"
                      filter={stageStatuses['lateral_movement'] === 'complete' || stageStatuses['impact'] ? 'url(#glow-red-map)' : 'none'}
                      className={stageStatuses['lateral_movement'] === 'complete' || stageStatuses['impact'] ? 'animate-pulse' : ''} />
              <text x="0" y="4" fontSize="14" textAnchor="middle" dominantBaseline="middle">🖥️</text>
              <rect x="-30" y="20" width="60" height="14" rx="4" fill="var(--color-bg-card)" opacity="0.8" />
              <text x="0" y="27" fill="var(--color-text)" fontSize="8" fontWeight="bold" textAnchor="middle" dominantBaseline="middle">MDMS</text>
            </g>

            {/* HES Node */}
            <g transform="translate(430, 200)" className="cursor-pointer transition-all duration-300 hover:scale-110">
              <circle cx="0" cy="0" r="18" fill="var(--color-bg-panel)" 
                      stroke={stageStatuses['reconnaissance'] || stageStatuses['initial_access'] ? 'var(--color-danger)' : 'var(--color-accent)'} 
                      strokeWidth="1.5"
                      filter={stageStatuses['reconnaissance'] || stageStatuses['initial_access'] ? 'url(#glow-red-map)' : 'none'}
                      className={stageStatuses['reconnaissance'] || stageStatuses['initial_access'] ? 'animate-pulse' : ''} />
              <text x="0" y="4" fontSize="14" textAnchor="middle" dominantBaseline="middle">🌐</text>
              <rect x="-30" y="20" width="60" height="14" rx="4" fill="var(--color-bg-card)" opacity="0.8" />
              <text x="0" y="27" fill="var(--color-text)" fontSize="8" fontWeight="bold" textAnchor="middle" dominantBaseline="middle">HES</text>
            </g>
          </g>

          {/* Attacker Node */}
          {isAttackActive && (
            <g className="attacker-node">
              <circle cx="60" cy="340" r="16" fill="var(--color-bg-panel)" stroke="var(--color-danger)" strokeWidth="2" 
                      className={`transition-all duration-500 ${stageStatuses['reconnaissance'] ? 'filter drop-shadow-[0_0_15px_rgba(239,68,68,0.8)] animate-pulse' : ''}`} />
              <text x="60" y="341" fill="var(--color-danger)" fontSize="14" textAnchor="middle" dominantBaseline="middle">☠️</text>
              <text x="60" y="365" fill="var(--color-danger)" fontSize="9" fontWeight="bold" textAnchor="middle">Attacker</text>
            </g>
          )}
        </svg>

        {/* Hover Tooltip for Meter */}
        {hoveredMeter && (() => {
          const telemetryList = Object.values(meterTelemetry || {}).filter(t => t.zone === hoveredMeter.zone);
          const idx = parseInt(hoveredMeter.id.split('-')[1], 10);
          const telemetry = telemetryList.length > 0 ? telemetryList[idx % telemetryList.length] : null;
          
          return (
            <div 
              className="absolute z-10 pointer-events-none transition-all duration-100"
              style={{ 
                left: `${(hoveredMeter.x / mapWidth) * 100}%`, 
                top: `${(hoveredMeter.y / mapHeight) * 100}%`,
                transform: hoveredMeter.y < 150 ? 'translate(-50%, 10px)' : 'translate(-50%, calc(-100% - 10px))'
              }}
            >
              <div className="bg-[var(--color-bg-card)] border border-[var(--color-border)] shadow-xl rounded px-3 py-2 text-xs backdrop-blur-md whitespace-nowrap min-w-[180px]">
                <div className="font-bold text-[var(--color-text)] mb-1 flex items-center justify-between border-b border-[var(--color-border-dim)] pb-1">
                  <span>{telemetry ? telemetry.meter_id : hoveredMeter.displayId}</span>
                  <span className={hoveredMeter.isOffline ? 'text-[var(--color-danger)]' : 'text-[var(--color-safe)]'}>
                    ●
                  </span>
                </div>
                <div className="text-[10px] text-[var(--color-text-dim)] flex flex-col gap-0.5">
                  <span className="uppercase tracking-wider font-mono mb-1">{ZONE_LABELS[hoveredMeter.zone]}</span>
                  
                  <span className="flex justify-between">
                    Status: <strong className={hoveredMeter.isOffline ? 'text-[var(--color-danger)]' : 'text-[var(--color-safe)]'}>
                      {hoveredMeter.isOffline ? 'OFFLINE' : 'ONLINE'}
                    </strong>
                  </span>
                  
                  {telemetry ? (
                    <>
                      <span className="flex justify-between">
                        FWD (kWh): <strong className="text-[var(--color-text)]">{telemetry.consumption_kwh.toFixed(1)}</strong>
                      </span>
                      <span className="flex justify-between">
                        MD (kW): <strong className="text-[var(--color-text)]">{telemetry.max_demand_kw.toFixed(2)}</strong>
                      </span>
                      <span className="flex justify-between">
                        Load (W): <strong className="text-[var(--color-text)]">{telemetry.active_power_w.toFixed(0)}</strong>
                      </span>
                      <span className="flex justify-between">
                        BATT (V): <strong className={telemetry.battery_voltage < 3.5 ? 'text-[var(--color-danger)]' : 'text-[var(--color-text)]'}>{telemetry.battery_voltage.toFixed(3)}V</strong>
                      </span>
                      <span className="flex justify-between">
                        DIAG: <strong className={telemetry.diag_status === 'Good' ? 'text-[var(--color-safe)]' : 'text-[var(--color-danger)]'}>{telemetry.diag_status}</strong>
                      </span>
                      <span className="flex justify-between">
                        WAN/HAN: <strong>{telemetry.wan_status.charAt(0)}/{telemetry.han_status.charAt(0)}</strong>
                      </span>
                      <span className="flex justify-between mt-1 pt-1 border-t border-[var(--color-border-dim)]">
                        PWR FAIL: <strong>{hoveredMeter.isOffline ? (telemetry.power_fail_count + 1) : telemetry.power_fail_count}</strong>
                      </span>
                    </>
                  ) : (
                    <>
                      <span className="flex justify-between">
                        FWD (kWh): <strong className="text-[var(--color-text)]">{(Math.random() * 1000 + 5000).toFixed(1)}</strong>
                      </span>
                      <span className="flex justify-between">
                        MD (kW): <strong className="text-[var(--color-text)]">{(Math.random() * 5 + 1).toFixed(2)}</strong>
                      </span>
                      <span className="flex justify-between">
                        Load (W): <strong className="text-[var(--color-text)]">{hoveredMeter.isOffline ? 0 : Math.floor(Math.random() * 2000 + 3000)}</strong>
                      </span>
                      <span className="flex justify-between">
                        BATT (V): <strong className="text-[var(--color-text)]">3.850V</strong>
                      </span>
                      <span className="flex justify-between">
                        DIAG: <strong className={hoveredMeter.isOffline ? 'text-[var(--color-danger)]' : 'text-[var(--color-safe)]'}>{hoveredMeter.isOffline ? 'Tamper' : 'Good'}</strong>
                      </span>
                      <span className="flex justify-between">
                        WAN/HAN: <strong>{hoveredMeter.isOffline ? 'D/D' : 'C/C'}</strong>
                      </span>
                      <span className="flex justify-between mt-1 pt-1 border-t border-[var(--color-border-dim)]">
                        PWR FAIL: <strong>{hoveredMeter.isOffline ? 1 : 0}</strong>
                      </span>
                    </>
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* Hover Tooltip for Zone Summary */}
        {hoveredZone && !hoveredMeter && (
          <div className="absolute bottom-4 right-4 z-10 pointer-events-none">
            <div className="bg-[var(--color-bg-panel)] border border-[var(--color-border)] shadow-2xl rounded-lg p-3 text-xs backdrop-blur-md w-48">
              <div className="font-bold text-[var(--color-text)] mb-2 pb-2 border-b border-[var(--color-border-dim)]">
                {ZONE_LABELS[hoveredZone]} Summary
              </div>
              <div className="flex justify-between mb-1">
                <span className="text-[var(--color-text-dim)]">Total Meters:</span>
                <span className="font-mono text-[var(--color-text)]">
                  {meterStatuses[hoveredZone]?.total || (Math.floor(totalMeters / 6) + (Object.keys(ZONE_LABELS).indexOf(hoveredZone) < (totalMeters % 6) ? 1 : 0))}
                </span>
              </div>
              <div className="flex justify-between mb-1">
                <span className="text-[var(--color-safe)] opacity-80">Online:</span>
                <span className="font-mono text-[var(--color-safe)]">
                  {meterStatuses[hoveredZone]?.connected || (Math.floor(totalMeters / 6) + (Object.keys(ZONE_LABELS).indexOf(hoveredZone) < (totalMeters % 6) ? 1 : 0))}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--color-danger)] opacity-80">Offline:</span>
                <span className="font-mono text-[var(--color-danger)]">{meterStatuses[hoveredZone]?.disconnected || 0}</span>
              </div>
            </div>
          </div>
        )}

        {/* Selected Meter Event Log Panel */}
        {selectedMeter && (() => {
          const telemetryList = Object.values(meterTelemetry || {}).filter(t => t.zone === selectedMeter.zone);
          const idx = parseInt(selectedMeter.id.split('-')[1], 10);
          const telemetry = telemetryList.length > 0 ? telemetryList[idx % telemetryList.length] : null;
          const realMeterId = telemetry ? telemetry.meter_id : selectedMeter.displayId;
          const events = meterEvents?.[realMeterId] || [];

          return (
            <div className="absolute top-0 right-0 w-72 h-full bg-[var(--color-bg-panel)] border-l border-[var(--color-border)] shadow-2xl z-20 flex flex-col transform transition-transform duration-300">
              <div className="p-3 border-b border-[var(--color-border-dim)] flex justify-between items-center bg-[var(--color-bg-card)]">
                <div>
                  <h3 className="font-bold text-sm text-[var(--color-text)] flex items-center gap-2">
                    <span className="text-[16px]">📑</span> Event Log
                  </h3>
                  <div className="text-[10px] text-[var(--color-text-dim)] font-mono mt-0.5">{realMeterId}</div>
                </div>
                <button 
                  onClick={() => setSelectedMeter(null)}
                  className="w-6 h-6 rounded-full hover:bg-[var(--color-border)] flex items-center justify-center transition-colors text-[var(--color-text-dim)]"
                >
                  ✕
                </button>
              </div>
              <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2 scrollbar-thin">
                {events.length === 0 ? (
                  <div className="text-xs text-[var(--color-text-muted)] italic text-center mt-4 p-4 border border-dashed border-[var(--color-border-dim)] rounded">
                    No recent events logged for this meter.
                  </div>
                ) : (
                  events.map((ev, i) => (
                    <div key={i} className="text-[11px] bg-[var(--color-bg-card)] p-2.5 rounded border border-[var(--color-border-dim)] shadow-sm">
                      <div className="flex justify-between items-center mb-1.5">
                        <span className="font-bold text-[var(--color-text)] uppercase">{ev.event.replace(/_/g, ' ')}</span>
                        <span className="text-[9px] text-[var(--color-text-muted)] font-mono">
                          {new Date(ev.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second:'2-digit' })}
                        </span>
                      </div>
                      {ev.reason && (
                        <div className="text-[10px] text-[var(--color-danger)] bg-[color-mix(in_srgb,var(--color-danger)_10%,transparent)] px-1.5 py-0.5 rounded mt-1">
                          Reason: {ev.reason}
                        </div>
                      )}
                      {ev.token && (
                        <div className="text-[10px] text-[var(--color-warning)] font-mono bg-[color-mix(in_srgb,var(--color-warning)_10%,transparent)] px-1.5 py-0.5 rounded mt-1">
                          Token: {ev.token}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })()}

      </div>
    </div>
  );
}
