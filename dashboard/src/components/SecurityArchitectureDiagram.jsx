import { useState, useMemo, useRef } from 'react';
import useSimulationStore from '../store/simulationStore';
import { scenarios } from '../config/scenarios';

const NODE_META = {
  operator1:       { icon: '👤', label: 'operator1',       role: 'HES Operator',       ip: '10.0.1.12',    type: 'account' },
  admin:           { icon: '👤', label: 'admin',            role: 'MDMS Admin',         ip: '10.0.1.5',     type: 'account' },
  svc_backup:      { icon: '🔧', label: 'svc_backup',       role: 'Service Account',    ip: '10.0.1.20',    type: 'account' },
  maintenance_svc: { icon: '🤖', label: 'maintenance_svc',  role: 'Automation Script',  ip: '10.0.1.35',    type: 'account' },
  field_tech:      { icon: '👷', label: 'field_tech',       role: 'Field Technician',   ip: '10.0.2.55',    type: 'account' },
  rogue_acct:      { icon: '👻', label: 'rogue_op',         role: 'Rogue Account',      ip: '10.0.1.99',    type: 'rogue' },
  c2_host:         { icon: '☠️', label: 'C2 Host',          role: 'External C2 Server', ip: '203.0.113.42', type: 'external' },
  HES:             { icon: '🌐', label: 'HES',              role: 'Head End System',    ip: '192.168.50.10',type: 'service' },
  MDMS:            { icon: '🖥️', label: 'MDMS',             role: 'MDMS Server',        ip: '192.168.50.11',type: 'service' },
  meters:          { icon: '⚡', label: 'Meter Fleet',      role: 'Smart Meters (500)', ip: '10.100.x.x',   type: 'fleet' },
};

const NODE_COLORS = {
  account:  '#22d3ee',
  service:  '#38bdf8',
  fleet:    '#f59e0b',
  rogue:    '#a855f7',
  external: '#ef4444',
};

// Fixed positions on an 1000x600 viewBox
const POSITIONS = {
  c2_host:         { x: 500, y: 70 },
  rogue_acct:      { x: 125, y: 220 },
  operator1:       { x: 275, y: 220 },
  admin:           { x: 425, y: 220 },
  svc_backup:      { x: 575, y: 220 },
  maintenance_svc: { x: 725, y: 220 },
  field_tech:      { x: 875, y: 220 },
  MDMS:            { x: 375, y: 380 },
  HES:             { x: 625, y: 380 },
  meters:          { x: 500, y: 530 },
};

// ============================================================
// BASELINE_NODES: object map keyed by node ID. These always
// render regardless of simulation state.
// ============================================================
const BASELINE_NODES = {
  operator1:       { id: 'operator1',       ...POSITIONS.operator1 },
  admin:           { id: 'admin',           ...POSITIONS.admin },
  svc_backup:      { id: 'svc_backup',      ...POSITIONS.svc_backup },
  maintenance_svc: { id: 'maintenance_svc', ...POSITIONS.maintenance_svc },
  field_tech:      { id: 'field_tech',      ...POSITIONS.field_tech },
  HES:             { id: 'HES',             ...POSITIONS.HES },
  MDMS:            { id: 'MDMS',            ...POSITIONS.MDMS },
  meters:          { id: 'meters',          ...POSITIONS.meters },
};

const BASELINE_EDGES = [
  { id: 'baseline-operator1-HES',   source: 'operator1',  target: 'HES',    label: 'Normal access',          is_anomalous: false },
  { id: 'baseline-admin-MDMS',      source: 'admin',      target: 'MDMS',   label: 'Admin access',           is_anomalous: false },
  { id: 'baseline-svcbackup-HES',   source: 'svc_backup', target: 'HES',    label: 'Scheduled backup',       is_anomalous: false },
  { id: 'baseline-HES-MDMS',        source: 'HES',        target: 'MDMS',   label: 'System-to-system sync',  is_anomalous: false },
  { id: 'baseline-HES-meters',      source: 'HES',        target: 'meters', label: 'Meter telemetry',        is_anomalous: false },
];

// ============================================================
// SINGLE SOURCE OF TRUTH: useTopologyThreatState
// Computes BOTH which non-baseline nodes should exist AND which
// anomalous edges should exist, from the same kill-chain state.
// An edge can NEVER reference a node that isn't simultaneously
// being rendered — this is structurally guaranteed.
// ============================================================
function useTopologyThreatState(stageStatuses, selectedScenario) {
  return useMemo(() => {
    // activeNodes: non-baseline nodes to render, keyed by ID
    const activeNodes = {};
    // activeEdges: anomalous edges to render
    const activeEdges = [];
    // compromised: set of node IDs marked as compromised
    const compromised = new Set();
    // appeared: set of node IDs that are newly appeared (for animation)
    const appeared = new Set();

    const stageActive = (id) =>
      stageStatuses[id] === 'active' ||
      stageStatuses[id] === 'complete' ||
      stageStatuses[id] === 'blocked';

    // Resolve the compromised identity from scenario config
    const scenarioConfig = scenarios[selectedScenario];
    const identity = scenarioConfig?.compromisedIdentity || 'operator1';

    // false_positive has no kill-chain stages — no threat nodes/edges
    if (selectedScenario === 'false_positive') {
      return { activeNodes, activeEdges, compromised, appeared };
    }

    // Mark compromised identity once initial access or later is active
    if (
      stageActive('initial_access') ||
      stageActive('persistence') ||
      stageActive('lateral_movement') ||
      stageActive('command_control') ||
      stageActive('impact')
    ) {
      compromised.add(identity);
    }

    // Persistence: rogue account appears + edge to HES
    if (stageActive('persistence')) {
      activeNodes['rogue_acct'] = {
        id: 'rogue_acct',
        ...POSITIONS.rogue_acct,
      };
      appeared.add('rogue_acct');
      compromised.add('rogue_acct');
      activeEdges.push({
        id: 'threat-rogue-HES',
        source: 'rogue_acct',
        target: 'HES',
        is_anomalous: true,
        label: 'Rogue account accessing HES',
      });
    }

    // Lateral movement: compromised identity reaches MDMS
    if (stageActive('lateral_movement')) {
      activeEdges.push({
        id: `threat-${identity}-MDMS`,
        source: identity,
        target: 'MDMS',
        is_anomalous: true,
        label: 'Lateral movement to MDMS',
      });
      // Rogue lateral movement — only if rogue_acct is active
      if (activeNodes['rogue_acct']) {
        activeEdges.push({
          id: 'threat-rogue-MDMS',
          source: 'rogue_acct',
          target: 'MDMS',
          is_anomalous: true,
          label: 'Rogue lateral movement',
        });
      }
    }

    // Command & Control: C2 Host node appears + C2 beaconing edges
    // THIS is the single flag that controls BOTH the node's
    // existence AND every edge that targets it.
    if (stageActive('command_control')) {
      activeNodes['c2_host'] = {
        id: 'c2_host',
        ...POSITIONS.c2_host, // fixed coordinate — no dynamic positioning
      };
      appeared.add('c2_host');
      activeEdges.push({
        id: `threat-c2-${identity}`,
        source: 'c2_host',
        target: identity,
        is_anomalous: true,
        is_c2: true,
        label: 'C2 beaconing',
      });
      // C2 → rogue only if rogue_acct is also active
      if (activeNodes['rogue_acct']) {
        activeEdges.push({
          id: 'threat-c2-rogue',
          source: 'c2_host',
          target: 'rogue_acct',
          is_anomalous: true,
          is_c2: true,
          label: 'C2 beaconing',
        });
      }
    }

    return { activeNodes, activeEdges, compromised, appeared };
  }, [stageStatuses, selectedScenario]);
}

export default function SecurityArchitectureDiagram() {
  // Subscribe ONLY to the specific state slices we need to avoid re-rendering
  // on every single risk score update tick. This prevents React-induced flickering.
  const stageStatuses = useSimulationStore(s => 
    (s.isScrubbing && s.riskHistory[s.scrubIndex]?.snapshot) 
      ? s.riskHistory[s.scrubIndex].snapshot.stageStatuses 
      : s.stageStatuses
  );
  const selectedScenario = useSimulationStore(s => s.selectedScenario);

  const [tooltip, setTooltip] = useState(null);
  const containerRef = useRef(null);

  // Single source of truth for threat topology
  const { activeNodes, activeEdges, compromised, appeared } =
    useTopologyThreatState(stageStatuses, selectedScenario);

  // Merge baseline + active nodes into one map — this is the
  // complete set of nodes that will be rendered.
  const allNodes = useMemo(
    () => ({ ...BASELINE_NODES, ...activeNodes }),
    [activeNodes]
  );

  // Build baseline edges, applying the impact-stage override
  const baselineEdges = useMemo(() => {
    const stageActive = (id) =>
      stageStatuses[id] === 'active' ||
      stageStatuses[id] === 'complete' ||
      stageStatuses[id] === 'blocked';

    return BASELINE_EDGES.map((e) => {
      // Impact stage: HES→meters becomes anomalous
      if (
        stageActive('impact') &&
        selectedScenario !== 'false_positive' &&
        e.source === 'HES' &&
        e.target === 'meters'
      ) {
        return {
          ...e,
          is_anomalous: true,
          label: 'Malicious disconnect commands flowing to meter fleet',
        };
      }
      return e;
    });
  }, [stageStatuses, selectedScenario]);

  // Combine all edges
  const allEdges = useMemo(
    () => [...baselineEdges, ...activeEdges],
    [baselineEdges, activeEdges]
  );

  // ============================================================
  // GUARD: Filter out any edge whose source or target doesn't
  // resolve to a currently-rendered node. This makes a "dangling
  // edge to empty space" structurally impossible.
  // ============================================================
  const renderableEdges = useMemo(() => {
    const safe = allEdges.filter(
      (edge) => allNodes[edge.source] && allNodes[edge.target]
    );

    if (allEdges.length !== safe.length) {
      // Dev-time safety net: this should never fire. If it does,
      // it means a scenario config references a node ID that was
      // never defined — surface it loudly instead of silently
      // drawing a broken line.
      console.warn(
        '[SecurityArchitectureDiagram] Dropped edge(s) with missing node:',
        allEdges.filter((e) => !allNodes[e.source] || !allNodes[e.target])
      );
    }

    return safe;
  }, [allEdges, allNodes]);

  const anomalousCount = renderableEdges.filter((e) => e.is_anomalous).length;

  const handleMouseEnter = (evt, type, data) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    setTooltip({
      ...data,
      type,
      x: evt.clientX - rect.left,
      y: evt.clientY - rect.top,
    });
  };

  return (
    <div className="glass-panel p-3 h-full flex flex-col relative" ref={containerRef}>
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <span className="text-lg">🌐</span>
          <h2 className="text-sm font-bold text-[var(--color-text)] uppercase tracking-wider">
            SOC Threat Topology
          </h2>
        </div>
        {anomalousCount > 0 && (
          <span className="text-[10px] bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full font-bold animate-pulse">
            {anomalousCount} Anomal{anomalousCount > 1 ? 'ies' : 'y'}
          </span>
        )}
      </div>

      <div className="flex-1 min-h-0 relative">
        <svg viewBox="0 0 1000 620" className="w-full h-full" preserveAspectRatio="xMidYMid meet">
          <defs>
            <filter id="topo-glow-red" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>
          
          <g className="tiers">
            <rect x="0" y="20" width="1000" height="100" fill="var(--color-danger)" opacity="0.1" rx="8" />
            <text x="20" y="55" fill="var(--color-text-dim)" fontSize="22" fontWeight="bold">External / Untrusted</text>
            
            <rect x="0" y="150" width="1000" height="130" fill="#22d3ee" opacity="0.1" rx="8" />
            <text x="20" y="175" fill="var(--color-text-dim)" fontSize="22" fontWeight="bold">Identity / Access Layer</text>
            
            <rect x="0" y="310" width="1000" height="130" fill="var(--color-accent)" opacity="0.1" rx="8" />
            <text x="20" y="335" fill="var(--color-text-dim)" fontSize="22" fontWeight="bold">OT Systems</text>
            
            <rect x="0" y="470" width="1000" height="130" fill="var(--color-warning)" opacity="0.1" rx="8" />
            <text x="20" y="495" fill="var(--color-text-dim)" fontSize="22" fontWeight="bold">Field Devices</text>
          </g>

          {/* Edges render FIRST — so nodes sit on top visually */}
          <g className="edges">
            {renderableEdges.map((e) => {
              const source = allNodes[e.source];
              const target = allNodes[e.target];
              return (
                <line
                  key={e.id}
                  x1={source.x} y1={source.y} x2={target.x} y2={target.y}
                  className={`cursor-pointer transition-all duration-300 ${
                    e.is_c2 ? 'graph-edge-c2' : e.is_anomalous ? 'graph-edge-anomalous' : 'graph-edge-normal'
                  }`}
                  filter={e.is_anomalous ? 'url(#topo-glow-red)' : 'none'}
                  onMouseEnter={(evt) => handleMouseEnter(evt, 'edge', { label: e.label, isAnomalous: e.is_anomalous })}
                  onMouseLeave={() => setTooltip(null)}
                />
              );
            })}
          </g>
          
          {/* Nodes render SECOND — so they sit on top of edges */}
          <g className="nodes">
            {Object.entries(allNodes).map(([nodeId, pos]) => {
              const meta = NODE_META[nodeId];
              const isComp = compromised.has(nodeId);
              const isNew = appeared.has(nodeId);
              if (!meta) return null;
              return (
                <g 
                  key={nodeId} 
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onMouseEnter={(evt) => handleMouseEnter(evt, 'node', { 
                    id: nodeId, icon: meta.icon, label: meta.label, 
                    role: meta.role, ip: meta.ip, isCompromised: isComp, nodeType: meta.type 
                  })}
                  onMouseLeave={() => setTooltip(null)}
                  className={`cursor-pointer transition-transform duration-300 hover:scale-110 ${isNew ? 'animate-node-appear' : ''}`}
                >
                  {isComp && (
                    <circle r="36" fill="none" stroke="#ef4444" strokeWidth="2" className="animate-pulse-ring" />
                  )}
                  <circle r="28" fill="var(--color-bg-panel)" stroke={NODE_COLORS[meta.type] || '#888'} strokeWidth="1.5" />
                  <text textAnchor="middle" dominantBaseline="central" fontSize="30">{meta.icon}</text>
                  <rect x="-70" y="32" width="140" height="28" rx="4" fill="var(--color-bg-card)" opacity="0.9" />
                  <text y="51" textAnchor="middle" fill="var(--color-text)" fontSize="18" fontWeight="bold">{meta.label}</text>
                </g>
              );
            })}
          </g>
        </svg>

        {tooltip && (
          <div
            className="absolute pointer-events-none z-50"
            style={{
              left: Math.min(tooltip.x + 15, containerRef.current?.offsetWidth - 160 || 9999),
              ...(tooltip.y > (containerRef.current?.offsetHeight || 0) / 2
                ? { bottom: (containerRef.current?.offsetHeight || 0) - tooltip.y + 10 }
                : { top: tooltip.y - 10 }),
            }}
          >
            {tooltip.type === 'node' ? (
              <div className="bg-[var(--color-bg-panel)] border border-[var(--color-border-dim)] rounded-lg p-2 shadow-2xl min-w-[150px]">
                <div className="flex items-center gap-1.5 border-b border-[var(--color-border-dim)] pb-1 mb-1">
                  <span className="text-sm">{tooltip.icon}</span>
                  <span className="text-[10px] font-bold text-[var(--color-text)]">{tooltip.label}</span>
                  <span className="text-[8px] text-[var(--color-text-dim)] ml-auto">({tooltip.role})</span>
                </div>
                <div className="text-[8px] font-mono text-[var(--color-text-dim)] flex justify-between">
                  <span>IP:</span> <span className="text-[var(--color-text)]">{tooltip.ip}</span>
                </div>
                <div className={`text-[8.5px] font-bold mt-1 text-center py-0.5 rounded ${
                  tooltip.isCompromised
                    ? 'bg-red-500/20 text-red-400'
                    : tooltip.nodeType === 'rogue'
                    ? 'bg-purple-500/20 text-purple-400'
                    : tooltip.nodeType === 'external'
                    ? 'bg-red-500/20 text-red-400'
                    : 'bg-green-500/10 text-[var(--color-safe)]'
                }`}>
                  {tooltip.isCompromised ? '⚠️ COMPROMISED' :
                   tooltip.nodeType === 'rogue' ? '👻 Rogue — Attacker Created' :
                   tooltip.nodeType === 'external' ? '☠️ External Threat' :
                   '✓ Healthy'}
                </div>
              </div>
            ) : (
              <div className={`bg-[var(--color-bg-panel)] border rounded-lg p-2 shadow-2xl max-w-[200px] ${
                tooltip.isAnomalous ? 'border-red-500/40' : 'border-[var(--color-border-dim)]'
              }`}>
                <div className="text-[9px] leading-tight text-[var(--color-text)]">{tooltip.label}</div>
                {tooltip.isAnomalous && (
                  <div className="text-[8px] font-bold mt-1 text-red-400">🔴 Anomalous Connection</div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
