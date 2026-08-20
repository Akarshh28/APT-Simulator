/**
 * APT Simulator — SOC Threat Topology Panel
 *
 * D3.js force-directed graph showing the access topology of the simulated
 * environment.  Nodes and edges are added progressively as the kill-chain
 * advances, visually proving the "Graph Anomaly" detection signal.
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import useActiveState from '../hooks/useActiveState';

/* ─── Static Metadata ─────────────────────────────────────── */

const NODE_META = {
  operator1:  { icon: '👤', label: 'operator1',    role: 'HES Operator',       ip: '10.0.1.12',    proto: 'SSH / RDP' },
  admin:      { icon: '👤', label: 'admin',         role: 'MDMS Admin',         ip: '10.0.1.5',     proto: 'HTTPS' },
  svc_backup: { icon: '🔧', label: 'svc_backup',    role: 'Service Account',    ip: '10.0.1.20',    proto: 'SSH' },
  HES:        { icon: '🖥️', label: 'HES',           role: 'Head End System',    ip: '192.168.50.10', proto: 'DNP3 / TLS' },
  MDMS:       { icon: '🖥️', label: 'MDMS',          role: 'MDMS Server',        ip: '192.168.50.11', proto: 'REST API' },
  meters:     { icon: '⚡',  label: 'Meter Fleet',   role: 'Smart Meters (500)', ip: '10.100.x.x',    proto: 'DLMS/COSEM' },
  rogue_acct: { icon: '👻', label: 'rogue_op',      role: 'Rogue Account',      ip: '10.0.1.99',    proto: 'SSH / RDP' },
  c2_host:    { icon: '☠️', label: 'C2 Host',       role: 'External C2 Server', ip: '203.0.113.42', proto: 'Custom C2' },
};

const NODE_COLORS = {
  account:  '#22d3ee',   // cyan
  service:  '#38bdf8',   // blue
  fleet:    '#f59e0b',   // amber
  rogue:    '#a855f7',   // purple
  external: '#ef4444',   // red
};

const INITIAL_POSITIONS = {
  operator1:  { x: 0.25, y: 0.15 },
  admin:      { x: 0.75, y: 0.15 },
  svc_backup: { x: 0.50, y: 0.10 },
  HES:        { x: 0.30, y: 0.50 },
  MDMS:       { x: 0.70, y: 0.50 },
  meters:     { x: 0.50, y: 0.85 },
  rogue_acct: { x: 0.10, y: 0.35 },
  c2_host:    { x: 0.05, y: 0.65 },
};

/* ─── Baseline topology (always visible in idle) ─────────── */

const BASELINE_NODES = [
  { id: 'operator1',  type: 'account' },
  { id: 'admin',      type: 'account' },
  { id: 'svc_backup', type: 'account' },
  { id: 'HES',        type: 'service' },
  { id: 'MDMS',       type: 'service' },
  { id: 'meters',     type: 'fleet' },
];

const BASELINE_EDGES = [
  { source: 'operator1',  target: 'HES',    label: 'Normal access',          is_anomalous: false },
  { source: 'admin',      target: 'MDMS',   label: 'Admin access',           is_anomalous: false },
  { source: 'svc_backup', target: 'HES',    label: 'Scheduled backup',       is_anomalous: false },
  { source: 'HES',        target: 'MDMS',   label: 'System-to-system sync',  is_anomalous: false },
  { source: 'HES',        target: 'meters', label: 'Meter telemetry',        is_anomalous: false },
];

/* ─── Edge tooltips for anomalous connections ─────────────── */

const ANOMALY_TOOLTIPS = {
  'rogue_acct->HES':     'Rogue account accessing HES — unknown credential created during Persistence phase',
  'operator1->MDMS':     'Unexpected: operator accounts should never access MDMS directly — flagged by Graph Anomaly detector',
  'rogue_acct->MDMS':    'Rogue account performing lateral movement to MDMS — cross-system privilege escalation',
  'c2_host->operator1':  'C2 beaconing: compromised operator1 communicating with external command server',
  'c2_host->rogue_acct': 'C2 beaconing: rogue account receiving instructions from external command server',
};

/* ─── Component ───────────────────────────────────────────── */

export default function NetworkGraph() {
  const { simulationState, stageStatuses, graphData } = useActiveState();
  const svgRef = useRef(null);
  const simRef = useRef(null);
  const [tooltip, setTooltip] = useState(null);
  const [dimensions, setDimensions] = useState({ width: 400, height: 280 });

  /* ── Derive visible nodes & edges from stage progression ── */
  const getActiveGraph = useCallback(() => {
    const nodes = [...BASELINE_NODES];
    const edges = [...BASELINE_EDGES];
    const compromised = new Set();
    const appeared = new Set();      // newly appearing node IDs (for animation)

    // Gather completed or active stages
    const stageActive = (id) => {
      const s = stageStatuses[id];
      return s === 'active' || s === 'complete' || s === 'blocked';
    };

    // Initial Access — mark operator1 compromised
    if (stageActive('initial_access')) {
      compromised.add('operator1');
    }

    // Persistence — rogue_acct appears
    if (stageActive('persistence')) {
      nodes.push({ id: 'rogue_acct', type: 'rogue' });
      appeared.add('rogue_acct');
      edges.push({ source: 'rogue_acct', target: 'HES', label: ANOMALY_TOOLTIPS['rogue_acct->HES'], is_anomalous: true });
      compromised.add('rogue_acct');
    }

    // Lateral Movement — anomalous cross-access edges
    if (stageActive('lateral_movement')) {
      edges.push({ source: 'operator1', target: 'MDMS', label: ANOMALY_TOOLTIPS['operator1->MDMS'], is_anomalous: true });
      if (nodes.some(n => n.id === 'rogue_acct')) {
        edges.push({ source: 'rogue_acct', target: 'MDMS', label: ANOMALY_TOOLTIPS['rogue_acct->MDMS'], is_anomalous: true });
      }
    }

    // Command & Control — c2_host appears + beaconing edges
    if (stageActive('command_control')) {
      nodes.push({ id: 'c2_host', type: 'external' });
      appeared.add('c2_host');
      edges.push({ source: 'c2_host', target: 'operator1', label: ANOMALY_TOOLTIPS['c2_host->operator1'], is_anomalous: true, is_c2: true });
      if (nodes.some(n => n.id === 'rogue_acct')) {
        edges.push({ source: 'c2_host', target: 'rogue_acct', label: ANOMALY_TOOLTIPS['c2_host->rogue_acct'], is_anomalous: true, is_c2: true });
      }
    }

    // Impact — HES→meters turns anomalous
    if (stageActive('impact')) {
      // Replace the baseline HES→meters edge with an anomalous version
      const hesMetersIdx = edges.findIndex(e =>
        (typeof e.source === 'string' ? e.source : e.source.id) === 'HES' &&
        (typeof e.target === 'string' ? e.target : e.target.id) === 'meters' &&
        !e.is_anomalous
      );
      if (hesMetersIdx >= 0) {
        edges[hesMetersIdx] = {
          source: 'HES', target: 'meters',
          label: 'Malicious disconnect commands flowing to meter fleet',
          is_anomalous: true,
        };
      }
    }

    return { nodes, edges, compromised, appeared };
  }, [stageStatuses]);

  /* ── Resize observer ──────────────────────────────────────── */
  useEffect(() => {
    const container = svgRef.current?.parentElement;
    if (!container) return;
    const ro = new ResizeObserver(entries => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) setDimensions({ width, height });
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  /* ── D3 Force simulation ──────────────────────────────────── */
  useEffect(() => {
    const { nodes, edges, compromised, appeared } = getActiveGraph();
    const { width, height } = dimensions;
    const svg = d3.select(svgRef.current);

    // Prepare simulation data — give each node an initial position
    const simNodes = nodes.map(n => {
      const pos = INITIAL_POSITIONS[n.id] || { x: 0.5, y: 0.5 };
      return { ...n, x: pos.x * width, y: pos.y * height };
    });
    const simEdges = edges.map(e => ({
      ...e,
      source: typeof e.source === 'string' ? e.source : e.source.id,
      target: typeof e.target === 'string' ? e.target : e.target.id,
    }));

    // Stop previous simulation
    if (simRef.current) simRef.current.stop();

    const simulation = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink(simEdges).id(d => d.id).distance(width * 0.22).strength(0.4))
      .force('charge', d3.forceManyBody().strength(-width * 0.5))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(28))
      .force('x', d3.forceX(d => (INITIAL_POSITIONS[d.id]?.x ?? 0.5) * width).strength(0.12))
      .force('y', d3.forceY(d => (INITIAL_POSITIONS[d.id]?.y ?? 0.5) * height).strength(0.12))
      .alphaDecay(0.03)
      .velocityDecay(0.4);

    simRef.current = simulation;

    const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

    simulation.on('tick', () => {
      // Constrain nodes within SVG bounds (with safe margin for labels and rings)
      simNodes.forEach(n => {
        n.x = clamp(n.x, 45, width - 45);
        n.y = clamp(n.y, 40, height - 45);
      });

      /* ── Edges ── */
      const edgeGroup = svg.select('.edges');
      const edgeSel = edgeGroup.selectAll('line').data(simEdges, (d, i) => `${d.source.id || d.source}-${d.target.id || d.target}-${i}`);
      edgeSel.exit().remove();
      const edgeEnter = edgeSel.enter().append('line');
      edgeSel.merge(edgeEnter)
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y)
        .attr('class', d => d.is_c2 ? 'graph-edge-c2' : d.is_anomalous ? 'graph-edge-anomalous' : 'graph-edge-normal')
        .on('mouseenter', function (event, d) {
          if (d.label) {
            const rect = svgRef.current.getBoundingClientRect();
            setTooltip({
              type: 'edge',
              x: event.clientX - rect.left,
              y: event.clientY - rect.top,
              label: d.label,
              isAnomalous: d.is_anomalous,
            });
          }
        })
        .on('mouseleave', () => setTooltip(null));

      /* ── Nodes ── */
      const nodeGroup = svg.select('.nodes');
      const nodeSel = nodeGroup.selectAll('.node-group').data(simNodes, d => d.id);
      nodeSel.exit().remove();
      const nodeEnter = nodeSel.enter().append('g')
        .attr('class', d => `node-group ${appeared.has(d.id) ? 'animate-node-appear' : ''}`)
        .style('transform-origin', d => `${d.x}px ${d.y}px`);

      // Compromised ring (pulsing)
      nodeEnter.append('circle')
        .attr('class', 'compromised-ring')
        .attr('r', 24).attr('fill', 'none').attr('stroke', '#ef4444')
        .attr('stroke-width', 2).style('display', 'none');

      // Main circle
      nodeEnter.append('circle')
        .attr('class', 'main-circle')
        .attr('r', 18)
        .attr('fill', 'var(--color-bg-panel)')
        .attr('stroke-width', 1.5);

      // Icon text
      nodeEnter.append('text')
        .attr('class', 'node-icon')
        .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
        .attr('font-size', 13);

      // Label background
      nodeEnter.append('rect')
        .attr('class', 'label-bg')
        .attr('rx', 3).attr('fill', 'var(--color-bg-card)').attr('opacity', 0.85);

      // Label text
      nodeEnter.append('text')
        .attr('class', 'label-text')
        .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
        .attr('fill', 'var(--color-text)').attr('font-size', 8).attr('font-weight', 'bold');

      // Merge
      const allNodes = nodeSel.merge(nodeEnter);

      allNodes.attr('transform', d => `translate(${d.x}, ${d.y})`);
      allNodes.select('.main-circle')
        .attr('stroke', d => NODE_COLORS[d.type] || '#888');
      allNodes.select('.node-icon')
        .text(d => NODE_META[d.id]?.icon || '❓');
      allNodes.select('.label-bg')
        .attr('x', -28).attr('y', 20).attr('width', 56).attr('height', 14);
      allNodes.select('.label-text')
        .attr('y', 27)
        .text(d => NODE_META[d.id]?.label || d.id);

      // Compromised ring visibility
      allNodes.select('.compromised-ring')
        .style('display', d => compromised.has(d.id) ? 'block' : 'none')
        .attr('class', d => compromised.has(d.id) ? 'compromised-ring animate-pulse-ring' : 'compromised-ring');

      // Hover events
      allNodes
        .style('cursor', 'pointer')
        .on('mouseenter', function (event, d) {
          const rect = svgRef.current.getBoundingClientRect();
          const meta = NODE_META[d.id] || {};
          setTooltip({
            type: 'node',
            x: event.clientX - rect.left,
            y: event.clientY - rect.top,
            id: d.id,
            icon: meta.icon,
            label: meta.label || d.id,
            role: meta.role,
            ip: meta.ip,
            proto: meta.proto,
            isCompromised: compromised.has(d.id),
            nodeType: d.type,
          });
        })
        .on('mouseleave', () => setTooltip(null));
    });

    return () => simulation.stop();
  }, [getActiveGraph, dimensions]);

  /* ── Anomaly count ──────────────────────────────────────── */
  const { edges: activeEdges } = getActiveGraph();
  const anomalousCount = activeEdges.filter(e => e.is_anomalous).length;

  return (
    <div className="glass-panel p-3 h-full flex flex-col relative">
      {/* Header */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <span className="text-sm">🌐</span>
          <h2 className="text-xs font-bold text-[var(--color-text)] uppercase tracking-wider">
            SOC Threat Topology
          </h2>
        </div>
        {anomalousCount > 0 && (
          <span className="text-[10px] bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full font-bold animate-pulse">
            {anomalousCount} Anomal{anomalousCount > 1 ? 'ies' : 'y'}
          </span>
        )}
      </div>

      {/* Graph Container */}
      <div className="flex-1 min-h-0 relative">
        <svg
          ref={svgRef}
          width={dimensions.width}
          height={dimensions.height}
          className="w-full h-full"
        >
          <defs>
            <filter id="topo-glow-red" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>
          <g className="edges" />
          <g className="nodes" />
        </svg>

        {/* Tooltip overlay */}
        {tooltip && (
          <div
            className="absolute pointer-events-none z-50"
            style={{
              left: tooltip.x + 15 > dimensions.width - 160 ? tooltip.x - 175 : tooltip.x + 15,
              top: tooltip.y - 10 > dimensions.height - 80 ? tooltip.y - 90 : tooltip.y - 10,
            }}
          >
            {tooltip.type === 'node' ? (
              <div className="bg-[var(--color-bg-panel)] border border-[var(--color-border-dim)] rounded-lg p-2 shadow-2xl min-w-[150px]">
                <div className="flex items-center gap-1.5 border-b border-[var(--color-border-dim)] pb-1 mb-1">
                  <span className="text-sm">{tooltip.icon}</span>
                  <span className="text-[10px] font-bold text-white">{tooltip.label}</span>
                  <span className="text-[8px] text-[var(--color-text-dim)] ml-auto">({tooltip.role})</span>
                </div>
                <div className="text-[8px] font-mono text-[var(--color-text-dim)] flex justify-between">
                  <span>IP:</span> <span className="text-[var(--color-text)]">{tooltip.ip}</span>
                </div>
                <div className="text-[8px] font-mono text-[var(--color-text-dim)] flex justify-between">
                  <span>Proto:</span> <span className="text-[var(--color-text)]">{tooltip.proto}</span>
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
