/**
 * APT Simulator — Network Graph Component
 * 
 * High-end SOC Threat Topology Map with dynamic nodes,
 * hierarchical layout, and traveling data packet animations.
 */

import { useEffect, useState, useRef } from 'react';
import useSimulationStore from '../store/simulationStore';
import useActiveState from '../hooks/useActiveState';

const API_BASE = 'http://localhost:8003';

const NODE_META = {
  'admin': { icon: '👤', name: 'Admin Console', ip: '10.0.1.5', proto: 'HTTPS' },
  'operator1': { icon: '👤', name: 'Operator 1', ip: '10.0.1.12', proto: 'SSH / RDP' },
  'HES': { icon: '🖥️', name: 'Head End System', ip: '192.168.50.10', proto: 'DNP3 / TLS' },
  'MDMS': { icon: '🖥️', name: 'MDMS Server', ip: '192.168.50.11', proto: 'REST API' },
  'meters': { icon: '⚡', name: 'Smart Meter Fleet', ip: '10.100.x.x', proto: 'DLMS / COSEM' },
  'attacker': { icon: '☠️', name: 'Unknown Threat', ip: '203.0.113.42', proto: 'Custom / C2' }
};

const NODE_COLORS = {
  'service': 'var(--color-accent)',
  'operator': 'var(--color-safe)',
  'rogue': 'var(--color-danger)',
  'fleet': 'var(--color-warning)',
  'attacker': 'var(--color-info)',
};

// Fixed positions for SOC hierarchy
const FIXED_POSITIONS = {
  'operator1': { x: 70, y: 50 },
  'admin': { x: 230, y: 50 },
  'HES': { x: 100, y: 150 },
  'MDMS': { x: 200, y: 150 },
  'meters': { x: 150, y: 250 },
  'attacker': { x: -20, y: 100 } // mostly hidden/offscreen unless used
};

export default function NetworkGraph() {
  const { graphData, setGraphData } = useSimulationStore();
  const { simulationState, stageStatuses } = useActiveState();
  const [hoveredNode, setHoveredNode] = useState(null);
  
  const svgRef = useRef(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Poll graph data
  useEffect(() => {
    const fetchGraph = async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/graph`);
        if (resp.ok) {
          const data = await resp.json();
          setGraphData(data);
        }
      } catch (e) { /* detector not running yet */ }
    };

    fetchGraph();
    const interval = setInterval(fetchGraph, 3000);
    return () => clearInterval(interval);
  }, [setGraphData]);

  // Merge backend nodes with default topology
  const defaultNodes = [
    { id: 'operator1', type: 'operator' },
    { id: 'admin', type: 'operator' },
    { id: 'HES', type: 'service' },
    { id: 'MDMS', type: 'service' },
    { id: 'meters', type: 'fleet' },
  ];
  
  const nodes = graphData.nodes?.length > 0 ? graphData.nodes : defaultNodes;

  const edges = graphData.edges?.length > 0 ? graphData.edges : [
    { source: 'operator1', target: 'HES', is_anomalous: false },
    { source: 'admin', target: 'HES', is_anomalous: false },
    { source: 'HES', target: 'MDMS', is_anomalous: false },
    { source: 'HES', target: 'meters', is_anomalous: false },
  ];
  
  const anomalousCount = edges.filter(e => e.is_anomalous).length;
  const attackActive = simulationState === 'running' && anomalousCount > 0;

  // Handle Hover Tooltip
  const handleMouseMove = (e, node) => {
    if (!svgRef.current) return;
    const pt = svgRef.current.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const svgP = pt.matrixTransform(svgRef.current.getScreenCTM().inverse());
    setTooltipPos({ x: svgP.x, y: svgP.y });
    setHoveredNode(node);
  };

  return (
    <div className="glass-panel p-4 h-full flex flex-col relative">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-sm">🌐</span>
          <h2 className="text-xs font-bold text-[var(--color-text)] uppercase tracking-wider">
            SOC Threat Topology
          </h2>
        </div>
        {anomalousCount > 0 && (
          <span className="text-[10px] bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full font-bold animate-pulse">
            {anomalousCount} Anomalous Connection{anomalousCount > 1 ? 's' : ''}
          </span>
        )}
      </div>

      <div className="flex-1 min-h-0 relative">
        <svg ref={svgRef} viewBox="0 0 300 280" className="w-full h-full" preserveAspectRatio="xMidYMid meet">
          <defs>
            <filter id="glow-cyan" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Edges & Traveling Packets */}
          {edges.map((edge, i) => {
            const from = FIXED_POSITIONS[edge.source] || { x: 0, y: 0 };
            const to = FIXED_POSITIONS[edge.target] || { x: 0, y: 0 };
            const pathData = `M ${from.x} ${from.y} L ${to.x} ${to.y}`;
            const pathId = `edge-${i}`;

            return (
              <g key={pathId}>
                {/* Base Line */}
                <path 
                  id={pathId} d={pathData} fill="none"
                  stroke={edge.is_anomalous ? 'var(--color-danger)' : 'var(--color-info)'}
                  strokeWidth={edge.is_anomalous ? 2.5 : 1}
                  opacity={edge.is_anomalous ? 0.8 : 0.3}
                  strokeDasharray={edge.is_anomalous ? '6 4' : 'none'}
                  className={edge.is_anomalous ? 'animate-flow-dash' : ''}
                />
                
                {/* Traveling Packets (Anomalous = Fast Red, Normal = Slow Cyan) */}
                <circle r={edge.is_anomalous ? 2.5 : 1.5} fill={edge.is_anomalous ? 'var(--color-danger)' : 'var(--color-info)'} filter={edge.is_anomalous ? 'url(#glow-red)' : 'none'}>
                  <animateMotion dur={edge.is_anomalous ? "1.5s" : "4s"} repeatCount="indefinite">
                    <mpath href={`#${pathId}`} />
                  </animateMotion>
                </circle>
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const pos = FIXED_POSITIONS[node.id] || { x: -100, y: -100 };
            const meta = NODE_META[node.id] || { icon: '❓', name: node.id };
            const isHovered = hoveredNode?.id === node.id;
            const color = NODE_COLORS[node.type] || 'var(--color-text-muted)';
            
            // Is this node part of an anomalous connection?
            const isCompromised = edges.some(e => e.is_anomalous && (e.target === node.id || e.source === node.id));

            return (
              <g key={node.id}
                onMouseMove={(e) => handleMouseMove(e, { ...node, ...meta, isCompromised })}
                onMouseLeave={() => setHoveredNode(null)}
                className={`cursor-pointer transition-all duration-300 ${isHovered ? 'scale-110' : ''}`}
                style={{ transformOrigin: `${pos.x}px ${pos.y}px` }}
              >
                {/* Background Glow */}
                <circle cx={pos.x} cy={pos.y} r="18" fill="var(--color-bg-panel)" 
                        stroke={isCompromised ? 'var(--color-danger)' : color} strokeWidth="1.5"
                        filter={isCompromised ? 'url(#glow-red)' : 'none'}
                        className={isCompromised ? 'animate-pulse' : ''} />
                
                {/* Node Icon */}
                <text x={pos.x} y={pos.y + 4} fontSize="14" textAnchor="middle" dominantBaseline="middle">
                  {meta.icon}
                </text>

                {/* Node Label (Below) */}
                <rect x={pos.x - 30} y={pos.y + 20} width="60" height="14" rx="4" fill="var(--color-bg-card)" opacity="0.8" />
                <text x={pos.x} y={pos.y + 27} fill="var(--color-text)" fontSize="8" fontWeight="bold" textAnchor="middle" dominantBaseline="middle">
                  {node.id}
                </text>
              </g>
            );
          })}

          {/* Custom HTML Tooltip via foreignObject */}
          {hoveredNode && (
            <foreignObject 
              x={tooltipPos.x + 15 > 150 ? tooltipPos.x - 160 : tooltipPos.x + 15} 
              y={tooltipPos.y - 30 > 200 ? tooltipPos.y - 80 : tooltipPos.y - 30} 
              width="150" height="80" 
              className="pointer-events-none transition-all"
            >
              <div className="bg-[var(--color-bg-panel)] border border-[var(--color-border-dim)] rounded-lg p-2 shadow-2xl flex flex-col gap-1">
                <div className="flex items-center gap-1.5 border-b border-[var(--color-border-dim)] pb-1 mb-0.5">
                  <span className="text-sm">{hoveredNode.icon}</span>
                  <span className="text-[10px] font-bold text-white truncate">{hoveredNode.name}</span>
                </div>
                <div className="text-[8px] font-mono text-[var(--color-text-dim)] flex justify-between">
                  <span>IP:</span> <span className="text-[var(--color-text)]">{hoveredNode.ip}</span>
                </div>
                <div className="text-[8px] font-mono text-[var(--color-text-dim)] flex justify-between">
                  <span>Proto:</span> <span className="text-[var(--color-text)]">{hoveredNode.proto}</span>
                </div>
                <div className={`text-[8.5px] font-bold mt-1 text-center py-0.5 rounded ${hoveredNode.isCompromised ? 'bg-red-500/20 text-red-400' : 'bg-green-500/10 text-[var(--color-safe)]'}`}>
                  {hoveredNode.isCompromised ? '⚠️ Anomaly Detected' : '✓ Healthy'}
                </div>
              </div>
            </foreignObject>
          )}
        </svg>
      </div>
    </div>
  );
}
