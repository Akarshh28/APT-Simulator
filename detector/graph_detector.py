"""
APT Simulator — Graph-Based Lateral Movement Detector
======================================================
Maintains a live directed graph of service-to-service and
operator-to-service communications. New edges that don't exist
in the baseline graph are flagged as potential lateral movement.

This catches the attacker's pivot from HES to MDMS, which creates
a new graph edge (rogue_operator → MDMS) that wasn't in the baseline.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import networkx as nx

logger = logging.getLogger(__name__)


class GraphDetector:
    """
    Graph-based lateral movement detection.
    
    Baseline: a known-good communication graph.
    Live: incoming authentication/access events add edges.
    Detection: any edge not in baseline is anomalous.
    """

    def __init__(self):
        # Baseline graph (known-good edges)
        self.baseline_graph = nx.DiGraph()
        self._init_baseline()

        # Live graph (grows as events come in)
        self.live_graph = nx.DiGraph()

        # Anomalous edges detected
        self.anomalous_edges: list[dict] = []

    def _init_baseline(self):
        """Set up the baseline communication graph."""
        # Known legitimate communication edges
        known_edges = [
            ("operator1", "HES", "operator_login"),
            ("admin", "HES", "admin_login"),
            ("HES", "MDMS", "data_forward"),
            ("HES", "meters", "command_dispatch"),
            ("meters", "HES", "telemetry"),
        ]

        for source, target, edge_type in known_edges:
            self.baseline_graph.add_edge(source, target, type=edge_type)

    def record_interaction(
        self,
        source: str,
        target: str,
        interaction_type: str = "access",
        metadata: dict = None,
    ) -> Optional[dict]:
        """
        Record a service interaction and check for anomalies.
        
        Returns anomaly dict if this is a new (non-baseline) edge,
        None otherwise.
        """
        metadata = metadata or {}
        now = datetime.now(timezone.utc)

        # Add to live graph
        if self.live_graph.has_edge(source, target):
            # Update edge count
            edge_data = self.live_graph.edges[source, target]
            edge_data["count"] = edge_data.get("count", 0) + 1
            edge_data["last_seen"] = now.isoformat()
        else:
            self.live_graph.add_edge(
                source, target,
                type=interaction_type,
                first_seen=now.isoformat(),
                last_seen=now.isoformat(),
                count=1,
                metadata=metadata,
            )

        # Check if this edge exists in baseline
        if not self.baseline_graph.has_edge(source, target):
            anomaly = {
                "source": source,
                "target": target,
                "type": interaction_type,
                "first_seen": now.isoformat(),
                "metadata": metadata,
                "severity": self._assess_severity(source, target, interaction_type),
            }
            self.anomalous_edges.append(anomaly)

            logger.warning(
                f"GRAPH ANOMALY: new edge {source} → {target} "
                f"({interaction_type}) — not in baseline"
            )
            return anomaly

        return None

    @staticmethod
    def _assess_severity(source: str, target: str, interaction_type: str) -> str:
        """Assess the severity of an anomalous edge."""
        # Cross-service access from unknown accounts is high severity
        if target == "MDMS" and source not in ("HES", "operator1", "admin"):
            return "high"
        # New operator accounts accessing anything is medium
        if source.startswith("svc_") or source.startswith("OP-"):
            return "medium"
        return "low"

    def get_anomalous_edges(self) -> list[dict]:
        """Return all detected anomalous edges."""
        return list(self.anomalous_edges)

    def get_graph_data(self) -> dict:
        """Return graph data for visualization (D3.js force-directed format)."""
        nodes = set()
        edges = []

        # Add baseline edges
        for u, v, data in self.baseline_graph.edges(data=True):
            nodes.add(u)
            nodes.add(v)
            edges.append({
                "source": u,
                "target": v,
                "type": data.get("type", "baseline"),
                "is_anomalous": False,
                "is_baseline": True,
            })

        # Add live edges
        for u, v, data in self.live_graph.edges(data=True):
            nodes.add(u)
            nodes.add(v)
            is_anomalous = not self.baseline_graph.has_edge(u, v)
            edges.append({
                "source": u,
                "target": v,
                "type": data.get("type", "live"),
                "count": data.get("count", 1),
                "is_anomalous": is_anomalous,
                "is_baseline": False,
                "first_seen": data.get("first_seen"),
            })

        return {
            "nodes": [{"id": n, "type": self._node_type(n)} for n in nodes],
            "edges": edges,
            "anomalous_count": len(self.anomalous_edges),
        }

    @staticmethod
    def _node_type(node_id: str) -> str:
        """Classify a node by type for visualization."""
        if node_id in ("HES", "MDMS"):
            return "service"
        if node_id == "meters":
            return "fleet"
        if node_id.startswith("svc_"):
            return "rogue"
        return "operator"

    def reset(self):
        """Reset the live graph and anomalies."""
        self.live_graph.clear()
        self.anomalous_edges.clear()
