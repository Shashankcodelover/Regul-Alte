"""
citation_graph.py
=================
NetworkX graph tracking which agent claims cite which clauses.
Falls back gracefully if networkx is not installed.
"""

import logging
from typing import Dict, Any, List, Optional

log = logging.getLogger("regulaite.memory.citation_graph")

try:
    import networkx as nx
    NX_AVAILABLE = True
    log.info("CitationGraph: networkx is available.")
except ImportError:
    NX_AVAILABLE = False
    log.warning("CitationGraph: networkx not installed — using dict-based fallback.")


class CitationGraph:
    """
    Tracks which agent claims cite which clauses.

    Nodes: agent names and clause IDs
    Edges: (agent, clause_id) with attributes {claim, confidence, verified}

    Falls back to a simple dict if networkx is not installed.
    """

    def __init__(self):
        if NX_AVAILABLE:
            self._graph = nx.DiGraph()
        else:
            self._graph = None
        # Fallback storage
        self._citations: List[Dict[str, Any]] = []
        self._agent_stats: Dict[str, Dict[str, int]] = {}

    def add_citation(
        self,
        agent_name: str,
        claim: str,
        clause_id: str,
        confidence: float,
        verified: bool = False,
    ) -> None:
        """
        Record that agent_name made a claim citing clause_id.

        Args:
            agent_name: name of the agent making the claim
            claim: the claim text
            clause_id: the clause being cited
            confidence: similarity/confidence score (0.0-1.0)
            verified: whether the claim was verified against the clause
        """
        citation = {
            "agent": agent_name,
            "claim": claim[:200],
            "clause_id": clause_id,
            "confidence": confidence,
            "verified": verified,
        }
        self._citations.append(citation)

        # Update agent stats
        if agent_name not in self._agent_stats:
            self._agent_stats[agent_name] = {"total": 0, "verified": 0, "unverified": 0}
        self._agent_stats[agent_name]["total"] += 1
        if verified:
            self._agent_stats[agent_name]["verified"] += 1
        else:
            self._agent_stats[agent_name]["unverified"] += 1

        # Add to networkx graph if available
        if NX_AVAILABLE and self._graph is not None:
            try:
                if not self._graph.has_node(agent_name):
                    self._graph.add_node(agent_name, node_type="agent")
                if not self._graph.has_node(clause_id):
                    self._graph.add_node(clause_id, node_type="clause")
                self._graph.add_edge(
                    agent_name, clause_id,
                    claim=claim[:200],
                    confidence=confidence,
                    verified=verified,
                )
            except Exception as exc:
                log.warning(f"CitationGraph: networkx add_edge failed: {exc}")

    def get_summary(self) -> Dict[str, Any]:
        """
        Return a summary of all citations.

        Returns:
            {
                total_citations: int,
                verified_count: int,
                hallucination_rate: float,
                agent_stats: {agent_name: {total, verified, unverified}},
                most_cited_clauses: [{clause_id, citation_count}],
            }
        """
        total = len(self._citations)
        verified_count = sum(1 for c in self._citations if c.get("verified"))
        unverified_count = total - verified_count
        hallucination_rate = round(unverified_count / total, 4) if total > 0 else 0.0

        # Count citations per clause
        clause_counts: Dict[str, int] = {}
        for c in self._citations:
            cid = c.get("clause_id", "?")
            clause_counts[cid] = clause_counts.get(cid, 0) + 1

        most_cited = sorted(
            [{"clause_id": k, "citation_count": v} for k, v in clause_counts.items()],
            key=lambda x: x["citation_count"],
            reverse=True,
        )[:5]

        return {
            "total_citations": total,
            "verified_count": verified_count,
            "unverified_count": unverified_count,
            "hallucination_rate": hallucination_rate,
            "agent_stats": dict(self._agent_stats),
            "most_cited_clauses": most_cited,
        }

    def get_hallucination_rate(self) -> float:
        """Return the hallucination rate (fraction of unverified claims)."""
        return self.get_summary()["hallucination_rate"]

    def get_citations_for_clause(self, clause_id: str) -> List[Dict[str, Any]]:
        """Return all citations for a specific clause."""
        return [c for c in self._citations if c.get("clause_id") == clause_id]

    def get_citations_by_agent(self, agent_name: str) -> List[Dict[str, Any]]:
        """Return all citations made by a specific agent."""
        return [c for c in self._citations if c.get("agent") == agent_name]
