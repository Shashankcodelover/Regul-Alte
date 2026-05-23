"""
bridge.py
=========
MemoryBridge — connects the Logic + Memory subsystems to the agent pipeline.

Indexes clauses in the RAG store and verifies agent claims against them,
tracking all citations in the CitationGraph for hallucination detection.
"""

import logging
from typing import List, Dict, Any

from .rag import InMemoryRAG
from .citation_graph import CitationGraph

log = logging.getLogger("regulaite.memory.bridge")


class MemoryBridge:
    """
    Connects logic + memory to the agent pipeline.

    Usage:
        bridge = MemoryBridge(clauses)
        result = bridge.verify_claim("risk_scorer", "This clause limits liability")
        results = bridge.verify_batch("risk_scorer", ["claim1", "claim2"])
        summary = bridge.get_summary()
    """

    def __init__(self, clauses: List[Dict[str, Any]]):
        """
        Initialize the bridge by indexing clauses in the RAG store.

        Args:
            clauses: list of clause dicts from the pipeline
        """
        self._rag = InMemoryRAG()
        self._graph = CitationGraph()
        self._clauses = clauses

        count = self._rag.index(clauses)
        log.info(f"MemoryBridge: indexed {count} clauses in RAG store.")

    def verify_claim(self, agent_name: str, claim: str) -> Dict[str, Any]:
        """
        Verify a single agent claim against the indexed clauses.

        Args:
            agent_name: name of the agent making the claim
            claim: the claim text to verify

        Returns:
            CitationResult-compatible dict:
            {claim, source_clause_id, source_text_excerpt, confidence_score, verified}
        """
        if not claim or not claim.strip():
            return {
                "claim": claim,
                "source_clause_id": "?",
                "source_text_excerpt": "",
                "confidence_score": 0.0,
                "verified": False,
            }

        result = self._rag.verify(claim)

        # Record in citation graph
        self._graph.add_citation(
            agent_name=agent_name,
            claim=claim,
            clause_id=result.get("source_clause_id", "?"),
            confidence=result.get("confidence_score", 0.0),
            verified=result.get("verified", False),
        )

        return {
            "claim": claim,
            "source_clause_id": result.get("source_clause_id", "?"),
            "source_text_excerpt": result.get("source_text_excerpt", ""),
            "confidence_score": result.get("confidence_score", 0.0),
            "verified": result.get("verified", False),
        }

    def verify_batch(
        self, agent_name: str, claims: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Verify a batch of agent claims.

        Args:
            agent_name: name of the agent making the claims
            claims: list of claim texts

        Returns:
            list of CitationResult-compatible dicts
        """
        results = []
        for claim in claims:
            result = self.verify_claim(agent_name, claim)
            results.append(result)
        log.info(
            f"MemoryBridge: verified {len(results)} claims for agent '{agent_name}'. "
            f"Verified: {sum(1 for r in results if r['verified'])}/{len(results)}"
        )
        return results

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Search for the most relevant clauses for a query.

        Args:
            query: search query text
            top_k: number of results to return

        Returns:
            list of {clause, similarity} dicts
        """
        return self._rag.search(query, top_k=top_k)

    def get_summary(self) -> Dict[str, Any]:
        """
        Return a combined summary of RAG indexing and citation graph stats.

        Returns:
            {
                total_citations, verified_count, hallucination_rate,
                agent_stats, most_cited_clauses, clauses_indexed
            }
        """
        graph_summary = self._graph.get_summary()
        graph_summary["clauses_indexed"] = len(self._clauses)
        return graph_summary

    def get_hallucination_rate(self) -> float:
        """Return the current hallucination rate."""
        return self._graph.get_hallucination_rate()
