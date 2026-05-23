"""Agents package — the 5 AI agents in the orchestration pipeline."""
from .extractor import extract_clauses
from .risk_scorer import score_clauses
from .contradiction import detect_contradictions
from .compliance import check_compliance
from .rewriter import rewrite_clauses

__all__ = [
    "extract_clauses",
    "score_clauses",
    "detect_contradictions",
    "check_compliance",
    "rewrite_clauses",
]
