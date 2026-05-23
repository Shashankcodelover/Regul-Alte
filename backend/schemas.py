"""
schemas.py
==========
Pydantic models for the RegulAIte pipeline data structures.
"""

from pydantic import BaseModel
from typing import Optional, List


class Clause(BaseModel):
    id: str
    number: str
    text: str
    section: str = "General"
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    issues: List[str] = []
    plain_english: Optional[str] = None
    rewritten: Optional[str] = None
    negotiation_score: Optional[int] = None
    attacker: Optional[str] = None
    defender: Optional[str] = None
    power_imbalance: Optional[str] = None
    imbalance_level: Optional[str] = None
    flags: List[str] = []


class ContradictionResult(BaseModel):
    clause_a: str
    clause_b: str
    contradiction_type: str  # "MUTUAL_EXCLUSION"|"LOGICAL_DEAD_END"|"CIRCULAR_OBLIGATION"
    description: str
    severity: str
    z3_proof: str
    attacker: str
    defender: str


class CitationResult(BaseModel):
    claim: str
    source_clause_id: str
    source_text_excerpt: str
    confidence_score: float
    verified: bool


class ViolationResult(BaseModel):
    law: str
    clause: str
    description: str
    penalty: str
    severity: str
    attacker: str
    defender: str


class AnalysisResult(BaseModel):
    overall_risk_score: int
    jurisdiction: str
    contract_completeness: int
    party_bias: int
    party_bias_label: str
    summary: str
    clauses: List[Clause]
    contradictions: List[ContradictionResult]
    violations: List[ViolationResult]
    missing_clauses: List[str]
    key_dates: List[str]
    hallucination_rate: float = 0.0
    citation_graph_summary: dict = {}
