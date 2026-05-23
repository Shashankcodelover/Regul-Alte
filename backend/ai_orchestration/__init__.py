"""
AI Orchestration Package
========================
Multi-agent pipeline for legal contract analysis.

Usage:
    from ai_orchestration.pipeline import run_pipeline
    result = await run_pipeline(contract_text, api_key)
"""
from .pipeline import run_pipeline, get_stored_clauses

__all__ = ["run_pipeline", "get_stored_clauses"]
