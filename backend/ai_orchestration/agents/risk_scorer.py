"""
risk_scorer.py — Agent 2: RiskScorer
======================================
Scores each clause 0-100 for legal risk AND identifies:
  - attacker: who this clause hurts
  - defender: who this clause protects
  - power_imbalance: how one-sided the clause is

Step 1: Deterministic pre-scoring + attacker/defender (no API)
Step 2: Claude refinement for clauses with base_score >= 40
Step 3: final_score = max(base_score, claude_score)
"""

import asyncio
import json
import logging
import re
from typing import List, Dict, Any

log = logging.getLogger("regulaite.risk_scorer")

from ..tools.legal_patterns import pre_score_clause
from ..tools.attacker_defender import identify_attacker_defender

_RISK_LEVEL_MAP = [
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0,  "low"),
]

def _risk_level(score: int) -> str:
    for threshold, level in _RISK_LEVEL_MAP:
        if score >= threshold:
            return level
    return "low"


_SCORE_PROMPT = """You are a legal risk analyst specialising in contract power dynamics.
Analyse this contract clause and return ONLY valid JSON.

CLAUSE NUMBER: {number}
CLAUSE TEXT:
{text}

PRE-DETECTED ISSUES (from pattern matching):
{issues}

PRE-IDENTIFIED ATTACKER: {attacker}
PRE-IDENTIFIED DEFENDER: {defender}

Return ONLY this JSON (no markdown, no preamble):
{{
  "risk_score": <integer 0-100>,
  "plain_english": "<one sentence: what this clause means in plain English>",
  "issues": ["<specific legal issue 1>", "<specific legal issue 2>"],
  "negotiation_score": <integer 0-100, how negotiable is this clause>,
  "attacker": "<who this clause hurts — be specific about which party and why>",
  "defender": "<who this clause protects — be specific about which party and why>",
  "power_imbalance": "<one sentence describing the power imbalance: HIGH/MEDIUM/LOW/BALANCED and why>"
}}

Scoring guide: 0-24=low risk, 25-49=medium, 50-74=high, 75-100=critical.
negotiation_score: 0=non-negotiable (statutory), 100=highly negotiable.
For attacker/defender: identify the actual party names if visible (Client, Vendor, Employee, etc.)"""


async def _score_clause_with_claude(
    clause: Dict[str, Any],
    client,
    model: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """Call Claude to refine scoring + attacker/defender for a single clause."""
    async with semaphore:
        try:
            prompt = _SCORE_PROMPT.format(
                number=clause.get("number", "?"),
                text=clause.get("text", "")[:800],
                issues="\n".join(f"- {r}" for r in clause.get("_pre_reasons", [])) or "None detected",
                attacker=clause.get("attacker", "Unknown"),
                defender=clause.get("defender", "Unknown"),
            )

            def _call():
                return client.messages.create(
                    model=model,
                    max_tokens=600,
                    messages=[{"role": "user", "content": prompt}],
                )

            message = await asyncio.to_thread(_call)
            raw = message.content[0].text.strip()
            raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.MULTILINE)
            raw = re.sub(r"\s*```$", "", raw, flags=re.MULTILINE)
            data = json.loads(raw.strip())

            claude_score = int(data.get("risk_score", clause["_base_score"]))
            final_score = max(clause["_base_score"], claude_score)

            clause["risk_score"] = min(final_score, 100)
            clause["risk_level"] = _risk_level(clause["risk_score"])
            clause["plain_english"] = data.get("plain_english", clause.get("plain_english", ""))
            clause["issues"] = data.get("issues", clause.get("_pre_reasons", []))
            clause["negotiation_score"] = int(data.get("negotiation_score", 50))

            # Claude may refine attacker/defender with actual party names
            if data.get("attacker"):
                clause["attacker"] = data["attacker"]
            if data.get("defender"):
                clause["defender"] = data["defender"]
            if data.get("power_imbalance"):
                clause["power_imbalance"] = data["power_imbalance"]

        except Exception as exc:
            log.warning(f"Claude scoring failed for clause {clause.get('number')}: {exc}")
            clause["risk_score"] = clause["_base_score"]
            clause["risk_level"] = _risk_level(clause["_base_score"])
            clause["plain_english"] = clause.get("plain_english", f"Clause {clause.get('number', '?')} — see issues.")
            clause["issues"] = clause.get("_pre_reasons", [])
            clause["negotiation_score"] = 50

        return clause


async def score_clauses(
    clauses: List[Dict[str, Any]],
    api_key: str = "",
    model: str = "claude-sonnet-4-20250514",
) -> List[Dict[str, Any]]:
    """
    Main entry point for Agent 2.

    Returns clauses with these fields added:
      risk_score, risk_level, issues, plain_english, negotiation_score,
      attacker, defender, power_imbalance, imbalance_level, id
    """
    scored: List[Dict[str, Any]] = []

    # ── Step 1: Deterministic pre-scoring + attacker/defender for ALL clauses ──
    for clause in clauses:
        text = clause.get("text", "")
        pre = pre_score_clause(text)
        ad = identify_attacker_defender(text, pre["flags"])

        clause["_base_score"] = pre["base_score"]
        clause["_pre_flags"] = pre["flags"]
        clause["_pre_reasons"] = pre["reasons"]

        # Risk fields
        clause["risk_score"] = pre["base_score"]
        clause["risk_level"] = _risk_level(pre["base_score"])
        clause["issues"] = pre["reasons"]
        clause["negotiation_score"] = max(0, 100 - pre["base_score"])

        # Attacker / Defender fields (deterministic)
        clause["attacker"] = ad["attacker"]
        clause["defender"] = ad["defender"]
        clause["power_imbalance"] = ad["power_imbalance"]
        clause["imbalance_level"] = ad["imbalance_level"]

        # Plain English fallback
        if pre["reasons"]:
            clause["plain_english"] = pre["reasons"][0]
        else:
            clause["plain_english"] = f"Clause {clause.get('number', '?')} — standard contract provision."

        # Build clause id
        num = clause.get("number", "1")
        safe_num = re.sub(r"[^a-zA-Z0-9]", "_", str(num))
        clause["id"] = f"clause_{safe_num}"

        scored.append(clause)

    # ── Step 2: Claude refinement for high-risk clauses ────────────────────
    if api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            high_risk = [c for c in scored if c["_base_score"] >= 40]
            log.info(f"RiskScorer: sending {len(high_risk)}/{len(scored)} clauses to Claude.")

            semaphore = asyncio.Semaphore(5)
            tasks = [
                _score_clause_with_claude(c, client, model, semaphore)
                for c in high_risk
            ]
            await asyncio.gather(*tasks)

        except ImportError:
            log.warning("anthropic not installed — using deterministic scores only.")
        except Exception as exc:
            log.warning(f"RiskScorer Claude batch failed: {exc}")
    else:
        log.info("RiskScorer: no API key — using deterministic attacker/defender analysis only.")

    # ── Step 3: Clean up internal fields ──────────────────────────────────
    for clause in scored:
        clause.pop("_base_score", None)
        clause.pop("_pre_flags", None)
        clause.pop("_pre_reasons", None)

    log.info(f"RiskScorer: scored {len(scored)} clauses with attacker/defender analysis.")
    return scored
