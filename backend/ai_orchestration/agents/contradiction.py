"""
contradiction.py — Agent 3: ContradictionDetector
===================================================
Finds pairs of clauses that logically contradict each other.

Step 1: Z3 SMT solver formal proof (deterministic)
Step 2: Claude semantic contradiction detection (if API key)
Step 3: Merge + deduplicate
"""

import asyncio
import json
import logging
import re
from typing import List, Dict, Any

log = logging.getLogger("regulaite.contradiction")

from ..tools.z3_checker import check_contradictions as z3_check, check_deterministic_contradictions


_CONTRADICTION_PROMPT = """You are a legal contract analyst specialising in finding logical contradictions.

Below are contract clauses. Find ALL pairs of clauses that directly contradict each other — where complying with one clause makes it impossible or illegal to comply with the other.

CLAUSES:
{clauses_text}

ALREADY FOUND BY FORMAL ANALYSIS:
{already_found}

Return ONLY valid JSON (no markdown):
{{
  "contradictions": [
    {{
      "clause_a": "<clause number>",
      "clause_b": "<clause number>",
      "description": "<clear explanation of what contradicts what and why>",
      "severity": "<Critical|High|Medium>"
    }}
  ]
}}

Focus on: data retention vs destruction, payment terms conflicts, termination notice conflicts,
governing law vs arbitration venue, exclusivity vs non-exclusive grants, liability cap conflicts.
Return empty array if no additional contradictions found."""


async def detect_contradictions(
    clauses: List[Dict[str, Any]],
    api_key: str = "",
    model: str = "claude-sonnet-4-20250514",
) -> List[Dict[str, Any]]:
    """
    Main entry point for Agent 3.

    Args:
        clauses: scored clause dicts from Agent 2
        api_key: Anthropic API key
        model: Claude model name

    Returns:
        list of {clause_a, clause_b, description, severity}
    """
    results: List[Dict[str, Any]] = []

    # Step 1: Z3 formal contradiction detection
    z3_results = z3_check(clauses)
    log.info(f"ContradictionDetector: Z3 found {len(z3_results)} formal contradictions.")

    # Step 1b: Deterministic pattern-based contradiction detection
    det_results = check_deterministic_contradictions(clauses)
    log.info(f"ContradictionDetector: Deterministic engine found {len(det_results)} contradictions.")

    # Merge Z3 + deterministic, deduplicate by clause pair
    seen_pairs = set()
    for z in z3_results + det_results:
        pair = tuple(sorted([str(z["clause_a"]), str(z["clause_b"])]))
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            results.append({
                "clause_a": z["clause_a"],
                "clause_b": z["clause_b"],
                "description": z.get("description_hint", z.get("description", "")),
                "severity": z.get("severity_hint", z.get("severity", "Medium")),
                "_source": "deterministic",
            })

    # Step 2: Claude semantic detection
    if api_key and len(clauses) >= 2:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            # Build clauses text (limit to first 20 clauses to stay within token budget)
            sample = clauses[:20]
            clauses_text = "\n\n".join(
                f"[{c.get('number', '?')}] {c.get('text', '')[:300]}"
                for c in sample
            )

            already_found = "\n".join(
                f"- Clause {r['clause_a']} vs Clause {r['clause_b']}: {r['description'][:100]}"
                for r in results
            ) or "None"

            prompt = _CONTRADICTION_PROMPT.format(
                clauses_text=clauses_text,
                already_found=already_found,
            )

            def _call():
                return client.messages.create(
                    model=model,
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )

            message = await asyncio.to_thread(_call)
            raw = message.content[0].text.strip()
            raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.MULTILINE)
            raw = re.sub(r"\s*```$", "", raw, flags=re.MULTILINE)
            data = json.loads(raw.strip())

            claude_contradictions = data.get("contradictions", [])
            log.info(f"ContradictionDetector: Claude found {len(claude_contradictions)} additional contradictions.")

            # Merge — deduplicate by clause pair
            existing_pairs = {
                (r["clause_a"], r["clause_b"]) for r in results
            } | {
                (r["clause_b"], r["clause_a"]) for r in results
            }

            for c in claude_contradictions:
                pair = (c.get("clause_a", ""), c.get("clause_b", ""))
                rev_pair = (pair[1], pair[0])
                if pair not in existing_pairs and rev_pair not in existing_pairs:
                    results.append({
                        "clause_a": c.get("clause_a", "?"),
                        "clause_b": c.get("clause_b", "?"),
                        "description": c.get("description", ""),
                        "severity": c.get("severity", "Medium"),
                        "_source": "claude",
                    })
                    existing_pairs.add(pair)

        except Exception as exc:
            log.warning(f"ContradictionDetector Claude call failed: {exc}")

    # Step 3: Enrich Z3 descriptions with Claude if API available
    if api_key:
        for r in results:
            if r.get("_source") == "z3" and not r["description"].startswith("Clause"):
                pass  # description already set by z3_checker

    # Clean internal fields
    for r in results:
        r.pop("_source", None)

    log.info(f"ContradictionDetector: returning {len(results)} total contradictions.")
    return results
