"""
compliance.py — Agent 4: ComplianceChecker
============================================
Detects GDPR, Indian law, IP, and labour law violations.

Step 1: Deterministic regex patterns (legal_patterns.py)
Step 2: Claude enrichment with penalty amounts + missed violations
"""

import asyncio
import json
import logging
import re
from typing import List, Dict, Any

log = logging.getLogger("regulaite.compliance")

from ..tools.legal_patterns import detect_legal_violations


_COMPLIANCE_PROMPT = """You are a legal compliance expert. Review these contract clauses for violations of:
- GDPR (Arts. 6, 7, 13, 25, 28, 32, 33, 44-49)
- Indian Contract Act (S.27, S.74)
- Indian Copyright Act (S.17, S.57)
- Industrial Disputes Act (S.25F)
- DPDP Act 2023 (S.7, S.8, S.12)
- RBI usury guidelines

JURISDICTION: {jurisdiction}

CLAUSES:
{clauses_text}

ALREADY DETECTED VIOLATIONS:
{already_found}

Return ONLY valid JSON (no markdown):
{{
  "violations": [
    {{
      "law": "<exact law name and article/section>",
      "clause": "<clause number>",
      "description": "<specific violation details with exact legal reference>",
      "penalty": "<specific penalty amount or consequence>"
    }}
  ]
}}

Only report violations not already in the ALREADY DETECTED list.
Return empty array if no additional violations found."""


async def check_compliance(
    clauses: List[Dict[str, Any]],
    jurisdiction: str = "Unknown",
    api_key: str = "",
    model: str = "claude-sonnet-4-20250514",
) -> List[Dict[str, Any]]:
    """
    Main entry point for Agent 4.

    Args:
        clauses: scored clause dicts from Agent 2
        jurisdiction: detected jurisdiction string
        api_key: Anthropic API key
        model: Claude model name

    Returns:
        list of {law, clause, description, penalty}
    """
    # Step 1: Deterministic pattern matching
    violations = detect_legal_violations(clauses)
    log.info(f"ComplianceChecker: patterns found {len(violations)} violations.")

    # Remove internal severity field for output
    clean_violations = []
    for v in violations:
        clean_violations.append({
            "law": v["law"],
            "clause": v["clause"],
            "description": v["description"],
            "penalty": v["penalty"],
        })

    # Step 2: Claude enrichment
    if api_key and clauses:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            sample = clauses[:15]
            clauses_text = "\n\n".join(
                f"[{c.get('number', '?')}] {c.get('text', '')[:300]}"
                for c in sample
            )

            already_found = "\n".join(
                f"- {v['law']} in Clause {v['clause']}: {v['description'][:80]}"
                for v in clean_violations
            ) or "None"

            prompt = _COMPLIANCE_PROMPT.format(
                jurisdiction=jurisdiction,
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

            claude_violations = data.get("violations", [])
            log.info(f"ComplianceChecker: Claude found {len(claude_violations)} additional violations.")

            # Deduplicate by law+clause
            existing_keys = {(v["law"], v["clause"]) for v in clean_violations}
            for cv in claude_violations:
                key = (cv.get("law", ""), cv.get("clause", ""))
                if key not in existing_keys:
                    clean_violations.append({
                        "law": cv.get("law", "Unknown Law"),
                        "clause": cv.get("clause", "?"),
                        "description": cv.get("description", ""),
                        "penalty": cv.get("penalty", "See applicable law"),
                    })
                    existing_keys.add(key)

        except Exception as exc:
            log.warning(f"ComplianceChecker Claude call failed: {exc}")

    log.info(f"ComplianceChecker: returning {len(clean_violations)} total violations.")
    return clean_violations
