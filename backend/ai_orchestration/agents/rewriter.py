"""
rewriter.py — Agent 5: ClauseRewriter
=======================================
Rewrites high-risk clauses (risk_score >= 40) to be balanced and legally sound.

Without API key: uses deterministic template-based rewrites.
With API key: uses Claude for high-quality rewrites, validated.
"""

import asyncio
import logging
import re
from typing import List, Dict, Any

log = logging.getLogger("regulaite.rewriter")

# ── Deterministic rewrite templates ───────────────────────────────────────────
# Applied in order — first match wins. Each entry:
# (detection_regex, rewrite_template_fn)
_DETERMINISTIC_REWRITES = [
    (
        r"\b(client|company|employer|buyer)\s+may\s+terminate\s+(at\s+any\s+time|immediately|without\s+(cause|notice|reason))\b",
        lambda text: (
            "Either party may terminate this Agreement for convenience upon thirty (30) days' "
            "prior written notice to the other party. Either party may terminate immediately "
            "for material breach that remains uncured for fifteen (15) days after written notice "
            "specifying the breach in reasonable detail."
        )
    ),
    (
        r"\b(vendor|supplier)\s+may\s+terminate\s+(at\s+any\s+time|immediately|without\s+(cause|notice|reason))\b",
        lambda text: (
            "Either party may terminate this Agreement for convenience upon thirty (30) days' "
            "prior written notice. Either party may terminate for material breach remaining "
            "uncured for fifteen (15) days after written notice."
        )
    ),
    (
        r"\bindemnif(y|ication).{0,100}regardless\s+of\s+fault\b",
        lambda text: (
            "Each party shall indemnify, defend, and hold harmless the other party from and "
            "against claims, losses, and damages arising out of or related to that party's own "
            "negligence, wilful misconduct, or material breach of this Agreement. Neither party "
            "shall be required to indemnify the other for the other party's own negligence or "
            "wilful misconduct."
        )
    ),
    (
        r"\bindemnif(y|ication)\b",
        lambda text: (
            re.sub(
                r"\b(vendor|supplier|service\s+provider)\s+(shall|agrees?\s+to)\s+indemnif",
                "Each party shall indemnif",
                text, flags=re.IGNORECASE
            ) if re.search(r"\b(vendor|supplier)\s+(shall|agrees?\s+to)\s+indemnif", text, re.IGNORECASE)
            else text + " This indemnification obligation shall be mutual and apply equally to both parties."
        )
    ),
    (
        r"\bwork\s+made\s+for\s+hire\b|whether\s+or\s+not\s+during\s+working\s+hours\b",
        lambda text: (
            "All deliverables and work product specifically created by Vendor for Client under "
            "this Agreement ('Deliverables') shall be the exclusive property of Client upon full "
            "payment of all fees. Vendor retains all rights to its pre-existing intellectual "
            "property, background IP, tools, methodologies, and any work created outside the "
            "scope of this Agreement ('Background IP'). Vendor grants Client a perpetual, "
            "royalty-free licence to use Background IP solely to the extent incorporated into "
            "the Deliverables."
        )
    ),
    (
        r"\bnon[- ]?compete\b.{0,200}\b(perpetual|forever|indefinite)\b",
        lambda text: (
            "Vendor agrees not to directly solicit Client's named customers for a period of "
            "twelve (12) months following termination of this Agreement, limited to the specific "
            "services provided under this Agreement. This restriction shall not prevent Vendor "
            "from engaging in general business activities in the same industry."
        )
    ),
    (
        r"\bnon[- ]?compete\b",
        lambda text: re.sub(
            r"\b(perpetual|forever|indefinite|no\s+time\s+limit)\b",
            "twelve (12) months",
            text, flags=re.IGNORECASE
        )
    ),
    (
        r"\bnon[- ]?refundable\b",
        lambda text: (
            text.replace("non-refundable", "refundable within 30 days if services are not delivered as specified")
                .replace("non refundable", "refundable within 30 days if services are not delivered as specified")
        )
    ),
    (
        r"\bno\s+(equivalent\s+)?cap\s+(is\s+)?placed\b|no\s+limit\s+on\s+(vendor|supplier)'?s?\s+liability\b",
        lambda text: (
            "Each party's aggregate liability arising out of or related to this Agreement, "
            "whether in contract, tort, or otherwise, shall not exceed the total fees paid or "
            "payable by Client to Vendor in the twelve (12) months immediately preceding the "
            "event giving rise to the claim. This limitation shall not apply to breaches of "
            "confidentiality, wilful misconduct, or fraud."
        )
    ),
    (
        r"\bsole\s+discretion\b",
        lambda text: re.sub(
            r"\b(at\s+)?(its|their|our|the\s+\w+)'?s?\s+sole\s+discretion\b",
            "acting reasonably and in good faith",
            text, flags=re.IGNORECASE
        )
    ),
    (
        r"\bwithout\s+notice\b",
        lambda text: re.sub(
            r"\bwithout\s+notice\b",
            "upon fourteen (14) days' written notice",
            text, flags=re.IGNORECASE
        )
    ),
    (
        r"\bauto[- ]?renew(al|s)?\b",
        lambda text: (
            text + " Either party may prevent automatic renewal by providing written notice of "
            "non-renewal at least sixty (60) days before the end of the then-current term."
        ) if "prevent" not in text.lower() and "cancel" not in text.lower() else text
    ),
    (
        r"\bprocess(ing)?\s+personal\s+data\b",
        lambda text: (
            text + " All processing of personal data shall be conducted in accordance with "
            "applicable data protection laws including GDPR and the DPDP Act 2023, with a "
            "valid lawful basis documented prior to processing. A Data Processing Agreement "
            "shall be executed between the parties."
        ) if "gdpr" not in text.lower() and "lawful basis" not in text.lower() else text
    ),
]

_REWRITE_PROMPT = """You are a legal contract drafter. Rewrite the following high-risk contract clause to be balanced, fair, and legally sound.

CLAUSE NUMBER: {number}
ORIGINAL CLAUSE:
{text}

IDENTIFIED ISSUES:
{issues}

ATTACKER (who this clause hurts): {attacker}
DEFENDER (who this clause protects): {defender}

Requirements:
1. Remove one-sided language (sole discretion, without notice, regardless of fault)
2. Make obligations mutual where appropriate
3. Add reasonable time limits and notice periods
4. Preserve the commercial intent
5. Keep it concise and professionally worded

Return ONLY the rewritten clause text — no explanation, no preamble, no JSON."""


def _deterministic_rewrite(clause: Dict[str, Any]) -> str:
    """Apply deterministic template rewrites for known high-risk patterns."""
    text = clause.get("text", "")
    for pattern, rewrite_fn in _DETERMINISTIC_REWRITES:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            try:
                result = rewrite_fn(text)
                if result and result != text and len(result) > 20:
                    return result
            except Exception:
                continue
    return ""  # no deterministic rewrite available


def _validate_rewrite(original: str, rewritten: str) -> bool:
    """Validate that the rewrite is an improvement."""
    if not rewritten or len(rewritten) < 30:
        return False
    if rewritten == original:
        return False
    # Check for unbalanced problematic phrases
    problematic = [r"\bsole\s+discretion\b", r"\bwithout\s+notice\b", r"\bregardless\s+of\s+fault\b"]
    for phrase in problematic:
        if re.search(phrase, rewritten, re.IGNORECASE):
            ctx = rewritten.lower()
            if "either party" not in ctx and "mutual" not in ctx and "both parties" not in ctx:
                return False
    return True


async def _rewrite_clause_with_claude(
    clause: Dict[str, Any],
    client,
    model: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """Rewrite a single clause using Claude."""
    async with semaphore:
        original = clause.get("text", "")
        try:
            issues_text = "\n".join(f"- {i}" for i in clause.get("issues", [])) or "- General risk identified"
            prompt = _REWRITE_PROMPT.format(
                number=clause.get("number", "?"),
                text=original[:800],
                issues=issues_text,
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
            rewritten = message.content[0].text.strip()

            if _validate_rewrite(original, rewritten):
                clause["rewritten"] = rewritten
            else:
                # Fall back to deterministic
                det = _deterministic_rewrite(clause)
                clause["rewritten"] = det if det else original

        except Exception as exc:
            log.warning(f"Rewriter failed for clause {clause.get('number')}: {exc}")
            det = _deterministic_rewrite(clause)
            clause["rewritten"] = det if det else original

        return clause


async def rewrite_clauses(
    clauses: List[Dict[str, Any]],
    api_key: str = "",
    model: str = "claude-sonnet-4-20250514",
) -> List[Dict[str, Any]]:
    """
    Main entry point for Agent 5.
    Always produces rewrites — deterministic when no API key, Claude when available.
    """
    # Step 1: Apply deterministic rewrites to ALL high-risk clauses first
    for clause in clauses:
        score = clause.get("risk_score", 0)
        if score < 40:
            clause["rewritten"] = clause.get("text", "")
        else:
            det = _deterministic_rewrite(clause)
            clause["rewritten"] = det if det else clause.get("text", "")

    # Step 2: Claude refinement for high-risk clauses (if API key available)
    if api_key:
        high_risk = [c for c in clauses if c.get("risk_score", 0) >= 40]
        log.info(f"ClauseRewriter: refining {len(high_risk)} clauses with Claude.")
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            semaphore = asyncio.Semaphore(4)
            tasks = [_rewrite_clause_with_claude(c, client, model, semaphore) for c in high_risk]
            await asyncio.gather(*tasks)
        except ImportError:
            log.warning("anthropic not installed — using deterministic rewrites only.")
        except Exception as exc:
            log.warning(f"ClauseRewriter Claude batch failed: {exc}")
    else:
        log.info(f"ClauseRewriter: no API key — using deterministic rewrites for {len([c for c in clauses if c.get('risk_score',0)>=40])} high-risk clauses.")

    log.info(f"ClauseRewriter: done. {len([c for c in clauses if c.get('rewritten','') != c.get('text','')])} clauses rewritten.")
    return clauses
