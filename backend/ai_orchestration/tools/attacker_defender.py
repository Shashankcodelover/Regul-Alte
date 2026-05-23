"""
attacker_defender.py
====================
Deterministic engine to identify WHO a clause hurts (attacker's target)
and WHO it protects (defender) for every clause type.

This is the core of the orchestrator's power-imbalance analysis.
No LLM needed — pure pattern matching against known clause archetypes.
"""

import re
from typing import Dict, Any, List, Tuple

# ── Clause archetype map ───────────────────────────────────────────────────────
# Each entry: (regex, attacker_label, defender_label, power_imbalance, imbalance_level)
# imbalance_level: "HIGH", "MEDIUM", "LOW", "BALANCED"
ATTACKER_DEFENDER_PATTERNS: List[Tuple] = [

    # ── Termination ────────────────────────────────────────────────────────
    (
        r"\b(client|company|employer|buyer)\s+may\s+terminate\s+(at\s+any\s+time|immediately|without\s+(cause|notice|reason))\b",
        "Vendor / Service Provider — can be cut off with zero warning, no time to find alternative, no compensation",
        "Client / Buyer — maximum flexibility to exit at any time for any reason",
        "HIGH — only Client has this right; Vendor has no equivalent exit right",
        "HIGH",
    ),
    (
        r"\b(vendor|supplier|service\s+provider|seller)\s+may\s+terminate\s+(at\s+any\s+time|immediately|without\s+(cause|notice|reason))\b",
        "Client / Buyer — can lose service with zero warning, no time to find alternative",
        "Vendor / Supplier — protected from being locked into unprofitable contracts",
        "HIGH — only Vendor has this right; Client has no equivalent protection",
        "HIGH",
    ),
    (
        r"\bterminate\s+(at\s+any\s+time|immediately|without\s+(cause|notice|reason))\b",
        "Weaker party (typically the party that did not draft this clause)",
        "Drafting party — retains unilateral exit right",
        "HIGH — unilateral termination right with no reciprocal obligation",
        "HIGH",
    ),
    (
        r"\b(\d+)[- ]day\s+notice\b.{0,100}\b(\d+)[- ]day\s+notice\b",
        "Party with longer notice period — operationally disadvantaged",
        "Party with shorter notice period — greater flexibility",
        "MEDIUM — asymmetric notice periods create operational imbalance",
        "MEDIUM",
    ),

    # ── Liability ──────────────────────────────────────────────────────────
    (
        r"\bno\s+(limit|cap)\s+on\s+(vendor|supplier|service\s+provider)'?s?\s+liability\b",
        "Vendor / Supplier — faces unlimited financial exposure",
        "Client / Buyer — fully protected against any loss amount",
        "HIGH — Client liability capped but Vendor liability uncapped; extreme imbalance",
        "HIGH",
    ),
    (
        r"\b(client|buyer|company)'?s?\s+(total\s+)?(aggregate\s+)?liability.{0,50}(shall\s+not\s+exceed|is\s+limited\s+to|capped\s+at)\b",
        "Vendor / Supplier — if Client causes damage, recovery is severely capped",
        "Client / Buyer — maximum financial exposure is strictly limited",
        "HIGH — one-sided liability cap protects only one party",
        "HIGH",
    ),
    (
        r"\b(vendor|supplier)'?s?\s+(total\s+)?(aggregate\s+)?liability.{0,50}(shall\s+not\s+exceed|is\s+limited\s+to|capped\s+at)\b",
        "Client / Buyer — if Vendor causes damage, recovery is severely capped",
        "Vendor / Supplier — maximum financial exposure is strictly limited",
        "HIGH — one-sided liability cap protects only Vendor",
        "HIGH",
    ),
    (
        r"\bin\s+no\s+event\s+shall\b",
        "Party seeking damages — recovery may be blocked entirely",
        "Party invoking the cap — protected from consequential damages",
        "MEDIUM — consequential damages waiver limits recourse",
        "MEDIUM",
    ),

    # ── Indemnification ────────────────────────────────────────────────────
    (
        r"\b(vendor|supplier|service\s+provider)\s+(shall|agrees?\s+to)\s+indemnif(y|ication).{0,100}regardless\s+of\s+fault\b",
        "Vendor / Supplier — must pay even for Client's own negligence",
        "Client / Buyer — fully insulated from all liability including self-caused harm",
        "CRITICAL — 'regardless of fault' forces Vendor to indemnify Client's own wrongdoing",
        "HIGH",
    ),
    (
        r"\b(vendor|supplier|service\s+provider)\s+(shall|agrees?\s+to)\s+indemnif(y|ication)\b",
        "Vendor / Supplier — bears indemnification burden",
        "Client / Buyer — protected against third-party claims",
        "MEDIUM — check if indemnification is mutual",
        "MEDIUM",
    ),
    (
        r"\bindemnif(y|ication).{0,50}(mutual|both\s+parties|each\s+party)\b",
        "Neither party — mutual indemnification is balanced",
        "Both parties — each protected against the other's actions",
        "BALANCED — mutual indemnification is market standard",
        "LOW",
    ),

    # ── Intellectual Property ──────────────────────────────────────────────
    (
        r"\bwork\s+made\s+for\s+hire\b",
        "Vendor / Creator — loses all IP rights including pre-existing work",
        "Client / Employer — owns all created work product",
        "HIGH — work-for-hire strips creator of all IP ownership",
        "HIGH",
    ),
    (
        r"\bwhether\s+or\s+not\s+during\s+working\s+hours\b",
        "Vendor / Employee — off-hours personal projects may be captured",
        "Client / Employer — maximum IP capture including side projects",
        "CRITICAL — captures IP created outside work hours with personal resources",
        "HIGH",
    ),
    (
        r"\ball\s+(inventions?|discoveries|improvements|work\s+product).{0,50}(exclusive\s+property|belongs?\s+to|owned\s+by)\s+(client|employer|company)\b",
        "Vendor / Employee — loses all IP including potentially pre-existing IP",
        "Client / Employer — owns all created IP",
        "HIGH — broad IP assignment may capture pre-existing background IP",
        "HIGH",
    ),
    (
        r"\bvendor\s+retains?\s+(all\s+)?(background\s+)?ip\b",
        "Client — limited to license, cannot own the underlying technology",
        "Vendor — retains ownership of all pre-existing and background IP",
        "MEDIUM — Vendor retains IP; Client gets license only",
        "MEDIUM",
    ),

    # ── Non-compete / Non-solicit ──────────────────────────────────────────
    (
        r"\bnon[- ]?compete\b.{0,200}\b(perpetual|forever|indefinite|no\s+time\s+limit)\b",
        "Employee / Vendor — career and business permanently restricted",
        "Employer / Client — protected from competition indefinitely",
        "CRITICAL — perpetual non-compete is void under Indian Contract Act S.27",
        "HIGH",
    ),
    (
        r"\bnon[- ]?compete\b",
        "Employee / Vendor — restricted from working in their field",
        "Employer / Client — protected from direct competition",
        "HIGH — non-compete restricts livelihood; check duration and scope",
        "HIGH",
    ),
    (
        r"\bnon[- ]?solicit(ation)?\b",
        "Employee / Vendor — cannot approach former clients or colleagues",
        "Employer / Client — protected from talent and client poaching",
        "MEDIUM — non-solicitation limits post-contract opportunities",
        "MEDIUM",
    ),

    # ── Auto-renewal ───────────────────────────────────────────────────────
    (
        r"\bauto[- ]?renew(al|s)?\b.{0,200}\b(without\s+notice|unless\s+cancelled|automatically)\b",
        "Client / Subscriber — locked into renewal without active consent",
        "Vendor / Provider — guaranteed revenue continuation",
        "HIGH — auto-renewal without adequate notice traps the weaker party",
        "HIGH",
    ),
    (
        r"\bauto[- ]?renew(al|s)?\b",
        "Client / Subscriber — may be locked in if cancellation window missed",
        "Vendor / Provider — revenue continuity protected",
        "MEDIUM — auto-renewal; check notice period for cancellation",
        "MEDIUM",
    ),

    # ── Payment ────────────────────────────────────────────────────────────
    (
        r"\bnon[- ]?refundable\b",
        "Client / Buyer — no recourse if services are unsatisfactory",
        "Vendor / Seller — payment secured regardless of outcome",
        "HIGH — non-refundable payment removes Client's primary leverage",
        "HIGH",
    ),
    (
        r"\binterest\s+at\s+(\d+)\s*%",
        "Debtor (typically Client) — faces compounding financial penalty",
        "Creditor (typically Vendor) — protected against late payment",
        "MEDIUM — interest rate clause; check if rate is commercially reasonable",
        "MEDIUM",
    ),
    (
        r"\bunilateral(ly)?\s+(modify|change|amend|adjust)\s+(price|fee|rate|payment)\b",
        "Client / Buyer — prices can change without consent",
        "Vendor / Provider — can adjust pricing unilaterally",
        "HIGH — unilateral price modification removes Client's budget certainty",
        "HIGH",
    ),

    # ── Data / GDPR ────────────────────────────────────────────────────────
    (
        r"\bprocess(ing)?\s+personal\s+data\b",
        "Data subjects (individuals whose data is processed) — privacy rights at risk",
        "Data controller / processor — can use personal data for stated purposes",
        "MEDIUM — personal data processing; verify lawful basis and consent",
        "MEDIUM",
    ),
    (
        r"\btransfer\s+(of\s+)?personal\s+data\b.{0,100}\b(outside|third\s+countr|international)\b",
        "Data subjects — data leaves jurisdiction with potentially weaker protections",
        "Data controller — operational flexibility for global data flows",
        "HIGH — cross-border data transfer without adequate safeguards violates GDPR Art.44",
        "HIGH",
    ),

    # ── Sole discretion ────────────────────────────────────────────────────
    (
        r"\b(at\s+)?(its|their|our|the\s+(company|vendor|client|employer))'?s?\s+sole\s+discretion\b",
        "Weaker party — subject to arbitrary decisions with no recourse",
        "Stronger party — retains absolute unilateral decision-making power",
        "HIGH — 'sole discretion' clauses are inherently one-sided and often unenforceable",
        "HIGH",
    ),

    # ── Governing law / Dispute ────────────────────────────────────────────
    (
        r"\bbinding\s+arbitration\b.{0,100}\bclass\s+action\s+waiver\b",
        "Individual claimants — cannot join class actions; must arbitrate individually",
        "Company / Platform — protected from class action liability",
        "HIGH — class action waiver severely limits collective redress rights",
        "HIGH",
    ),
    (
        r"\bbinding\s+arbitration\b",
        "Weaker party — waives right to jury trial and public court proceedings",
        "Stronger party — disputes resolved privately, often in their preferred venue",
        "MEDIUM — binding arbitration limits access to courts",
        "MEDIUM",
    ),

    # ── Balanced clauses ───────────────────────────────────────────────────
    (
        r"\beither\s+party\s+may\s+terminate\b.{0,100}\b(30|thirty|60|sixty)\s+days?\b",
        "Neither party — mutual termination right with reasonable notice",
        "Both parties — equal exit rights with adequate notice period",
        "BALANCED — mutual termination with notice is market standard",
        "LOW",
    ),
    (
        r"\beach\s+party'?s?\s+(aggregate\s+)?liability.{0,100}(shall\s+not\s+exceed|is\s+limited\s+to)\b",
        "Neither party — mutual liability cap protects both sides equally",
        "Both parties — each protected from catastrophic claims",
        "BALANCED — mutual liability cap is market standard",
        "LOW",
    ),
]

# ── Fallback attacker/defender by flag name ────────────────────────────────────
FLAG_ATTACKER_DEFENDER: Dict[str, Dict[str, str]] = {
    "regardless_of_fault":      {"attacker": "Vendor — indemnifies Client even for Client's own negligence", "defender": "Client — fully insulated from all liability", "imbalance": "CRITICAL"},
    "uncapped_liability":       {"attacker": "Party with uncapped liability — faces unlimited exposure", "defender": "Party with capped liability — protected from large claims", "imbalance": "HIGH"},
    "sole_discretion":          {"attacker": "Weaker party — subject to arbitrary unilateral decisions", "defender": "Stronger party — retains absolute decision-making power", "imbalance": "HIGH"},
    "without_cause":            {"attacker": "Party subject to termination — no protection or compensation", "defender": "Terminating party — maximum flexibility", "imbalance": "HIGH"},
    "at_any_time":              {"attacker": "Party subject to the right — no certainty or stability", "defender": "Party holding the right — maximum operational flexibility", "imbalance": "HIGH"},
    "work_for_hire":            {"attacker": "Creator / Vendor — loses all IP ownership", "defender": "Client / Employer — owns all created work", "imbalance": "HIGH"},
    "overbroad_ip":             {"attacker": "Vendor / Employee — off-hours work captured", "defender": "Client / Employer — maximum IP capture", "imbalance": "CRITICAL"},
    "non_compete":              {"attacker": "Employee / Vendor — career restricted", "defender": "Employer / Client — protected from competition", "imbalance": "HIGH"},
    "non_refundable":           {"attacker": "Client / Buyer — no recourse for poor service", "defender": "Vendor / Seller — payment secured", "imbalance": "HIGH"},
    "auto_renewal":             {"attacker": "Client / Subscriber — may be locked in", "defender": "Vendor / Provider — revenue continuity", "imbalance": "MEDIUM"},
    "data_transfer":            {"attacker": "Data subjects — privacy rights at risk", "defender": "Data controller — operational flexibility", "imbalance": "HIGH"},
    "personal_data":            {"attacker": "Data subjects — privacy rights engaged", "defender": "Data controller — can process data", "imbalance": "MEDIUM"},
    "binding_arbitration":      {"attacker": "Weaker party — waives court rights", "defender": "Stronger party — private dispute resolution", "imbalance": "MEDIUM"},
    "liability_cap":            {"attacker": "Party seeking damages — recovery limited", "defender": "Party invoking cap — protected from large claims", "imbalance": "MEDIUM"},
    "indemnification":          {"attacker": "Indemnifying party — bears financial burden", "defender": "Indemnified party — protected from claims", "imbalance": "MEDIUM"},
    "perpetual_confidentiality":{"attacker": "Disclosing party — perpetual obligation may be unenforceable", "defender": "Receiving party — information protected indefinitely", "imbalance": "MEDIUM"},
}


def identify_attacker_defender(
    clause_text: str,
    flags: List[str],
) -> Dict[str, str]:
    """
    Identify attacker, defender, and power_imbalance for a clause.

    Args:
        clause_text: the clause text
        flags: list of flag names from pre_score_clause

    Returns:
        {attacker, defender, power_imbalance, imbalance_level}
    """
    text_lower = clause_text.lower()

    # Try specific patterns first (most accurate)
    for pattern, attacker, defender, imbalance, level in ATTACKER_DEFENDER_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
            return {
                "attacker": attacker,
                "defender": defender,
                "power_imbalance": imbalance,
                "imbalance_level": level,
            }

    # Fall back to flag-based lookup
    for flag in flags:
        if flag in FLAG_ATTACKER_DEFENDER:
            entry = FLAG_ATTACKER_DEFENDER[flag]
            return {
                "attacker": entry["attacker"],
                "defender": entry["defender"],
                "power_imbalance": f"{entry['imbalance']} — {flag.replace('_', ' ')} detected",
                "imbalance_level": entry["imbalance"],
            }

    # Default: balanced / unknown
    return {
        "attacker": "Neither party — clause appears balanced",
        "defender": "Both parties — mutual obligations",
        "power_imbalance": "LOW — no significant power imbalance detected",
        "imbalance_level": "LOW",
    }
