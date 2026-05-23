"""
legal_patterns.py
=================
Deterministic regex-based engines for:
  1. Pre-scoring clauses (PRE_SCORE_PATTERNS)
  2. Detecting legal violations / citations (LEGAL_CITATIONS)

No LLM calls — pure Python regex. Used by RiskScorer and ComplianceChecker
as a fast first pass before any Claude calls.
"""

import re
from typing import List, Dict, Any

# ── Pre-scoring patterns ───────────────────────────────────────────────────────
# Each entry: (regex_pattern, flag_name, score_contribution, human_reason)
PRE_SCORE_PATTERNS: List[tuple] = [
    # Liability
    (r"\bregardless\s+of\s+fault\b",                        "regardless_of_fault",      30, "Indemnification regardless of fault — extreme vendor exposure"),
    (r"\bno\s+limit\s+on\s+(liability|damages)\b",          "uncapped_liability",        28, "Uncapped liability — unlimited financial exposure"),
    (r"\bin\s+no\s+event\s+shall\b",                        "liability_cap",             10, "Liability cap present — check if mutual"),
    (r"\bsole\s+discretion\b",                              "sole_discretion",           20, "Sole discretion clause — unilateral power"),
    (r"\bwithout\s+(cause|reason|notice)\b",                "without_cause",             22, "Termination or action without cause/notice"),
    (r"\bat\s+any\s+time\b",                                "at_any_time",               15, "Unilateral right exercisable at any time"),

    # Termination asymmetry
    (r"\b(client|company|employer)\s+may\s+terminate\s+at\s+any\s+time\b",
                                                            "term_asymmetry_client",     25, "Client can terminate at will — asymmetric"),
    (r"\b(\d+)\s*[-–]\s*day\s+notice\b",                   "notice_period",              5, "Notice period specified — check if mutual"),
    (r"\bauto[- ]?renew(al|s)?\b",                         "auto_renewal",              18, "Auto-renewal clause — may lock in unfavourable terms"),
    (r"\bperpetual\s+(license|licence|right)\b",            "perpetual_license",         12, "Perpetual license grant — check scope"),

    # IP / ownership
    (r"\bwork\s+made\s+for\s+hire\b",                      "work_for_hire",             20, "Work-for-hire — all IP transfers to client"),
    (r"\bwhether\s+or\s+not\s+during\s+working\s+hours\b", "overbroad_ip",              25, "Overbroad IP assignment — captures off-hours work"),
    (r"\ball\s+(inventions?|discoveries|improvements)\b",   "broad_ip_assignment",       22, "Broad IP assignment — may capture pre-existing IP"),
    (r"\bnon[- ]?compete\b",                                "non_compete",               20, "Non-compete clause — restricts future employment"),
    (r"\bnon[- ]?solicit(ation)?\b",                        "non_solicit",               12, "Non-solicitation clause"),

    # Payment / financial
    (r"\bnon[- ]?refundable\b",                             "non_refundable",            15, "Non-refundable payment — no recourse"),
    (r"\blate\s+(fee|penalty|charge)\b",                    "late_fee",                   8, "Late fee clause — check rate"),
    (r"\binterest\s+at\s+(\d+)\s*%",                        "interest_rate",             10, "Interest rate specified — check if usurious"),
    (r"\bnet\s+(\d+)\b",                                    "payment_terms",              5, "Payment terms specified"),

    # GDPR / data
    (r"\bpersonal\s+data\b",                                "personal_data",             10, "Personal data mentioned — GDPR obligations apply"),
    (r"\bdata\s+subject\b",                                 "data_subject",              10, "Data subject mentioned — GDPR Art.4 applies"),
    (r"\btransfer\s+(of\s+)?personal\s+data\b",             "data_transfer",             20, "Personal data transfer — GDPR Art.44-49 applies"),
    (r"\bprocess(ing)?\s+personal\s+data\b",                "data_processing",           15, "Data processing — GDPR Art.6 lawful basis required"),
    (r"\bdata\s+processor\b",                               "data_processor",            12, "Data processor role — GDPR Art.28 DPA required"),
    (r"\bretain\s+(data|records|logs)\b",                   "data_retention",            10, "Data retention clause — check GDPR Art.5(1)(e)"),
    (r"\bdestroy\s+(data|records|logs)\b",                  "data_destruction",          10, "Data destruction clause — check conflict with retention"),

    # Indemnification
    (r"\bindemnif(y|ication|ies)\b",                        "indemnification",           15, "Indemnification clause — check if mutual"),
    (r"\bhold\s+harmless\b",                                "hold_harmless",             12, "Hold harmless clause — check scope"),
    (r"\bdefend\s+and\s+indemnif(y|ication)\b",             "defend_indemnify",          18, "Defend and indemnify — broad obligation"),

    # Confidentiality
    (r"\bconfidential(ity)?\b",                             "confidentiality",            5, "Confidentiality clause present"),
    (r"\bperpetual\s+confidentiality\b",                    "perpetual_confidentiality", 15, "Perpetual confidentiality — may be unenforceable"),

    # Dispute resolution
    (r"\bbinding\s+arbitration\b",                          "binding_arbitration",       10, "Binding arbitration — waives court rights"),
    (r"\bclass\s+action\s+waiver\b",                        "class_action_waiver",       20, "Class action waiver — limits collective redress"),
    (r"\bjurisdiction\s+of\s+.{0,30}courts?\b",             "jurisdiction",               5, "Jurisdiction specified"),

    # Governing law
    (r"\bgoverned\s+by\s+the\s+laws?\s+of\b",               "governing_law",              5, "Governing law specified"),
]


# ── Legal citation patterns ────────────────────────────────────────────────────
# Each entry: (regex, violation_type, severity 1-10, law_reference, description, penalty_hint)
LEGAL_CITATIONS: List[tuple] = [
    # GDPR
    (r"\bprocess(ing)?\s+personal\s+data\b(?!.*lawful\s+basis)",
     "Missing Lawful Basis for Processing",
     8, "GDPR Art. 6",
     "Personal data processing without specifying a lawful basis violates GDPR Art. 6(1).",
     "Up to €20M or 4% of global annual turnover (whichever higher)"),

    (r"\btransfer\s+(of\s+)?personal\s+data\b(?!.*(adequacy|SCCs?|standard\s+contractual|binding\s+corporate))",
     "Unlawful Cross-Border Data Transfer",
     9, "GDPR Art. 44-49",
     "Transfer of personal data outside EEA without adequate safeguards violates GDPR Art. 44.",
     "Up to €20M or 4% of global annual turnover"),

    (r"\bdata\s+processor\b(?!.*data\s+processing\s+agreement)",
     "Missing Data Processing Agreement",
     8, "GDPR Art. 28",
     "Engaging a data processor without a written DPA violates GDPR Art. 28(3).",
     "Up to €10M or 2% of global annual turnover"),

    (r"\bpersonal\s+data\b(?!.*privacy\s+(notice|policy|statement))",
     "Missing Privacy Notice",
     7, "GDPR Art. 13-14",
     "Collecting personal data without providing a privacy notice violates GDPR Art. 13.",
     "Up to €20M or 4% of global annual turnover"),

    (r"\bdata\s+breach\b(?!.*72\s*hours?)",
     "Inadequate Breach Notification Period",
     7, "GDPR Art. 33",
     "Data breach notification must occur within 72 hours under GDPR Art. 33(1).",
     "Up to €10M or 2% of global annual turnover"),

    (r"\bprivacy\s+by\s+design\b",
     "Privacy by Design Obligation",
     5, "GDPR Art. 25",
     "GDPR Art. 25 requires data protection by design and by default.",
     "Up to €10M or 2% of global annual turnover"),

    # Indian Contract Act
    (r"\bnon[- ]?compete\b.{0,200}\b(perpetual|forever|indefinite|no\s+time\s+limit)\b",
     "Void Restraint of Trade",
     9, "Indian Contract Act S.27",
     "Perpetual or indefinite non-compete clauses are void under S.27 of the Indian Contract Act 1872.",
     "Clause unenforceable; potential damages claim"),

    (r"\bpenalty\b.{0,100}\b(pre[- ]?determined|fixed|liquidated)\b(?!.*genuine\s+pre[- ]?estimate)",
     "Unenforceable Penalty Clause",
     7, "Indian Contract Act S.74",
     "Penalty clauses must represent a genuine pre-estimate of loss under S.74 ICA; punitive penalties are void.",
     "Clause unenforceable; court may award only actual damages"),

    # Indian Copyright Act
    (r"\bwork\s+made\s+for\s+hire\b",
     "Overbroad IP Assignment",
     7, "Indian Copyright Act S.17",
     "Under S.17 of the Indian Copyright Act, the author (not employer) owns copyright unless employment contract specifies otherwise.",
     "IP ownership dispute; potential injunction"),

    (r"\bmoral\s+rights?\s+waiv(ed?|er)\b",
     "Waiver of Moral Rights",
     6, "Indian Copyright Act S.57",
     "S.57 of the Indian Copyright Act grants inalienable moral rights to authors; waiver may be unenforceable.",
     "Author may still assert moral rights despite waiver"),

    # Industrial Disputes Act
    (r"\bterminate\s+(at\s+will|immediately|without\s+cause)\b.{0,300}\b(employee|worker|staff)\b",
     "Unlawful Termination Without Notice",
     8, "Industrial Disputes Act S.25F",
     "S.25F of the Industrial Disputes Act requires one month's notice or pay in lieu for retrenchment.",
     "Reinstatement order; back wages; compensation up to ₹50,000"),

    # DPDP Act 2023
    (r"\bprocess(ing)?\s+personal\s+data\b(?!.*consent)",
     "Processing Without Consent",
     8, "DPDP Act 2023 S.7",
     "S.7 of India's Digital Personal Data Protection Act 2023 requires explicit consent for data processing.",
     "Penalty up to ₹250 crore"),

    (r"\bpersonal\s+data\b(?!.*purpose\s+limitation)",
     "Missing Purpose Limitation",
     7, "DPDP Act 2023 S.8",
     "S.8 DPDP Act requires data to be used only for the specified purpose.",
     "Penalty up to ₹200 crore"),

    (r"\bminor\b.{0,100}\bpersonal\s+data\b",
     "Processing Children's Data Without Parental Consent",
     9, "DPDP Act 2023 S.12",
     "S.12 DPDP Act prohibits processing personal data of minors without verifiable parental consent.",
     "Penalty up to ₹200 crore"),

    # RBI usury
    (r"\binterest\s+at\s+(\d+)\s*%",
     "Potentially Usurious Interest Rate",
     6, "RBI Guidelines / Usurious Loans Act 1918",
     "Interest rates exceeding RBI guidelines may be struck down as usurious.",
     "Court may reduce interest to reasonable rate"),
]


def pre_score_clause(text: str) -> Dict[str, Any]:
    """
    Run all PRE_SCORE_PATTERNS against a clause text.
    Returns {base_score, flags, reasons}.
    base_score is capped at 95.
    """
    text_lower = text.lower()
    base_score = 0
    flags: List[str] = []
    reasons: List[str] = []

    for pattern, flag, score, reason in PRE_SCORE_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            base_score += score
            flags.append(flag)
            reasons.append(reason)

    base_score = min(base_score, 95)
    return {"base_score": base_score, "flags": flags, "reasons": reasons}


def detect_legal_violations(clauses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run LEGAL_CITATIONS patterns against all clauses.
    Returns list of violation dicts matching the frontend shape:
    {law, clause, description, penalty}
    """
    violations: List[Dict[str, Any]] = []
    seen: set = set()

    for clause in clauses:
        text = clause.get("text", "")
        number = clause.get("number", "?")
        text_lower = text.lower()

        for pattern, vtype, severity, law_ref, description, penalty in LEGAL_CITATIONS:
            if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
                key = f"{law_ref}:{number}"
                if key not in seen:
                    seen.add(key)
                    violations.append({
                        "law": law_ref,
                        "clause": number,
                        "description": description,
                        "penalty": penalty,
                        "severity": severity,
                        "_violation_type": vtype,
                    })

    return violations
