"""
patterns.py
===========
Shared pattern registry for the Logic subsystem.

Contains:
  - CLAUSE_PATTERNS: logical tag extraction for Z3 contradiction detection
  - PRE_SCORE_PATTERNS: deterministic risk pre-scoring
  - LEGAL_CITATIONS: regulatory violation detection
  - pre_score_clause(text) -> dict
  - detect_legal_violations(clauses) -> list
"""

import re
from typing import List, Dict, Any, Tuple

# ── Clause logical tag patterns ────────────────────────────────────────────────
# (regex, logical_tag, polarity, attacker_hint, defender_hint)
# polarity: +1 = asserts TRUE, -1 = asserts FALSE
CLAUSE_PATTERNS: List[Tuple[str, str, int, str, str]] = [
    # Liability
    (r"\blimit(s|ed|ing)?\s+(liability|damages)\b",
     "liability_limited", +1,
     "The party whose liability is NOT limited",
     "The party whose liability IS limited"),
    (r"\bno\s+limit\s+on\s+(liability|damages)\b",
     "liability_limited", -1,
     "The party facing unlimited liability",
     "The party imposing unlimited liability on the other"),
    (r"\buncapped\s+(liability|damages)\b",
     "liability_limited", -1,
     "The party with uncapped exposure",
     "The party benefiting from the other's uncapped exposure"),
    (r"\bno\s+(equivalent\s+)?cap\s+(is\s+)?placed\b",
     "liability_limited", -1,
     "The party with no cap protection",
     "The party that drafted the asymmetric cap"),

    # Termination at will
    (r"\bterminate\s+(at\s+any\s+time|immediately|without\s+(cause|notice|reason))\b",
     "term_at_will", +1,
     "The party that cannot terminate at will",
     "The party that can terminate at will"),

    # Notice required
    (r"\b(\d+)[- ]day\s+notice\s+(period\s+)?required\b",
     "notice_required", +1,
     "The party that must give notice",
     "The party receiving notice protection"),
    (r"\bno\s+notice\s+required\b",
     "notice_required", -1,
     "The party that gets no notice",
     "The party that can act without notice"),
    (r"\bwithout\s+notice\b",
     "notice_required", -1,
     "The party that receives no warning",
     "The party acting without notice"),

    # Auto-renewal
    (r"\bauto[- ]?renew(al|s)?\b",
     "auto_renewal", +1,
     "The party locked into auto-renewal without active consent",
     "The party benefiting from automatic continuation"),
    (r"\bno\s+auto[- ]?renew(al)?\b",
     "auto_renewal", -1,
     "The party that loses automatic continuation",
     "The party that negotiated against auto-renewal"),

    # Exclusivity
    (r"\bexclusive\s+(rights?|licen[sc]e|grant)\b",
     "exclusive", +1,
     "Third parties excluded from the market",
     "The party holding exclusive rights"),
    (r"\bnon[- ]?exclusive\b",
     "exclusive", -1,
     "The party that cannot enforce exclusivity",
     "The party retaining freedom to deal with others"),

    # Indemnification
    (r"\bindemnif(y|ication|ies)\b",
     "indemnification", +1,
     "The party bearing indemnification obligations",
     "The party receiving indemnification protection"),
    (r"\bno\s+indemnif(y|ication)\b",
     "indemnification", -1,
     "The party that loses indemnification protection",
     "The party avoiding indemnification obligations"),

    # Refundability
    (r"\bfully\s+refundable\b",
     "refundable", +1,
     "The party that must process refunds",
     "The party entitled to refunds"),
    (r"\bnon[- ]?refundable\b",
     "refundable", -1,
     "The party that paid and cannot recover funds",
     "The party keeping non-refundable payments"),

    # Data retention vs destruction
    (r"\b(permanently\s+)?(destroy|destroyed|delete|deleted|erase|erased|wipe|wiped)\b.{0,80}\b(data|records|copies|backups|logs|information)\b",
     "data_retained", -1,
     "The party that must destroy data (conflicting with retention obligation)",
     "The party requiring data destruction"),
    (r"\b(permanently\s+)?(destroy|destroyed|delete|deleted|erase|erased|wipe|wiped)\b",
     "data_retained", -1,
     "The party obligated to destroy data",
     "The party requiring destruction"),
    (r"\b(retain|keep|maintain|store|preserve|backup)\b.{0,80}\b(data|records|copies|backups|logs|information)\b",
     "data_retained", +1,
     "The party that must retain data (conflicting with destruction obligation)",
     "The party requiring data retention"),
    (r"\bretain\b.{0,30}\b(backups?|copies|records)\b",
     "data_retained", +1,
     "The party obligated to retain backups",
     "The party requiring retention"),

    # Liability cap
    (r"\b(liability|damages).{0,60}(shall\s+not\s+exceed|is\s+limited\s+to|capped\s+at)\b",
     "liability_capped", +1,
     "The party whose liability is capped",
     "The party benefiting from the cap"),
    (r"\bno\s+(equivalent\s+)?cap\b",
     "liability_capped", -1,
     "The party with no cap protection",
     "The party that drafted the asymmetric arrangement"),
    (r"\bno\s+cap\s+(is\s+)?(placed|applied)\b",
     "liability_capped", -1,
     "The party facing uncapped liability",
     "The party that imposed no cap on the other"),
    (r"\bno\s+limit(ation)?\s+(on|applies?\s+to)\s+(vendor|supplier|client)\b",
     "liability_capped", -1,
     "The party with no limitation protection",
     "The party that drafted the unlimited exposure clause"),

    # Payment terms
    (r"\bnet\s+(\d+)\b",
     "payment_net", +1,
     "The party waiting for payment",
     "The party with extended payment terms"),
    (r"\bimmediate\s+payment\b",
     "payment_net", -1,
     "The party required to pay immediately",
     "The party demanding immediate payment"),

    # Governing law vs arbitration venue
    (r"\bgoverned\s+by\s+the\s+laws?\s+of\s+(delaware|california|new\s+york|india|england)\b",
     "governing_law_us", +1,
     "The party in a different jurisdiction",
     "The party in the governing law jurisdiction"),
    (r"\barbitration\s+in\s+(san\s+francisco|california|new\s+york|london|singapore)\b",
     "governing_law_us", -1,
     "The party that must travel to the arbitration venue",
     "The party in the arbitration venue city"),

    # Confidentiality survival
    (r"\bconfidential(ity)?\s+(survives?|continues?|shall\s+survive)\b",
     "confidentiality_survives", +1,
     "The party whose confidential information may be disclosed post-termination",
     "The party protected by surviving confidentiality"),
    (r"\bconfidential(ity)?\s+(ends?|terminates?|expires?|ceases?)\b",
     "confidentiality_survives", -1,
     "The party whose confidential information loses protection",
     "The party that negotiated expiry of confidentiality"),

    # Perpetual vs fixed term
    (r"\bperpetual\b",
     "perpetual", +1,
     "The party bound by perpetual obligations",
     "The party benefiting from perpetual rights"),
    (r"\bfixed\s+term\b",
     "perpetual", -1,
     "The party that loses perpetual protection",
     "The party that negotiated a fixed term"),
]

# ── Pre-scoring patterns ───────────────────────────────────────────────────────
# (regex, flag_name, score_contribution, reason, attacker_hint, defender_hint)
PRE_SCORE_PATTERNS: List[Tuple[str, str, int, str, str, str]] = [
    (r"\bregardless\s+of\s+fault\b",
     "regardless_of_fault", 30,
     "Indemnification regardless of fault — extreme vendor exposure",
     "Vendor / service provider bearing unlimited indemnification",
     "Client / drafting party protected from own negligence"),

    (r"\bno\s+limit\s+on\s+(liability|damages)\b",
     "uncapped_liability", 28,
     "Uncapped liability — unlimited financial exposure",
     "Party facing unlimited liability",
     "Party imposing unlimited liability on the other"),

    (r"\bin\s+no\s+event\s+shall\b",
     "liability_cap", 10,
     "Liability cap present — check if mutual",
     "Party whose liability is capped (check if mutual)",
     "Party benefiting from the cap"),

    (r"\bsole\s+discretion\b",
     "sole_discretion", 20,
     "Sole discretion clause — unilateral power",
     "Party subject to the other's sole discretion",
     "Party exercising sole discretion"),

    (r"\bwithout\s+(cause|reason|notice)\b",
     "without_cause", 22,
     "Termination or action without cause/notice",
     "Party that can be terminated without cause",
     "Party that can terminate without cause"),

    (r"\bat\s+any\s+time\b",
     "at_any_time", 15,
     "Unilateral right exercisable at any time",
     "Party subject to unilateral action at any time",
     "Party holding the unilateral right"),

    (r"\b(client|company|employer)\s+may\s+terminate\s+at\s+any\s+time\b",
     "term_asymmetry_client", 25,
     "Client can terminate at will — asymmetric",
     "Vendor / service provider with no equivalent right",
     "Client holding asymmetric termination right"),

    (r"\b(\d+)\s*[-–]\s*day\s+notice\b",
     "notice_period", 5,
     "Notice period specified — check if mutual",
     "Party required to give notice",
     "Party receiving notice protection"),

    (r"\bauto[- ]?renew(al|s)?\b",
     "auto_renewal", 18,
     "Auto-renewal clause — may lock in unfavourable terms",
     "Party locked into auto-renewal without active consent",
     "Party benefiting from automatic continuation"),

    (r"\bperpetual\s+(license|licence|right)\b",
     "perpetual_license", 12,
     "Perpetual license grant — check scope",
     "Party granting perpetual rights",
     "Party receiving perpetual license"),

    (r"\bwork\s+made\s+for\s+hire\b",
     "work_for_hire", 20,
     "Work-for-hire — all IP transfers to client",
     "Vendor / creator losing IP ownership",
     "Client receiving all IP"),

    (r"\bwhether\s+or\s+not\s+during\s+working\s+hours\b",
     "overbroad_ip", 25,
     "Overbroad IP assignment — captures off-hours work",
     "Vendor / employee losing off-hours IP",
     "Client claiming all IP regardless of when created"),

    (r"\ball\s+(inventions?|discoveries|improvements)\b",
     "broad_ip_assignment", 22,
     "Broad IP assignment — may capture pre-existing IP",
     "Vendor / creator losing pre-existing IP",
     "Client claiming broad IP ownership"),

    (r"\bnon[- ]?compete\b",
     "non_compete", 20,
     "Non-compete clause — restricts future employment",
     "Vendor / employee restricted from future work",
     "Client protected from competition"),

    (r"\bnon[- ]?refundable\b",
     "non_refundable", 15,
     "Non-refundable payment — no recourse",
     "Party that paid and cannot recover funds",
     "Party keeping non-refundable payments"),

    (r"\blate\s+(fee|penalty|charge)\b",
     "late_fee", 8,
     "Late fee clause — check rate",
     "Party subject to late fees",
     "Party collecting late fees"),

    (r"\binterest\s+at\s+(\d+)\s*%",
     "interest_rate", 10,
     "Interest rate specified — check if usurious",
     "Party paying interest",
     "Party collecting interest"),

    (r"\bpersonal\s+data\b",
     "personal_data", 10,
     "Personal data mentioned — GDPR/DPDP obligations apply",
     "Data subjects whose data is processed",
     "Data controller / processor"),

    (r"\btransfer\s+(of\s+)?personal\s+data\b",
     "data_transfer", 20,
     "Personal data transfer — GDPR Art.44-49 applies",
     "Data subjects in the originating jurisdiction",
     "Party receiving transferred data"),

    (r"\bindemnif(y|ication|ies)\b",
     "indemnification", 15,
     "Indemnification clause — check if mutual",
     "Party bearing indemnification obligations",
     "Party receiving indemnification protection"),

    (r"\bhold\s+harmless\b",
     "hold_harmless", 12,
     "Hold harmless clause — check scope",
     "Party bearing hold harmless obligations",
     "Party held harmless"),

    (r"\bbinding\s+arbitration\b",
     "binding_arbitration", 10,
     "Binding arbitration — waives court rights",
     "Party waiving court access",
     "Party benefiting from private arbitration"),

    (r"\bclass\s+action\s+waiver\b",
     "class_action_waiver", 20,
     "Class action waiver — limits collective redress",
     "Consumers / employees losing class action rights",
     "Company avoiding class action exposure"),

    (r"\bperpetual\s+confidentiality\b",
     "perpetual_confidentiality", 15,
     "Perpetual confidentiality — may be unenforceable",
     "Party bound by perpetual confidentiality",
     "Party protected by perpetual confidentiality"),
]

# ── Legal citation patterns ────────────────────────────────────────────────────
# (regex, violation_type, severity, law_ref, description, attacker_hint, defender_hint)
LEGAL_CITATIONS: List[Tuple[str, str, int, str, str, str, str]] = [
    (r"\bprocess(ing)?\s+personal\s+data\b(?!.*lawful\s+basis)",
     "Missing Lawful Basis for Processing",
     8, "GDPR Art. 6",
     "Personal data processing without specifying a lawful basis violates GDPR Art. 6(1). Penalty: Up to €20M or 4% of global annual turnover.",
     "Data subjects whose data is processed without lawful basis",
     "Data controller / processor benefiting from unconstrained processing"),

    (r"\btransfer\s+(of\s+)?personal\s+data\b(?!.*(adequacy|SCCs?|standard\s+contractual|binding\s+corporate))",
     "Unlawful Cross-Border Data Transfer",
     9, "GDPR Art. 44-49",
     "Transfer of personal data outside EEA without adequate safeguards violates GDPR Art. 44. Penalty: Up to €20M or 4% of global annual turnover.",
     "Data subjects in the EEA losing GDPR protection",
     "Party receiving data in a non-adequate jurisdiction"),

    (r"\bdata\s+processor\b(?!.*data\s+processing\s+agreement)",
     "Missing Data Processing Agreement",
     8, "GDPR Art. 28",
     "Engaging a data processor without a written DPA violates GDPR Art. 28(3). Penalty: Up to €10M or 2% of global annual turnover.",
     "Data subjects whose data is processed without DPA safeguards",
     "Data controller avoiding DPA obligations"),

    (r"\bpersonal\s+data\b(?!.*privacy\s+(notice|policy|statement))",
     "Missing Privacy Notice",
     7, "GDPR Art. 13-14",
     "Collecting personal data without providing a privacy notice violates GDPR Art. 13. Penalty: Up to €20M or 4% of global annual turnover.",
     "Data subjects not informed of their rights",
     "Data controller avoiding transparency obligations"),

    (r"\bdata\s+breach\b(?!.*72\s*hours?)",
     "Inadequate Breach Notification Period",
     7, "GDPR Art. 33",
     "Data breach notification must occur within 72 hours under GDPR Art. 33(1). Penalty: Up to €10M or 2% of global annual turnover.",
     "Data subjects not notified of breaches in time",
     "Data controller avoiding timely notification"),

    (r"\bnon[- ]?compete\b.{0,200}\b(perpetual|forever|indefinite|no\s+time\s+limit)\b",
     "Void Restraint of Trade",
     9, "Indian Contract Act S.27",
     "Perpetual or indefinite non-compete clauses are void under S.27 of the Indian Contract Act 1872. Clause unenforceable; potential damages claim.",
     "Vendor / employee restricted from future work indefinitely",
     "Client attempting to enforce perpetual non-compete"),

    (r"\bpenalty\b.{0,100}\b(pre[- ]?determined|fixed|liquidated)\b(?!.*genuine\s+pre[- ]?estimate)",
     "Unenforceable Penalty Clause",
     7, "Indian Contract Act S.74",
     "Penalty clauses must represent a genuine pre-estimate of loss under S.74 ICA; punitive penalties are void. Court may award only actual damages.",
     "Party subject to punitive penalty clause",
     "Party imposing punitive penalties"),

    (r"\bwork\s+made\s+for\s+hire\b",
     "Overbroad IP Assignment",
     7, "Indian Copyright Act S.17",
     "Under S.17 of the Indian Copyright Act, the author (not employer) owns copyright unless employment contract specifies otherwise. IP ownership dispute risk.",
     "Vendor / creator losing IP ownership",
     "Client claiming all IP via work-for-hire"),

    (r"\bterminate\s+(at\s+will|immediately|without\s+cause)\b.{0,300}\b(employee|worker|staff)\b",
     "Unlawful Termination Without Notice",
     8, "Industrial Disputes Act S.25F",
     "S.25F of the Industrial Disputes Act requires one month's notice or pay in lieu for retrenchment. Reinstatement order; back wages; compensation up to ₹50,000.",
     "Employee / worker terminated without notice",
     "Employer avoiding notice obligations"),

    (r"\bprocess(ing)?\s+personal\s+data\b(?!.*consent)",
     "Processing Without Consent",
     8, "DPDP Act 2023 S.7",
     "S.7 of India's Digital Personal Data Protection Act 2023 requires explicit consent for data processing. Penalty up to ₹250 crore.",
     "Data principals whose data is processed without consent",
     "Data fiduciary avoiding consent requirements"),

    (r"\bpersonal\s+data\b(?!.*purpose\s+limitation)",
     "Missing Purpose Limitation",
     7, "DPDP Act 2023 S.8",
     "S.8 DPDP Act requires data to be used only for the specified purpose. Penalty up to ₹200 crore.",
     "Data principals whose data may be used beyond stated purpose",
     "Data fiduciary retaining broad data use rights"),

    (r"\bminor\b.{0,100}\bpersonal\s+data\b",
     "Processing Children's Data Without Parental Consent",
     9, "DPDP Act 2023 S.12",
     "S.12 DPDP Act prohibits processing personal data of minors without verifiable parental consent. Penalty up to ₹200 crore.",
     "Minors whose data is processed without parental consent",
     "Data fiduciary processing children's data"),

    (r"\binterest\s+at\s+(\d+)\s*%",
     "Potentially Usurious Interest Rate",
     6, "RBI Guidelines / Usurious Loans Act 1918",
     "Interest rates exceeding RBI guidelines may be struck down as usurious. Court may reduce interest to reasonable rate.",
     "Party paying potentially usurious interest",
     "Party collecting high interest rates"),

    (r"\bmoral\s+rights?\s+waiv(ed?|er)\b",
     "Waiver of Moral Rights",
     6, "Indian Copyright Act S.57",
     "S.57 of the Indian Copyright Act grants inalienable moral rights to authors; waiver may be unenforceable. Author may still assert moral rights despite waiver.",
     "Author / creator whose moral rights are waived",
     "Client requiring moral rights waiver"),
]


def pre_score_clause(text: str) -> Dict[str, Any]:
    """
    Run all PRE_SCORE_PATTERNS against a clause text.
    Returns {base_score, flags, reasons, attacker, defender}.
    base_score is capped at 95.
    """
    text_lower = text.lower()
    base_score = 0
    flags: List[str] = []
    reasons: List[str] = []
    attacker_parts: List[str] = []
    defender_parts: List[str] = []

    for pattern, flag, score, reason, attacker, defender in PRE_SCORE_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            base_score += score
            flags.append(flag)
            reasons.append(reason)
            if attacker and attacker not in attacker_parts:
                attacker_parts.append(attacker)
            if defender and defender not in defender_parts:
                defender_parts.append(defender)

    base_score = min(base_score, 95)
    return {
        "base_score": base_score,
        "flags": flags,
        "reasons": reasons,
        "attacker": "; ".join(attacker_parts[:2]) if attacker_parts else "Neither party",
        "defender": "; ".join(defender_parts[:2]) if defender_parts else "Both parties",
    }


def detect_legal_violations(clauses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run LEGAL_CITATIONS patterns against all clauses.
    Returns list of violation dicts:
    {law, clause, description, penalty, severity, attacker, defender}
    """
    violations: List[Dict[str, Any]] = []
    seen: set = set()

    for clause in clauses:
        text = clause.get("text", "")
        number = clause.get("number", "?")
        text_lower = text.lower()

        for pattern, vtype, severity, law_ref, description, attacker, defender in LEGAL_CITATIONS:
            if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
                key = f"{law_ref}:{number}"
                if key not in seen:
                    seen.add(key)
                    # Split description and penalty
                    parts = description.rsplit("Penalty:", 1)
                    desc_text = parts[0].strip()
                    penalty_text = ("Penalty:" + parts[1]).strip() if len(parts) > 1 else "See regulatory guidelines"
                    violations.append({
                        "law": law_ref,
                        "clause": number,
                        "description": desc_text,
                        "penalty": penalty_text,
                        "severity": str(severity),
                        "attacker": attacker,
                        "defender": defender,
                        "_violation_type": vtype,
                    })

    return violations
