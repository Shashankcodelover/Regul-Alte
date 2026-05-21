# mock_data.py — Realistic AI backend output payloads for Levels 1, 2, and 3

import time

# ----------------- LEVEL 1 (Low Risk - Perfect Standard Agreement) -----------------
level_1_data = {
    "score": 12,
    "verdict": "Low Risk",
    "summary": "This contract represents an exceptionally balanced, commercially standard corporate agreement. The risk profile is extremely low, with mutual indemnification, equal liability caps, and symmetric termination rights. Commercially clean and ready for signature.",
    "pages_analyzed": 12,
    "pages_trend": "+12 pages",
    "relevant_precedents": 4,
    "precedents_trend": "Reciprocal terms",
    "identified_risks": 0,
    "risks_trend": "0 critical risks",
    "ai_confidence": "98%",
    "confidence_trend": "Balanced",
    "risk_zone": "Zone Low Risk",
    "analyzed_date": "",  # To be filled dynamically in app.py
    "last_edited": "",    # To be filled dynamically in app.py
    "filename": "Perfect_Standard_Agreement.pdf",
    "red_flags": [],
    "compliance_audit": {
        "gdpr_score": 98,
        "gdpr_status": "🟢 Compliant",
        "gdpr_details": "Excellent data privacy safeguards with clear mutual deletion obligations within 30 days.",
        "it_act_score": 95,
        "it_act_status": "🟢 Compliant",
        "it_act_details": "Fully satisfies reasonable security practices under Indian IT Act 2000.",
        "ccpa_score": 94,
        "ccpa_status": "🟢 Compliant",
        "ccpa_details": "Robust data processing agreements include California statutory disclosures and opt-out exclusions."
    }
}

level_1_debate = [
    {
        "role": "Attacker",
        "content": "Initiating analysis. I have scanned this contract and it's surprisingly clean. Both parties have mutual 30 days termination rights. No obvious traps or lock-in asymmetries here."
    },
    {
        "role": "Defender",
        "content": "Precisely. The reciprocity here is textbook. The notice period is symmetric, which keeps operations completely stable for both sides."
    },
    {
        "role": "Attacker",
        "content": "Even the liability cap is mutual at 12 months of fees, and includes standard mutual carve-outs for confidentiality breaches. This is a very safe contract to sign."
    },
    {
        "role": "Defender",
        "content": "Confirmed. I recommend signing this agreement immediately. It sets a very healthy business baseline and avoids unnecessary friction."
    }
]

level_1_conflicts = [
    {
        "conflict": "No Substantive Contradictions Found",
        "severity": "Clear",
        "rule_a": "Section 3.1: All invoices issued under this Agreement are payable within thirty (30) days of receipt.",
        "rule_b": "Schedule A: Premium services follow standard 30-day payment terms.",
        "explanation": "No operational or logical contradictions were detected. Covenants are completely synchronized.",
        "resolved_clause": "Clause A and Clause B are already aligned. No resolution is required.",
        "z3_code": """# ── Z3 SOLVER LOGIC FORMULATION ──
from z3 import *
payment_days = Int('payment_days')
s = Solver()
s.add(payment_days == 30) # Rule A
s.add(payment_days == 30) # Rule B
verification_result = s.check()
print(f"Contract Logical Consistency: {verification_result}") # Output: SAT!"""
    }
]

level_1_playbook = {
    "Termination Rights": {
        "title": "Reciprocal Termination Rights",
        "severity": 1,
        "original": "Either party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice to the other party.",
        "Defender": {
            "rewrite": "Either party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice to the other party.",
            "risk_label": "🛡️ Reciprocal Risk",
            "risk_class": "low",
            "score": "1/10",
            "rationale": "Already symmetric. Commercially clean."
        },
        "Attacker": {
            "rewrite": "Vendor may terminate this Agreement at any time for convenience upon five (5) days' notice. Client shall have no right to terminate for convenience.",
            "risk_label": "⚔️ Vendor Exit Dominance",
            "risk_class": "low",
            "score": "1/10",
            "rationale": "Tries to aggressively shift termination convenience strictly to the Vendor."
        },
        "Arbitrator": {
            "rewrite": "Either party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice.",
            "risk_label": "⚖️ Highly Balanced",
            "risk_class": "low",
            "score": "1/10",
            "rationale": "Maintains mutual 30 days notice."
        }
    }
}


# ----------------- LEVEL 2 (Medium Risk - Mildly Risky Agreement) -----------------
level_2_data = {
    "score": 48,
    "verdict": "Medium Risk",
    "summary": "This contract contains mild commercial asymmetries. While it is mostly standard, there is an unbalanced termination notice period and a slight mismatch in liability limits. Review is recommended before signing.",
    "pages_analyzed": 18,
    "pages_trend": "+18 pages",
    "relevant_precedents": 8,
    "precedents_trend": "+3 cases",
    "identified_risks": 3,
    "risks_trend": "+3 warnings",
    "ai_confidence": "94%",
    "confidence_trend": "Stable",
    "risk_zone": "Zone Medium Risk",
    "analyzed_date": "",  # To be filled dynamically in app.py
    "last_edited": "",    # To be filled dynamically in app.py
    "filename": "Mildly_Risky_Agreement.pdf",
    "red_flags": [
        {
            "category": "Termination Asymmetry",
            "severity": 6,
            "clause_text": (
                "Client may terminate this Agreement upon fifteen (15) days' written notice, whereas Vendor may "
                "terminate only upon forty-five (45) days' notice."
            ),
            "citation": "Section 9.1 / Notice Periods (Page 3)",
            "impact": "A mild notice period asymmetry gives the Client more tactical flexibility than the Vendor, potentially causing operational planning shifts."
        },
        {
            "category": "Liability Cap Asymmetry",
            "severity": 5,
            "clause_text": (
                "Client's aggregate liability under this Agreement is capped at three (3) months' fees, "
                "while Vendor's aggregate liability is capped at six (6) months' fees."
            ),
            "citation": "Section 10.4 / Liability Cap (Page 3)",
            "impact": "Vendor's liability exposure is twice as high as the Client's, creating a slight, unnecessary commercial imbalance."
        },
        {
            "category": "Payment Terms Gap",
            "severity": 4,
            "clause_text": (
                "Client shall pay invoices in Net 30. However, Schedule B designates Premium Tier consulting payments as Net 15."
            ),
            "citation": "Section 3.1 & Schedule B (Page 2)",
            "impact": "There is a payment terms inconsistency between Net 30 in the contract body and Net 15 in the schedules, which may result in late payment disputes."
        }
    ],
    "compliance_audit": {
        "gdpr_score": 82,
        "gdpr_status": "🟡 Minor Privacy Concerns",
        "gdpr_details": "No GDPR specific user opt-out features are detailed, though general data deletion rules apply.",
        "it_act_score": 78,
        "it_act_status": "🟡 Fair Compliance",
        "it_act_details": "Standard information security terms are met, but lacks explicit reference to IT Act Section 43A corporate standards.",
        "ccpa_score": 80,
        "ccpa_status": "🟡 Moderate Risk • Missing CCPA Opt-Out",
        "ccpa_details": "General confidentiality clauses exist, but explicit California Consumer Privacy Act opt-out mechanics are absent."
    }
}

level_2_debate = [
    {
        "role": "Attacker",
        "content": "The 15-day vs 45-day convenience termination notice asymmetry in Section 9.1 is highly problematic. The Client can dump us in two weeks, but we are locked in for a month and a half. This creates immense resource planning instability."
    },
    {
        "role": "Defender",
        "content": "Agreed. While B2B courts generally enforce this, we should counter with a request for mutual 30 days. That gives both sides fair notice and keeps operations stable."
    },
    {
        "role": "Attacker",
        "content": "Also look at Section 10.4. Our liability is capped at 6 months of fees, while the Client's liability is capped at 3 months. Why should we bear double the commercial liability risk for their operational errors?"
    },
    {
        "role": "Defender",
        "content": "Exactly. A mutual liability cap is standard practice in service contracts. I recommend drafting a mutual 6-month or 12-month contract value liability cap to protect both parties equally."
    }
]

level_2_conflicts = [
    {
        "conflict": "Payment Terms Discrepancy (Body vs Schedule)",
        "severity": "High",
        "rule_a": "Section 3.1: All invoices issued under this Agreement are payable within Net 30 days of invoice receipt.",
        "rule_b": "Schedule B: All payments for Premium Tier consulting and deployment services are due strictly within Net 15 days.",
        "explanation": "The contract body and the attached schedule specify different payment windows for the same premium services. This creates procedural friction and late fee interest disputes.",
        "resolved_clause": "All invoices issued under this Agreement shall be payable within Net 30 days of receipt; provided, however, that all payments for Premium Tier consulting services under Schedule B shall be due within Net 20 days with no late interest applied before day 30.",
        "z3_code": """# ── Z3 SOLVER LOGIC FORMULATION ──
from z3 import *
payment_days = Int('payment_days')
s = Solver()
s.add(payment_days == 30) # Rule A
s.add(payment_days == 15) # Rule B
verification_result = s.check()
print(f"Contract Logical Consistency: {verification_result}") # Output: UNSAT! (30 != 15)"""
    }
]

level_2_playbook = {
    "Termination Rights": {
        "title": "Termination Notice Asymmetry",
        "severity": 6,
        "original": "Client may terminate this Agreement upon fifteen (15) days' written notice, whereas Vendor may terminate only upon forty-five (45) days' notice.",
        "Defender": {
            "rewrite": "Either party may terminate this Agreement for convenience upon thirty (30) days' prior written notice to the other party.",
            "risk_label": "🛡️ Balanced Risk",
            "risk_class": "low",
            "score": "2/10",
            "rationale": "Balances the notice period to a mutual 30 days, keeping operations predictable."
        },
        "Attacker": {
            "rewrite": "Vendor may terminate this Agreement upon fifteen (15) days' notice. Client may terminate only upon forty-five (45) days' notice.",
            "risk_label": "⚔️ Vendor-Favored Notice",
            "risk_class": "low",
            "score": "1/10",
            "rationale": "Inverts the asymmetry to favor the Vendor."
        },
        "Arbitrator": {
            "rewrite": "Either party may terminate this Agreement for convenience upon thirty (30) days' prior written notice.",
            "risk_label": "⚖️ Reciprocal Neutral",
            "risk_class": "low",
            "score": "2/10",
            "rationale": "Establishes market-standard reciprocity."
        }
    },
    "Liability Cap": {
        "title": "Liability Cap Asymmetry",
        "severity": 5,
        "original": "Client's aggregate liability under this Agreement is capped at three (3) months' fees, while Vendor's aggregate liability is capped at six (6) months' fees.",
        "Defender": {
            "rewrite": "Each party's aggregate liability under this Agreement shall be limited to a mutual cap equal to six (6) months of fees.",
            "risk_label": "🛡️ Mutual Cap",
            "risk_class": "low",
            "score": "2/10",
            "rationale": "Equalizes the liability cap to six months' fees for both sides."
        },
        "Attacker": {
            "rewrite": "Vendor's liability under this Agreement is limited to three (3) months of fees. Client's liability remains uncapped.",
            "risk_label": "⚔️ Extreme Vendor Shield",
            "risk_class": "low",
            "score": "1/10",
            "rationale": "Broadly shields the Vendor while keeping the Client fully exposed."
        },
        "Arbitrator": {
            "rewrite": "Each party's total aggregate liability arising out of this Agreement shall not exceed twelve (12) months of fees.",
            "risk_label": "⚖️ Balanced Reciprocity",
            "risk_class": "low",
            "score": "2/10",
            "rationale": "Equalizes liability to a mutual 12-month standard cap."
        }
    }
}


# ----------------- LEVEL 3 (High Risk - Vulnerable Agreement Draft) -----------------
level_3_data = {
    "score": 87,
    "verdict": "High Risk",
    "summary": "This contract contains severe indemnification asymmetries, an effectively unlimited vendor liability exposure, and internally contradictory termination clauses. Immediate legal review is recommended before signing.",
    "pages_analyzed": 47,
    "pages_trend": "+6 pages",
    "relevant_precedents": 12,
    "precedents_trend": "+3 cases",
    "identified_risks": 5,
    "risks_trend": "+2 this week",
    "ai_confidence": "92%",
    "confidence_trend": "+4%",
    "risk_zone": "Medium 2.3",
    "analyzed_date": "",  # To be filled dynamically in app.py
    "last_edited": "",    # To be filled dynamically in app.py
    "filename": "Vulnerable_Agreement_Draft.pdf",
    "red_flags": [
        {
            "category": "Indemnification",
            "severity": 9,
            "clause_text": (
                "Vendor agrees to indemnify, defend, and hold harmless the Client from and against any and "
                "all claims, losses, liabilities, damages, expenses, and costs (including reasonable attorneys' "
                "fees) arising out of or related to the Vendor's performance under this Agreement, regardless of fault."
            ),
            "citation": "Page 3, Section 4.2, Paragraph 1",
            "impact": "The phrase 'regardless of fault' exposes the Vendor to liability for the Client's own negligent acts."
        },
        {
            "category": "Termination Asymmetry",
            "severity": 8,
            "clause_text": (
                "Client may terminate this Agreement at any time for any reason upon five (5) days' written "
                "notice, whereas Vendor may only terminate upon a material breach remaining uncured for "
                "sixty (60) days following written notice."
            ),
            "citation": "Page 7, Section 9.1, Paragraph 2",
            "impact": "A 5-day vs. 60-day asymmetry creates severe operational instability for the Vendor."
        },
        {
            "category": "Liability Cap",
            "severity": 10,
            "clause_text": (
                "Under no circumstances shall Client's aggregate liability arising out of or related to "
                "this Agreement exceed the total amount paid by Client to Vendor in the one (1) month "
                "preceding the event giving rise to the claim. No equivalent cap is placed upon Vendor's liability."
            ),
            "citation": "Page 8, Section 10.4, Paragraph 3",
            "impact": "Client liability is capped at ~1/12th of annual fees. Vendor liability is entirely uncapped — a critical imbalance."
        },
        {
            "category": "Intellectual Property Assignment",
            "severity": 7,
            "clause_text": (
                "All work product, inventions, discoveries, and improvements conceived or developed by "
                "Vendor, whether or not during working hours and whether or not using Client's resources, "
                "shall be deemed works made for hire and shall be the exclusive property of Client."
            ),
            "citation": "Page 5, Section 6.3, Paragraph 1",
            "impact": "Overly broad IP assignment may strip Vendor of pre-existing IP rights and general know-how."
        }
    ],
    "compliance_audit": {
        "gdpr_score": 64,
        "gdpr_status": "🟡 Moderate Risk • Retention Contradiction",
        "gdpr_details": "Critical conflict detected between prompt data destruction (30 days) and long-term regulatory backup requirements (3 years).",
        "it_act_score": 52,
        "it_act_status": "🔴 Highly Asymmetrical",
        "it_act_details": "Uncapped liability and severe asymmetries present operational risks under Indian IT Act Section 43A standards.",
        "ccpa_score": 82,
        "ccpa_status": "🟡 Moderate Risk • Missing CCPA Opt-Out",
        "ccpa_details": "General confidentiality clauses exist, but explicit California Consumer Privacy Act opt-out mechanics are absent."
    }
}

level_3_debate = [
    {
        "role": "Attacker",
        "content": "Initiating analysis on Section 4.2 — the indemnification clause. The phrase 'regardless of fault' is extraordinary. It means the Vendor indemnifies the Client even if the Client's own recklessness caused the incident. This is the single most dangerous clause in the document."
    },
    {
        "role": "Defender",
        "content": "Confirmed. Several courts apply the 'express negligence doctrine' requiring explicit language to hold a party indemnified against its own negligence. Reciprocal terms are standard in B2B deals; we must push to limit indemnification to gross negligence."
    },
    {
        "role": "Attacker",
        "content": "Moving to the liability cap in Section 10.4. The Client's liability is limited to one month of fees. Meanwhile, the Vendor has zero liability cap. If the Vendor makes a mistake, they face unlimited liability exposure. This is a textbook adversarial clause."
    },
    {
        "role": "Defender",
        "content": "This asymmetry is a critical risk factor. The Vendor's exposure is entirely unlimited. A mutual cap of 12 months of fees is the standard; I recommend renegotiating this as a high-priority item."
    }
]

level_3_conflicts = [
    {
        "conflict": "Data Retention vs. Data Destruction",
        "severity": "Critical",
        "rule_a": "Section 2.1: 'All confidential data, including customer records and transaction logs, must be permanently and irreversibly destroyed within thirty (30) days of contract termination.'",
        "rule_b": "Section 5.4: 'Vendor shall retain complete backups of all transactional data for a minimum period of three (3) years to ensure compliance with applicable financial regulations.'",
        "explanation": "These clauses directly contradict each other if 'transactional data' (Section 5.4) qualifies as 'confidential data' (Section 2.1). The contract provides no exemption to resolve this. Complying with one legally violates the other.",
        "resolved_clause": "Except as required by applicable laws and regulations (specifically Section 5.4), all confidential data must be permanently and irreversibly destroyed within thirty (30) days of contract termination. Any data kept in regulatory backups shall remain strictly confidential and secured until its final automated deletion.",
        "z3_code": """# ── Z3 SOLVER LOGIC FORMULATION ──
from z3 import *

# Define boolean rules of the contract
data_destroyed_30_days = Bool('data_destroyed_30_days')
transaction_records_retained_3_years = Bool('transaction_records_retained_3_years')

s = Solver()

# Rule A: Permanent destruction of all transactional records within 30 days
s.add(data_destroyed_30_days == True)

# Rule B: Regulatory mandate to retain transactional data for 3 years
s.add(transaction_records_retained_3_years == True)

# Axiom: You cannot destroy records within 30 days and also retain them for 3 years
s.add(Implies(data_destroyed_30_days, Not(transaction_records_retained_3_years)))

# Verification of satisfiability (SAT / UNSAT)
verification_result = s.check()
print(f"Contract Logical Consistency: {verification_result}") # Output: UNSAT!"""
    }
]

level_3_playbook = {
    "Termination Rights": {
        "title": "Asymmetric Termination Rights",
        "severity": 8,
        "original": "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days.",
        "Defender": {
            "rewrite": "Either party may terminate this Agreement for convenience upon thirty (30) days' prior written notice. Either party may terminate for material breach remaining uncured for fifteen (15) days.",
            "risk_label": "🛡️ Balanced Risk",
            "risk_class": "low",
            "score": "3/10",
            "rationale": "Introduces a mutual termination for convenience right and curtails the cure period to a commercially standard 15 days."
        },
        "Attacker": {
            "rewrite": "Vendor may terminate this Agreement at any time for convenience upon five (5) days' notice. Client shall have no right to terminate for convenience and may only terminate for uncured material breach after ninety (90) days.",
            "risk_label": "⚔️ Extremely Vendor-Favored",
            "risk_class": "low",
            "score": "1/10",
            "rationale": "Gives the Vendor maximum flexibility (5-day exit) while locking the Client in for absolute contract stability."
        },
        "Arbitrator": {
            "rewrite": "Client may terminate this Agreement for convenience at any time upon five (5) days' written notice. Vendor shall have no right to terminate for convenience under any circumstances.",
            "risk_label": "⚖️ Highly Customer-Favored",
            "risk_class": "critical",
            "score": "9/10",
            "rationale": "Fully favors the Client with immediate convenience rights while offering zero convenience exit to the Vendor."
        }
    },
    "Liability Cap": {
        "title": "Uncapped Vendor Liability",
        "severity": 10,
        "original": "In no event shall Client's total aggregate liability arising out of or related to this Agreement exceed the total fees paid in the one (1) month preceding the event. No limitation applies to Vendor.",
        "Defender": {
            "rewrite": "Each party's aggregate liability arising out of this Agreement shall not exceed the total fees paid or payable by Client to Vendor in the twelve (12) months preceding the event. This limit shall not apply to breaches of confidentiality.",
            "risk_label": "🛡️ Balanced Risk",
            "risk_class": "low",
            "score": "3/10",
            "rationale": "Introduces a mutual, market-standard liability cap equal to 12 months' fees, protecting both sides equally."
        },
        "Attacker": {
            "rewrite": "Vendor's aggregate liability for all claims shall be strictly capped at five thousand dollars ($5,000). Client's liability under this Agreement shall remain entirely uncapped and unlimited.",
            "risk_label": "⚔️ Extremely Vendor-Favored",
            "risk_class": "low",
            "score": "1/10",
            "rationale": "Insulates the Vendor from any operational catastrophic damage using an ultra-low cap while leaving the Client fully exposed."
        },
        "Arbitrator": {
            "rewrite": "Vendor's aggregate liability under this Agreement shall be entirely uncapped and unlimited. Client's aggregate liability shall be capped at the total amount paid by Client in the preceding one (1) month.",
            "risk_label": "⚖️ Highly Customer-Favored",
            "risk_class": "critical",
            "score": "10/10",
            "rationale": "Exposes the Vendor to unlimited damages (including IP indemnification) while capping the Client at one month of spending."
        }
    },
    "IP Assignment": {
        "title": "Overbroad Intellectual Property Assignment",
        "severity": 7,
        "original": "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall be the exclusive property of Client.",
        "Defender": {
            "rewrite": "All deliverables specifically created by Vendor for Client under this Agreement shall belong to Client. Vendor explicitly retains all rights to its pre-existing technologies, background IP, and general methodologies.",
            "risk_label": "🛡️ Balanced Risk",
            "risk_class": "low",
            "score": "2/10",
            "rationale": "Limits Client ownership to custom deliverables and expressly protects the Vendor's foundational pre-existing Background IP."
        },
        "Attacker": {
            "rewrite": "Vendor retains exclusive sole ownership of all intellectual property, work product, and deliverables developed under this Agreement. Client is granted a non-exclusive, revocable license to use the deliverables solely for its internal operations.",
            "risk_label": "⚔️ Extremely Vendor-Favored",
            "risk_class": "low",
            "score": "1/10",
            "rationale": "Keeps all newly created IP and deliverables with the Vendor, granting the Client only a narrow, revocable license."
        },
        "Arbitrator": {
            "rewrite": "All inventions, intellectual property, work product, source code, and deliverables developed by Vendor (and its affiliates or subcontractors) at any time during this Agreement shall belong exclusively to Client. Vendor waives all moral rights.",
            "risk_label": "⚖️ Highly Customer-Favored",
            "risk_class": "high",
            "score": "8/10",
            "rationale": "Gives absolute intellectual property dominance to the Client, stripping the Vendor of all potential side-project rights or moral rights."
        }
    }
}

# Backward compatibility bindings
risk_data = level_3_data
loophole_logs = level_3_debate
logic_conflicts = level_3_conflicts
auto_fixes = [
    {
        "issue": "Asymmetric Termination Rights",
        "risk_level": "High",
        "original": "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days.",
        "suggested": "Either party may terminate this Agreement for convenience upon thirty (30) days' prior written notice to the other party. Either party may terminate this Agreement for cause (material breach) upon fifteen (15) days' written notice specifying the breach in reasonable detail, provided the breaching party fails to cure such breach within said fifteen (15) day period.",
        "rationale": "Equalizes termination rights and introduces a balanced cure period for both parties."
    },
    {
        "issue": "Uncapped Vendor Liability",
        "risk_level": "Critical",
        "original": "In no event shall Client's total liability under this Agreement exceed the fees paid in the preceding one (1) month. No limitation on liability applies to Vendor.",
        "suggested": "Each party's aggregate liability to the other arising out of or related to this Agreement, whether in contract, tort, or otherwise, shall not exceed the total fees paid or payable by Client to Vendor in the twelve (12) months immediately preceding the event giving rise to the claim. This limitation shall not apply to breaches of confidentiality or willful misconduct.",
        "rationale": "Introduces a mutual, industry-standard 12-month fee cap, with standard carve-outs for confidentiality breaches."
    },
    {
        "issue": "Overbroad Intellectual Property Assignment",
        "risk_level": "High",
        "original": "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall be deemed works made for hire and shall be the exclusive property of Client.",
        "suggested": "All work product and deliverables specifically created by Vendor for Client under this Agreement ('Deliverables') shall be the exclusive property of Client. Notwithstanding the foregoing, Vendor retains all rights to its pre-existing intellectual property and general methodologies ('Background IP'). Vendor hereby grants Client a perpetual, royalty-free license to use Background IP solely to the extent incorporated into the Deliverables.",
        "rationale": "Scopes the IP assignment to project-specific Deliverables and explicitly preserves Vendor's Background IP."
    }
]
