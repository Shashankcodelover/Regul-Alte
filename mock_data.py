
# mock_data.py — Realistic AI backend output payloads

risk_data = {
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
    "analyzed_date": "07 Nov 2025",
    "last_edited": "Anna K., Associate",
    "filename": "NDA_v3.2_Draft.pdf",
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
        },
    ]
}

loophole_logs = [
    {
        "role": "Exploiter",
        "content": (
            "Initiating analysis on Section 4.2 — the indemnification clause. "
            "The phrase 'regardless of fault' is extraordinary. It means the Vendor indemnifies the Client "
            "even if the Client's own recklessness caused the incident. This is the single most dangerous clause in the document."
        )
    },
    {
        "role": "Defender",
        "content": (
            "Confirmed. However, it's worth noting that several U.S. courts apply the 'express negligence doctrine,' "
            "requiring explicit and unambiguous language to hold a party indemnified against its own negligence. "
            "Depending on jurisdiction, this clause may be partially unenforceable — but it's still a severe risk "
            "that must be flagged and renegotiated."
        )
    },
    {
        "role": "Exploiter",
        "content": (
            "Moving to the liability cap in Section 10.4. The Client's liability is limited to one month of fees. "
            "On a $500K/year contract, that's roughly $41,667. Meanwhile, the Vendor has zero liability cap. "
            "If the Vendor makes a mistake worth $10M, they owe $10M. If the Client makes a mistake worth $10M, "
            "they owe $41,667. This is a textbook adversarial clause."
        )
    },
    {
        "role": "Defender",
        "content": (
            "This asymmetry is undeniable and constitutes a critical risk factor. "
            "The Vendor's exposure is effectively unlimited. I recommend flagging this as the highest priority "
            "item for renegotiation. A mutual cap of 12 months of fees is the market standard."
        )
    },
    {
        "role": "Exploiter",
        "content": (
            "The IP assignment in Section 6.3 is also aggressive — it covers inventions conceived "
            "'whether or not during working hours and whether or not using Client's resources.' "
            "This language could theoretically capture the Vendor's own side projects if they are even tangentially related to the work."
        )
    },
    {
        "role": "Defender",
        "content": (
            "Agreed. The clause lacks a carve-out for pre-existing IP and general know-how. "
            "Without an IP Schedule explicitly listing Vendor's retained background IP, the Vendor risks signing away "
            "foundational technology they built before this engagement. This requires a Vendor IP Schedule amendment."
        )
    },
]

logic_conflicts = [
    {
        "conflict": "Data Retention vs. Data Destruction",
        "rule_a": "Section 2.1: 'All confidential data, including customer records and transaction logs, must be permanently and irreversibly destroyed within thirty (30) days of contract termination.'",
        "rule_b": "Section 5.4: 'Vendor shall retain complete backups of all transactional data for a minimum period of three (3) years to ensure compliance with applicable financial regulations.'",
        "explanation": "These clauses directly contradict each other if 'transactional data' (Section 5.4) qualifies as 'confidential data' (Section 2.1). The contract provides no definition or exemption to resolve this. Complying with one clause legally violates the other.",
        "severity": "Critical"
    },
    {
        "conflict": "Payment Terms: Body vs. Schedule A",
        "rule_a": "Section 3.1 (Body): 'All invoices issued under this Agreement are payable within forty-five (45) days of receipt (Net 45).'",
        "rule_b": "Schedule A, Clause 7: 'All payments for services designated as Premium Tier are due within fifteen (15) days of invoice receipt (Net 15), with a 1.5% monthly late fee applied thereafter.'",
        "explanation": "The contract body and the attached schedule specify different payment windows for the same services. The contract does not specify which document takes precedence, creating an enforcement ambiguity and potential for disputed late fees.",
        "severity": "High"
    },
    {
        "conflict": "Governing Law vs. Dispute Resolution Venue",
        "rule_a": "Section 14.1: 'This Agreement shall be governed by the laws of the State of Delaware.'",
        "rule_b": "Section 14.3: 'Any disputes arising hereunder shall be submitted to binding arbitration in San Francisco, California, under the JAMS arbitration rules.'",
        "explanation": "While not an outright contradiction, applying Delaware law in a California arbitration creates procedural complexity and potential conflicts between Delaware contract law and California mandatory arbitration statutes (e.g., Cal. Code Civ. Proc. § 1281.2). This requires explicit clarification.",
        "severity": "Medium"
    },
]

auto_fixes = [
    {
        "issue": "Asymmetric Termination Rights",
        "risk_level": "High",
        "original": (
            "Client may terminate this Agreement at any time for any reason upon five (5) days' written "
            "notice, whereas Vendor may only terminate upon a material breach remaining uncured for "
            "sixty (60) days."
        ),
        "suggested": (
            "Either party may terminate this Agreement for convenience upon thirty (30) days' prior written "
            "notice to the other party. Either party may terminate this Agreement for cause (material breach) "
            "upon fifteen (15) days' written notice specifying the breach in reasonable detail, provided the "
            "breaching party fails to cure such breach within said fifteen (15) day period."
        ),
        "rationale": "Equalizes termination rights and introduces a balanced cure period for both parties."
    },
    {
        "issue": "Uncapped Vendor Liability",
        "risk_level": "Critical",
        "original": (
            "In no event shall Client's total liability under this Agreement exceed the fees paid in the "
            "preceding one (1) month. No limitation on liability applies to Vendor."
        ),
        "suggested": (
            "Each party's aggregate liability to the other arising out of or related to this Agreement, "
            "whether in contract, tort, or otherwise, shall not exceed the total fees paid or payable by "
            "Client to Vendor in the twelve (12) months immediately preceding the event giving rise to "
            "the claim. This limitation shall not apply to breaches of confidentiality or willful misconduct."
        ),
        "rationale": "Introduces a mutual, industry-standard 12-month fee cap, with standard carve-outs for confidentiality breaches."
    },
    {
        "issue": "Overbroad Intellectual Property Assignment",
        "risk_level": "High",
        "original": (
            "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, "
            "whether or not during working hours and whether or not using Client's resources, shall be deemed "
            "works made for hire and shall be the exclusive property of Client."
        ),
        "suggested": (
            "All work product and deliverables specifically created by Vendor for Client under this Agreement "
            "('Deliverables') shall be the exclusive property of Client. Notwithstanding the foregoing, Vendor "
            "retains all rights to its pre-existing intellectual property and general methodologies ('Background IP'). "
            "Vendor hereby grants Client a perpetual, royalty-free license to use Background IP solely to the "
            "extent incorporated into the Deliverables."
        ),
        "rationale": "Scopes the IP assignment to project-specific Deliverables and explicitly preserves Vendor's Background IP."
    },
]
