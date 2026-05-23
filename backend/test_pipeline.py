"""
test_pipeline.py
================
Smoke test for the AI orchestration pipeline.
Run from backend/ folder:
    python test_pipeline.py
"""

import asyncio
import sys
import os

# Ensure backend/ (current directory) is on path so ai_orchestration imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SAMPLE_CONTRACT = """
MASTER SERVICES AGREEMENT

This Master Services Agreement ("Agreement") is entered into as of January 1, 2025,
between CloudServe Inc. ("Vendor") and Acme Corp. ("Client").

1. SERVICES
1.1 Vendor shall provide cloud hosting and software development services as described in Schedule A.
1.2 Vendor warrants that all services will be performed in a professional manner.

2. PAYMENT
2.1 Client shall pay all invoices within Net 45 days of receipt.
2.2 All payments are non-refundable once services have commenced.
2.3 Late payments shall accrue interest at 24% per annum.

3. DATA AND PRIVACY
3.1 Vendor will process personal data of Client's customers in connection with the services.
3.2 All confidential data must be permanently and irreversibly destroyed within thirty (30) days
    of contract termination.
3.3 Vendor shall retain complete backups of all transactional data for a minimum period of
    three (3) years to ensure compliance with applicable financial regulations.

4. INDEMNIFICATION
4.1 Vendor agrees to indemnify, defend, and hold harmless the Client from and against any and
    all claims, losses, liabilities, damages, expenses, and costs arising out of or related to
    the Vendor's performance under this Agreement, regardless of fault.

5. INTELLECTUAL PROPERTY
5.1 All work product, inventions, discoveries, and improvements conceived or developed by Vendor,
    whether or not during working hours and whether or not using Client's resources, shall be
    deemed works made for hire and shall be the exclusive property of Client.

6. TERMINATION
6.1 Client may terminate this Agreement at any time for any reason upon five (5) days' written
    notice, whereas Vendor may only terminate upon a material breach remaining uncured for
    sixty (60) days following written notice.

7. LIABILITY
7.1 In no event shall Client's total aggregate liability arising out of or related to this
    Agreement exceed the total fees paid in the one (1) month preceding the event giving rise
    to the claim. No equivalent cap is placed upon Vendor's liability.

8. GOVERNING LAW
8.1 This Agreement shall be governed by the laws of the State of Delaware.
8.2 Any disputes arising hereunder shall be submitted to binding arbitration in San Francisco,
    California, under the JAMS arbitration rules.

9. NON-COMPETE
9.1 Vendor agrees not to compete with Client in any business activity for a perpetual period
    following termination of this Agreement.
"""

REQUIRED_KEYS = [
    "score", "verdict", "summary", "pages_analyzed", "identified_risks",
    "red_flags", "loophole_logs", "logic_conflicts", "auto_fixes",
    "overall_risk_score", "jurisdiction", "contract_completeness",
    "party_bias", "party_bias_label", "clauses", "contradictions",
    "violations", "missing_clauses", "key_dates",
]


async def main():
    print("=" * 60)
    print("RegulAIte AI Orchestration Pipeline Test")
    print("=" * 60)

    from ai_orchestration.pipeline import run_pipeline

    print("\n[1] Running pipeline on 9-clause test contract...")
    result = await run_pipeline(SAMPLE_CONTRACT, anthropic_api_key="", filename="test_contract.pdf")

    print("\n[2] Checking required keys...")
    missing_keys = []
    for key in REQUIRED_KEYS:
        if key not in result:
            missing_keys.append(key)
            print(f"  [ERR] MISSING: {key}")
        else:
            print(f"  [OK] {key}: {str(result[key])[:60]}")

    print("\n[3] Pipeline results summary:")
    print(f"  Overall risk score : {result.get('overall_risk_score', '?')}/100")
    print(f"  Verdict            : {result.get('verdict', '?')}")
    print(f"  Jurisdiction       : {result.get('jurisdiction', '?')}")
    print(f"  Completeness       : {result.get('contract_completeness', '?')}%")
    print(f"  Party bias         : {result.get('party_bias', '?')} — {result.get('party_bias_label', '?')}")
    print(f"  Clauses extracted  : {len(result.get('clauses', []))}")
    print(f"  Red flags          : {len(result.get('red_flags', []))}")
    print(f"  Contradictions     : {len(result.get('contradictions', []))}")
    print(f"  Violations         : {len(result.get('violations', []))}")
    print(f"  Missing clauses    : {result.get('missing_clauses', [])}")
    print(f"  Key dates          : {result.get('key_dates', [])[:3]}")

    print("\n[4] Checking /clauses store...")
    from ai_orchestration.pipeline import get_stored_clauses
    stored = get_stored_clauses()
    assert stored, "Clause store is empty after pipeline run!"
    assert stored["clause_count"] > 0, "No clauses stored!"
    print(f"  [OK] {stored['clause_count']} clauses stored in memory.")
    print(f"  [OK] Filename: {stored['filename']}")
    print(f"  [OK] Analyzed at: {stored['analyzed_at']}")

    if missing_keys:
        print(f"\n[ERR] PIPELINE TEST FAILED — missing keys: {missing_keys}")
        sys.exit(1)
    else:
        print("\n" + "=" * 60)
        print("PIPELINE TEST OK")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
