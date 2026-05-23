"""
create_sample_pdfs.py
Creates 3 real-world sample contract PDFs whose clause text matches the
mock_data.py Level 1/2/3 analysis payloads exactly.
Run from the project root:  python scripts/create_sample_pdfs.py
"""

import os
import sys

# Try to use reportlab for proper PDFs; fallback to fpdf2
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
    BACKEND = "reportlab"
except ImportError:
    try:
        from fpdf import FPDF
        BACKEND = "fpdf"
    except ImportError:
        print("ERROR: Install reportlab or fpdf2 first:  pip install reportlab")
        sys.exit(1)

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_agreements")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ─── AGREEMENT CONTENT DEFINITIONS ──────────────────────────────────────────

LEVEL_1_CLAUSES = [
    ("MUTUAL NON-DISCLOSURE AND SERVICES AGREEMENT", None, True),
    ("Effective Date: June 1, 2026", None, False),
    ("Parties: Acme Corp ('Client') and TechServe Solutions Pvt Ltd ('Vendor')", None, False),
    ("", None, False),
    ("1. SERVICES", "SECTION", False),
    ("Vendor shall provide software development and consulting services as described in Schedule A attached hereto. Vendor shall use commercially reasonable efforts to deliver all services in accordance with the agreed project milestones.", None, False),
    ("2. PAYMENT TERMS", "SECTION", False),
    ("All invoices issued under this Agreement are payable within thirty (30) days of receipt. Late payments beyond thirty (30) days shall accrue interest at 1.5% per month. All Premium Tier consulting services under Schedule A shall also follow the standard thirty (30) day payment terms.", None, False),
    ("3. TERMINATION", "SECTION", False),
    ("Either party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice to the other party. Either party may terminate this Agreement for material breach remaining uncured for fifteen (15) days following written notice specifying such breach in reasonable detail.", None, False),
    ("4. LIABILITY CAP", "SECTION", False),
    ("Each party's aggregate liability arising out of or related to this Agreement shall not exceed the total fees paid or payable by Client to Vendor in the twelve (12) months preceding the event giving rise to the claim. This mutual cap applies equally to both parties. This limitation shall not apply to breaches of confidentiality or willful misconduct.", None, False),
    ("5. INDEMNIFICATION", "SECTION", False),
    ("Each party ('Indemnifying Party') shall indemnify, defend, and hold harmless the other party from and against third-party claims arising out of the Indemnifying Party's own gross negligence or willful misconduct. Neither party shall be required to indemnify the other for the other party's own negligent acts.", None, False),
    ("6. INTELLECTUAL PROPERTY", "SECTION", False),
    ("All deliverables and work product specifically created by Vendor for Client under this Agreement ('Deliverables') shall be the exclusive property of Client upon full payment. Notwithstanding the foregoing, Vendor explicitly retains all rights to its pre-existing intellectual property, background technology, and general methodologies ('Background IP'). Vendor hereby grants Client a perpetual, royalty-free, non-exclusive license to use Background IP solely to the extent incorporated into the Deliverables.", None, False),
    ("7. DATA PROTECTION", "SECTION", False),
    ("Both parties shall comply with applicable data protection laws including GDPR and IT Act 2000. All personal data shall be processed only as necessary for performing the services. Upon termination, both parties shall delete all personal data within thirty (30) days, except where retention is required by applicable law or regulatory mandate, in which case such data shall be retained securely and destroyed upon expiry of the mandatory retention period.", None, False),
    ("8. GOVERNING LAW", "SECTION", False),
    ("This Agreement shall be governed by the laws of India. Any disputes shall be resolved by binding arbitration in Bangalore, Karnataka, India, under the Arbitration and Conciliation Act, 1996.", None, False),
    ("9. ENTIRE AGREEMENT", "SECTION", False),
    ("This Agreement constitutes the entire understanding between the parties with respect to its subject matter and supersedes all prior agreements. In the event of any conflict between the main body of this Agreement and any Schedule, the terms of the main body shall prevail.", None, False),
    ("", None, False),
    ("Signed and agreed by duly authorized representatives of both parties.", None, False),
]

LEVEL_2_CLAUSES = [
    ("TECHNOLOGY SERVICES AGREEMENT — MILDLY ASYMMETRIC DRAFT", None, True),
    ("Effective Date: June 1, 2026", None, False),
    ("Parties: GlobalTech Inc ('Client') and BuildSoft Pvt Ltd ('Vendor')", None, False),
    ("", None, False),
    ("1. SERVICES", "SECTION", False),
    ("Vendor shall provide software engineering, deployment, and support services as described in Schedule A. Vendor will assign dedicated resources for each project phase.", None, False),
    ("2. PAYMENT TERMS", "SECTION", False),
    ("All invoices issued under this Agreement are payable within thirty (30) days of receipt (Net 30). However, Schedule B designates all Premium Tier consulting and deployment services as payable within fifteen (15) days of invoice receipt (Net 15). Late payment interest shall apply at 2% per month.", None, False),
    ("3. TERMINATION — NOTICE PERIOD ASYMMETRY", "SECTION", False),
    ("Client may terminate this Agreement upon fifteen (15) days' written notice for any reason. Vendor may terminate this Agreement only upon forty-five (45) days' written notice, and only in the event of Client's material breach remaining uncured for twenty (20) days following written notice.", None, False),
    ("4. LIABILITY CAP", "SECTION", False),
    ("Client's aggregate liability under this Agreement is capped at the total fees paid in the three (3) months preceding the event giving rise to the claim. Vendor's aggregate liability under this Agreement is capped at the total fees paid in the six (6) months preceding the event. Neither cap shall apply to breaches of confidentiality.", None, False),
    ("5. INDEMNIFICATION", "SECTION", False),
    ("Vendor shall indemnify Client against third-party claims arising from Vendor's negligence. Client shall indemnify Vendor against third-party claims arising from Client's negligence or misuse of the services. Mutual indemnification is limited to proven negligence of the indemnifying party.", None, False),
    ("6. INTELLECTUAL PROPERTY", "SECTION", False),
    ("All deliverables created under this Agreement shall become the property of Client upon full payment. Vendor retains Background IP and general methodologies developed prior to or independently of this engagement. Client receives a non-exclusive license to use Background IP in delivered work.", None, False),
    ("7. DATA RETENTION", "SECTION", False),
    ("Vendor shall retain all project data and backups for a minimum of twelve (12) months following project completion for audit and support purposes. Upon contract termination, personal data shall be deleted within sixty (60) days unless otherwise required by applicable law.", None, False),
    ("8. GOVERNING LAW", "SECTION", False),
    ("This Agreement is governed by the laws of the State of Karnataka, India. Disputes shall be escalated first to senior management mediation for thirty (30) days before any arbitration proceeding.", None, False),
]

LEVEL_3_CLAUSES = [
    ("ENTERPRISE MASTER SERVICES AGREEMENT — DRAFT v0.1 (HIGHLY VENDOR RESTRICTIVE)", None, True),
    ("Effective Date: June 1, 2026", None, False),
    ("Parties: MegaCorp Global Ltd ('Client') and TechServe Vendors Pvt Ltd ('Vendor')", None, False),
    ("", None, False),
    ("IMPORTANT NOTICE: This draft contains several clauses that are severely disadvantageous to the Vendor. Legal review is strongly advised before signing.", None, False),
    ("", None, False),
    ("1. SERVICES", "SECTION", False),
    ("Vendor shall provide all software development, deployment, operations, and support services as directed by Client from time to time. Client reserves the right to modify the scope of services at any time without additional compensation.", None, False),
    ("2. PAYMENT TERMS", "SECTION", False),
    ("All invoices are payable within forty-five (45) days of receipt (Net 45). Client reserves the right to withhold payment for any deliverables deemed unsatisfactory in Client's sole discretion, without obligation to provide detailed justification.", None, False),
    ("3. TERMINATION — CRITICAL ASYMMETRY", "SECTION", False),
    ("Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days following written notice. Upon termination for any reason, Vendor must continue providing transition services for up to six (6) months at no additional charge.", None, False),
    ("4. INDEMNIFICATION — REGARDLESS OF FAULT", "SECTION", False),
    ("Vendor agrees to indemnify, defend, and hold harmless the Client from and against any and all claims, losses, liabilities, damages, expenses, and costs (including reasonable attorneys' fees) arising out of or related to the Vendor's performance under this Agreement, regardless of fault. This obligation shall survive termination of this Agreement indefinitely.", None, False),
    ("5. LIABILITY CAP — UNCAPPED VENDOR LIABILITY", "SECTION", False),
    ("Under no circumstances shall Client's aggregate liability arising out of or related to this Agreement exceed the total amount paid by Client to Vendor in the one (1) month preceding the event giving rise to the claim. No equivalent cap is placed upon Vendor's liability. Vendor's liability under this Agreement shall remain entirely uncapped and unlimited.", None, False),
    ("6. INTELLECTUAL PROPERTY — OVERBROAD ASSIGNMENT", "SECTION", False),
    ("All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall be deemed works made for hire and shall be the exclusive property of Client. This includes all background IP, pre-existing tools, and general methodologies used during the engagement.", None, False),
    ("7. DATA RETENTION vs. DATA DESTRUCTION — CONTRADICTORY CLAUSES", "SECTION", False),
    ("Section 7.1 — Data Destruction: All confidential data, including customer records and transaction logs, must be permanently and irreversibly destroyed within thirty (30) days of contract termination.", None, False),
    ("Section 7.2 — Data Retention: Vendor shall retain complete backups of all transactional data for a minimum period of three (3) years to ensure compliance with applicable financial regulations and tax audit requirements.", None, False),
    ("NOTE: Sections 7.1 and 7.2 directly contradict each other. Complying with Section 7.1 (destroy within 30 days) makes it legally impossible to comply with Section 7.2 (retain for 3 years). This is an unresolved logical conflict.", None, False),
    ("8. NON-COMPETE — HIGHLY RESTRICTIVE", "SECTION", False),
    ("Vendor agrees not to engage with any company that competes with Client in any capacity for a period of five (5) years following termination, in any jurisdiction worldwide, without Client's prior written consent.", None, False),
    ("9. GOVERNING LAW", "SECTION", False),
    ("This Agreement shall be governed exclusively by the laws of the State of Delaware, United States. All disputes must be resolved by binding arbitration in San Francisco, California, under JAMS arbitration rules, at Vendor's sole cost and expense.", None, False),
    ("", None, False),
    ("THIS AGREEMENT CONTAINS CRITICAL LEGAL RISKS. DO NOT SIGN WITHOUT INDEPENDENT LEGAL REVIEW.", None, False),
]


# ─── PDF GENERATION USING REPORTLAB ─────────────────────────────────────────

def make_pdf_reportlab(filename, clauses):
    filepath = os.path.join(OUTPUT_DIR, filename)
    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        rightMargin=60, leftMargin=60, topMargin=60, bottomMargin=60
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title", parent=styles["Heading1"],
        fontSize=13, leading=18, spaceAfter=12,
        textColor=colors.HexColor("#111827"), alignment=1
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"],
        fontSize=10, leading=14, spaceBefore=12, spaceAfter=4,
        textColor=colors.HexColor("#1e3a8a"), fontName="Helvetica-Bold"
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9.5, leading=15, spaceAfter=6,
        textColor=colors.HexColor("#374151")
    )
    note_style = ParagraphStyle(
        "Note", parent=styles["Normal"],
        fontSize=8.5, leading=13, spaceAfter=6,
        textColor=colors.HexColor("#dc2626"),
        backColor=colors.HexColor("#fff5f5"),
        borderPad=4
    )

    story = []
    for text, style_hint, is_title in clauses:
        if not text:
            story.append(Spacer(1, 8))
            continue
        if is_title:
            story.append(Paragraph(text, title_style))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e5e7eb"), spaceAfter=8))
        elif style_hint == "SECTION":
            story.append(Paragraph(text, section_style))
        elif "NOTE:" in text or "IMPORTANT" in text or "CRITICAL" in text or "DO NOT SIGN" in text:
            story.append(Paragraph(text, note_style))
        else:
            story.append(Paragraph(text, body_style))

    doc.build(story)
    print(f"[OK] Created: {filepath}")


# ─── PDF GENERATION USING FPDF (FALLBACK) ────────────────────────────────────

def make_pdf_fpdf(filename, clauses):
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    for text, style_hint, is_title in clauses:
        if not text:
            pdf.ln(4)
            continue
        if is_title:
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(17, 24, 39)
            pdf.multi_cell(0, 7, text, align="C")
            pdf.ln(2)
        elif style_hint == "SECTION":
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(30, 58, 138)
            pdf.multi_cell(0, 6, text)
            pdf.ln(1)
        elif "NOTE:" in text or "IMPORTANT" in text or "CRITICAL" in text:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(220, 38, 38)
            pdf.multi_cell(0, 5, text)
            pdf.ln(1)
        else:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(55, 65, 81)
            pdf.multi_cell(0, 5, text)
            pdf.ln(1)

    filepath = os.path.join(OUTPUT_DIR, filename)
    pdf.output(filepath)
    print(f"[OK] Created: {filepath}")


# ─── TEXT GENERATION ──────────────────────────────────────────────────────────

def make_txt(filename, clauses):
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        for text, type_val, is_title in clauses:
            if not text.strip():
                f.write("\n")
            elif is_title:
                f.write(f"=== {text} ===\n\n")
            elif type_val == "SECTION":
                f.write(f"\n{text}\n")
                f.write("-" * len(text) + "\n")
            else:
                f.write(f"{text}\n")
    print(f"[OK] Created Text: {filepath}")


# ─── MAIN ────────────────────────────────────────────────────────────────────

def make_pdf(filename, clauses):
    if BACKEND == "reportlab":
        make_pdf_reportlab(filename, clauses)
    else:
        make_pdf_fpdf(filename, clauses)


if __name__ == "__main__":
    print(f"Using backend: {BACKEND}")
    print(f"Output dir:    {OUTPUT_DIR}\n")

    # Generate PDFs
    make_pdf("Perfect_Standard_Agreement.pdf", LEVEL_1_CLAUSES)
    make_pdf("Mildly_Risky_Agreement.pdf",     LEVEL_2_CLAUSES)
    make_pdf("Vulnerable_Agreement_Draft.pdf", LEVEL_3_CLAUSES)

    # Generate TXTs for copy-paste testing
    make_txt("Perfect_Standard_Agreement.txt", LEVEL_1_CLAUSES)
    make_txt("Mildly_Risky_Agreement.txt",     LEVEL_2_CLAUSES)
    make_txt("Vulnerable_Agreement_Draft.txt", LEVEL_3_CLAUSES)

    print("\n[DONE] All 3 sample agreements (PDF & TXT) created successfully!")
    print("[DIR]  Location:", OUTPUT_DIR)
