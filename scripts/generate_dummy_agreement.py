import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def create_agreement_pdf(filename="Vulnerable_Agreement_Draft.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom high-quality styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        alignment=1, # Center
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        alignment=1,
        spaceAfter=30
    )
    
    heading2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e3a8a'),
        spaceBefore=12,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'AgreementBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155'),
        spaceAfter=10
    )
    
    clause_box_style = ParagraphStyle(
        'ClauseBox',
        parent=body_style,
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#7f1d1d'),
        backColor=colors.HexColor('#fef2f2'),
        borderColor=colors.HexColor('#fca5a5'),
        borderWidth=1,
        borderPadding=8,
        spaceAfter=12
    )

    story = []
    
    # Page 1: Title & Introduction
    story.append(Spacer(1, 40))
    story.append(Paragraph("MUTUAL NON-DISCLOSURE AND MASTER SERVICES AGREEMENT", title_style))
    story.append(Paragraph("Draft Version 3.2 — Subject to Legal Review", subtitle_style))
    story.append(Spacer(1, 20))
    
    intro_text = (
        "This Mutual Non-Disclosure and Master Services Agreement (the <b>\"Agreement\"</b>) is entered into "
        "and made effective as of May 20, 2026 (the <b>\"Effective Date\"</b>), by and between <b>Acme Global Solutions Inc.</b> "
        "(hereinafter referred to as <b>\"Client\"</b>), and <b>Regulaite AI Technologies LLC</b> "
        "(hereinafter referred to as <b>\"Vendor\"</b>). The Client and the Vendor may collectively be referred to as "
        "the \"Parties\" or individually as a \"Party.\""
    )
    story.append(Paragraph(intro_text, body_style))
    
    purpose_text = (
        "<b>WHEREAS</b>, the Parties wish to explore a potential business relationship in which Vendor provides "
        "advanced artificial intelligence and compliance scanning services to the Client, which relationship may "
        "require the disclosure of proprietary and confidential information by each Party; and "
        "<b>NOW, THEREFORE</b>, in consideration of the mutual covenants contained herein, the Parties agree as follows:"
    )
    story.append(Paragraph(purpose_text, body_style))
    
    # Section 1: Confidentiality & Data Retention
    story.append(Paragraph("1. Confidentiality and Data Use", heading2_style))
    story.append(Paragraph(
        "Each Party acknowledges that in the course of performance, it may have access to the other Party's "
        "proprietary or confidential information, including trade secrets, software designs, business plans, "
        "and customer list data.", body_style
    ))
    
    # [VULNERABILITY: LOGIC CONFLICT PART 1]
    conflict_1_text = (
        "<b>Section 2.1 (Data Destruction Clause):</b> All confidential data, including customer records and "
        "transaction logs, must be permanently and irreversibly destroyed within thirty (30) days of contract termination. "
        "Vendor shall certify such destruction in writing to the Client's chief compliance officer."
    )
    story.append(Paragraph("<b>[FLAGGED AREA]</b> " + conflict_1_text, clause_box_style))
    
    story.append(PageBreak())
    
    # Page 2: Services, Intellectual Property, and Payment
    story.append(Paragraph("2. Services and Payment Terms", heading2_style))
    
    # [VULNERABILITY: LOGIC CONFLICT PART 2]
    payment_body_text = (
        "<b>Section 3.1 (Payment Terms):</b> All invoices issued under this Agreement are payable within "
        "forty-five (45) days of receipt (Net 45) in US Dollars via wire transfer to Vendor's designated account."
    )
    story.append(Paragraph("<b>[FLAGGED AREA]</b> " + payment_body_text, clause_box_style))
    
    # Section 3: Intellectual Property
    story.append(Paragraph("3. Intellectual Property Rights", heading2_style))
    
    # [VULNERABILITY: OVERBROAD IP ASSIGNMENT]
    ip_assignment_text = (
        "<b>Section 6.3 (Intellectual Property Assignment):</b> All work product, inventions, discoveries, "
        "and improvements conceived or developed by Vendor, whether or not during working hours and whether or not "
        "using Client's resources, shall be deemed works made for hire and shall be the exclusive property of Client. "
        "Vendor retains zero Background IP rights and waives all moral rights globally."
    )
    story.append(Paragraph("<b>[FLAGGED AREA]</b> " + ip_assignment_text, clause_box_style))
    
    # [VULNERABILITY: LOGIC CONFLICT PART 1 bis - Retention]
    retention_body_text = (
        "<b>Section 5.4 (Backup and Regulatory Retention):</b> Vendor shall retain complete backups of all "
        "transactional data for a minimum period of three (3) years to ensure compliance with applicable financial "
        "regulations and data auditing standards."
    )
    story.append(Paragraph("<b>[FLAGGED AREA]</b> " + retention_body_text, clause_box_style))
    
    story.append(PageBreak())
    
    # Page 3: Termination, Liability, and Venue
    story.append(Paragraph("4. Term and Termination convenience", heading2_style))
    
    # [VULNERABILITY: TERMINATION ASYMMETRY]
    termination_asymmetry_text = (
        "<b>Section 9.1 (Asymmetrical Termination Rights):</b> Client may terminate this Agreement at any time "
        "for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach "
        "remaining uncured for sixty (60) days following formal written notice to the Client's executive board."
    )
    story.append(Paragraph("<b>[FLAGGED AREA]</b> " + termination_asymmetry_text, clause_box_style))
    
    # Section 5: Limitation of Liability
    story.append(Paragraph("5. Limitation of Liability and Cap", heading2_style))
    
    # [VULNERABILITY: UNCAPPED LIABILITY]
    liability_cap_text = (
        "<b>Section 10.4 (Asymmetrical Liability Cap):</b> Under no circumstances shall Client's aggregate "
        "liability arising out of or related to this Agreement exceed the total amount paid by Client to Vendor "
        "in the one (1) month preceding the event giving rise to the claim. No equivalent cap is placed upon "
        "Vendor's liability, which remains completely uncapped and unlimited."
    )
    story.append(Paragraph("<b>[FLAGGED AREA]</b> " + liability_cap_text, clause_box_style))
    
    # Section 6: Miscellaneous
    story.append(Paragraph("6. Governing Law and Venue", heading2_style))
    
    # [VULNERABILITY: LOGIC CONFLICT VENUE]
    venue_text_a = (
        "<b>Section 14.1 (Governing Law):</b> This Agreement shall be governed by, and construed in accordance "
        "with, the laws of the State of Delaware, without regard to conflict of laws principles."
    )
    venue_text_b = (
        "<b>Section 14.3 (Dispute Resolution Venue):</b> Any disputes arising hereunder shall be submitted "
        "to binding arbitration in San Francisco, California, under the JAMS arbitration rules."
    )
    story.append(Paragraph("<b>[FLAGGED AREA]</b> " + venue_text_a, clause_box_style))
    story.append(Paragraph("<b>[FLAGGED AREA]</b> " + venue_text_b, clause_box_style))
    
    # Schedule A excerpt
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Schedule A, Clause 7 (Pricing Schedule):</b> All payments for services designated as Premium Tier are due within fifteen (15) days of invoice receipt (Net 15), with a 1.5% monthly late fee applied thereafter.", clause_box_style))
    
    # Build Document
    doc.build(story)
    print(f"Agreement PDF generated successfully: {filename}")

if __name__ == "__main__":
    create_agreement_pdf()
