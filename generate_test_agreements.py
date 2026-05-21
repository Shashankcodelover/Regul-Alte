import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def create_perfect_agreement(filename="Perfect_Standard_Agreement.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=18, leading=22,
        textColor=colors.HexColor('#0f172a'), alignment=1, spaceAfter=15
    )
    heading2_style = ParagraphStyle(
        'SectionHeading', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=12, leading=16,
        textColor=colors.HexColor('#0284c7'), spaceBefore=12, spaceAfter=6
    )
    body_style = ParagraphStyle(
        'AgreementBody', parent=styles['Normal'],
        fontName='Helvetica', fontSize=10, leading=14,
        textColor=colors.HexColor('#334155'), spaceAfter=10
    )
    clause_box_style = ParagraphStyle(
        'ClauseBox', parent=body_style,
        fontName='Helvetica', fontSize=10, leading=14,
        textColor=colors.HexColor('#065f46'), backColor=colors.HexColor('#ecfdf5'),
        borderColor=colors.HexColor('#a7f3d0'), borderWidth=1, borderPadding=8, spaceAfter=12
    )

    story = []
    story.append(Spacer(1, 20))
    story.append(Paragraph("MUTUAL SERVICES AGREEMENT (COMMERCIALLY BALANCED)", title_style))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("This Mutual Services Agreement (the <b>\"Agreement\"</b>) is entered into as of May 20, 2026, by and between <b>Acme Global Solutions Inc.</b> (\"Client\") and <b>Regulaite AI Technologies LLC</b> (\"Vendor\"). The parties agree to the following terms:", body_style))
    
    story.append(Paragraph("1. Confidentiality & Retention", heading2_style))
    story.append(Paragraph("<b>Section 2.1 (Data Protection):</b> All confidential information shall be returned or destroyed within thirty (30) days of termination. The Vendor may retain a limited copy in secure, automated backups for regulatory purposes, provided such copy is kept strictly confidential.", clause_box_style))
    
    story.append(Paragraph("2. Fees and Payments", heading2_style))
    story.append(Paragraph("<b>Section 3.1 (Standard Payments):</b> Invoices shall be paid within thirty (30) days of receipt (Net 30) by bank transfer in USD.", clause_box_style))
    
    story.append(Paragraph("3. Intellectual Property Preservation", heading2_style))
    story.append(Paragraph("<b>Section 6.3 (Balanced Intellectual Property):</b> Vendor retains all right, title, and interest in its pre-existing background technologies, software, and general methods. Vendor grants Client a perpetual, royalty-free, non-exclusive license to use such background IP solely as integrated into the final deliverables. Client shall own all custom, project-specific deliverables created hereunder.", clause_box_style))
    
    story.append(Paragraph("4. Term and Termination parity", heading2_style))
    story.append(Paragraph("<b>Section 9.1 (Balanced Termination):</b> Either party may terminate this Agreement for convenience at any time upon thirty (30) days' written notice to the other party. Either party may terminate for material breach if such breach remains uncured for fifteen (15) days after written notice.", clause_box_style))
    
    story.append(Paragraph("5. Mutual Limitation of Liability", heading2_style))
    story.append(Paragraph("<b>Section 10.4 (Reciprocal Cap):</b> Each party's total aggregate liability arising out of this Agreement shall be capped at the total fees paid or payable in the twelve (12) months preceding the event. This cap does not apply to breaches of confidentiality or willful misconduct.", clause_box_style))
    
    story.append(Paragraph("6. Governing Law & Dispute Resolution", heading2_style))
    story.append(Paragraph("<b>Section 14.1 (Governing Law & Forum):</b> This Agreement is governed by the laws of Delaware. Any disputes shall be submitted to the state or federal courts located in Delaware.", clause_box_style))
    
    doc.build(story)
    print(f"Balanced PDF generated successfully: {filename}")

def create_mild_agreement(filename="Mildly_Risky_Agreement.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=18, leading=22,
        textColor=colors.HexColor('#0f172a'), alignment=1, spaceAfter=15
    )
    heading2_style = ParagraphStyle(
        'SectionHeading', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=12, leading=16,
        textColor=colors.HexColor('#d97706'), spaceBefore=12, spaceAfter=6
    )
    body_style = ParagraphStyle(
        'AgreementBody', parent=styles['Normal'],
        fontName='Helvetica', fontSize=10, leading=14,
        textColor=colors.HexColor('#334155'), spaceAfter=10
    )
    clause_box_style = ParagraphStyle(
        'ClauseBox', parent=body_style,
        fontName='Helvetica', fontSize=10, leading=14,
        textColor=colors.HexColor('#78350f'), backColor=colors.HexColor('#fffbeb'),
        borderColor=colors.HexColor('#fde68a'), borderWidth=1, borderPadding=8, spaceAfter=12
    )

    story = []
    story.append(Spacer(1, 20))
    story.append(Paragraph("PARTNERSHIP AGREEMENT (SEMI-BALANCED)", title_style))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("This Partnership Agreement is made between Acme Global Solutions Inc. (\"Client\") and Regulaite AI Technologies LLC (\"Vendor\"). This document is moderately balanced but contains minor asymmetries that require scrutiny:", body_style))
    
    story.append(Paragraph("1. Confidentiality and Retention", heading2_style))
    story.append(Paragraph("<b>Section 2.1 (Data Cleanse):</b> All confidential information must be destroyed within thirty (30) days of termination. No backup retention exceptions are stated.", clause_box_style))
    
    story.append(Paragraph("2. Payment Terms", heading2_style))
    story.append(Paragraph("<b>Section 3.1 (Payments):</b> Client shall pay invoices in Net 30. However, Schedule B designates Premium Tier consulting payments as Net 20.", clause_box_style))
    
    story.append(Paragraph("3. Intellectual Property Rights", heading2_style))
    story.append(Paragraph("<b>Section 6.3 (IP Exclusivity):</b> Client shall own all custom deliverables. Vendor retains Background IP, but grants Client an exclusive, irrevocable license to Vendor's background software within North America.", clause_box_style))
    
    story.append(Paragraph("4. Termination notice asymmetry", heading2_style))
    story.append(Paragraph("<b>Section 9.1 (Notice Periods):</b> Client may terminate this Agreement upon fifteen (15) days' written notice, whereas Vendor may terminate only upon forty-five (45) days' notice.", clause_box_style))
    
    story.append(Paragraph("5. Partially Asymmetric Liability Cap", heading2_style))
    story.append(Paragraph("<b>Section 10.4 (Liability Cap):</b> Client's aggregate liability under this Agreement is capped at three (3) months' fees, while Vendor's aggregate liability is capped at six (6) months' fees.", clause_box_style))
    
    story.append(Paragraph("6. Governing Law & Dispute Resolution", heading2_style))
    story.append(Paragraph("<b>Section 14.1 (Governing Law):</b> Governed by California law. Any disputes shall be arbitrated in San Francisco under JAMS rules.", clause_box_style))
    
    doc.build(story)
    print(f"Semi-balanced PDF generated successfully: {filename}")

if __name__ == "__main__":
    create_perfect_agreement()
    create_mild_agreement()
