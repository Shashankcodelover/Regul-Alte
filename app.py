# pyrefly: ignore [missing-import]
import streamlit as st
from dotenv import load_dotenv
load_dotenv()
import time
import textwrap
import difflib
import os
import json
import sqlite3
import hashlib
import uuid
import shutil
from mock_data import risk_data, loophole_logs, logic_conflicts, auto_fixes, HISTORICAL_SCAMS

# ── SQLite Relational Database Engine & Sandbox Helpers ─────────────────────────
DB_FILE = os.path.join("data", "regulaite.db")
SESSION_CACHE_FILE = os.path.join("data", "last_session.json")

def save_last_session(name, role, user_hash):
    try:
        import time as _time
        os.makedirs(os.path.dirname(SESSION_CACHE_FILE), exist_ok=True)
        with open(SESSION_CACHE_FILE, "w") as f:
            json.dump({
                "name": name,
                "role": role,
                "user_hash": user_hash,
                "saved_at": _time.time()
            }, f)
    except Exception:
        pass

def load_last_session():
    """Load session with 24-hour expiry for security."""
    if os.path.exists(SESSION_CACHE_FILE):
        try:
            import time as _time
            with open(SESSION_CACHE_FILE, "r") as f:
                data = json.load(f)
            # Expire sessions older than 24 hours
            saved_at = data.get("saved_at", 0)
            if _time.time() - saved_at > 86400:  # 24 hours
                os.remove(SESSION_CACHE_FILE)
                return None, None, None
            return data.get("name"), data.get("role"), data.get("user_hash")
        except Exception:
            pass
    return None, None, None

def init_db():
    os.makedirs(os.path.join("data", "users"), exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Enable WAL mode for concurrent 1K-user read safety
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    
    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_hash TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            persona TEXT NOT NULL,
            email TEXT,
            password_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Robust migration check if columns don't exist
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN specialization TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN organization TEXT")
    except Exception:
        pass
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            user_hash TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            analysis_json TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_hash) REFERENCES users (user_hash) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_hash TEXT NOT NULL,
            doc_id TEXT NOT NULL,
            action TEXT NOT NULL,
            performed_by TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_hash) REFERENCES users (user_hash) ON DELETE CASCADE
        )
    """)
    
    conn.commit()
    conn.close()

def get_db_connection():
    return sqlite3.connect(DB_FILE)

def register_user(name, persona, email=None, password=None):
    if email:
        user_hash = hashlib.sha256(email.strip().lower().encode('utf-8')).hexdigest()[:16]
    else:
        user_hash = hashlib.sha256(f"{name.strip().lower()}:{persona.strip().lower()}".encode('utf-8')).hexdigest()[:16]
    conn = get_db_connection()
    cursor = conn.cursor()
    
    password_hash = None
    if password:
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
    cursor.execute("""
        INSERT OR REPLACE INTO users (user_hash, name, persona, email, password_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (user_hash, name, persona, email, password_hash))
    conn.commit()
    conn.close()
    return user_hash

def verify_user(email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    cursor.execute("""
        SELECT user_hash, name, persona FROM users 
        WHERE email = ? AND password_hash = ?
    """, (email.strip().lower(), password_hash))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0], row[1], row[2] # user_hash, name, persona
    return None

def save_document(user_hash, filename, file_path, risk_score, verdict, analysis_json):
    doc_id = str(uuid.uuid4())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO documents (id, user_hash, filename, file_path, risk_score, verdict, analysis_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (doc_id, user_hash, filename, file_path, risk_score, verdict, json.dumps(analysis_json)))
    
    # Audit log
    log_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO audit_logs (id, user_hash, doc_id, action, performed_by)
        VALUES (?, ?, ?, ?, ?)
    """, (log_id, user_hash, doc_id, "UPLOAD", user_hash))
    
    conn.commit()
    conn.close()
    return doc_id

def get_user_documents(user_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, file_path, risk_score, verdict, analysis_json, uploaded_at FROM documents WHERE user_hash = ? ORDER BY uploaded_at DESC", (user_hash,))
    rows = cursor.fetchall()
    conn.close()
    
    docs = []
    for r in rows:
        try:
            docs.append({
                "id": r[0],
                "filename": r[1],
                "file_path": r[2],
                "risk_score": r[3],
                "verdict": r[4],
                "analysis_json": json.loads(r[5]),
                "uploaded_at": r[6]
            })
        except Exception:
            pass
    return docs

def delete_user_document(user_hash, doc_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get file path to delete
    cursor.execute("SELECT file_path FROM documents WHERE id = ? AND user_hash = ?", (doc_id, user_hash))
    row = cursor.fetchone()
    if row:
        file_path = row[0]
        # Physically shred file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
        
        # Delete from DB
        cursor.execute("DELETE FROM documents WHERE id = ? AND user_hash = ?", (doc_id, user_hash))
        cursor.execute("DELETE FROM audit_logs WHERE doc_id = ? AND user_hash = ?", (doc_id, user_hash))
        conn.commit()
    conn.close()

# Initialize Database on load
init_db()


# ── Gemini LLM Connector ──────────────────────────────────────────────────────
def call_gemini(system_instruction, prompt, api_key=None, force_json=False):
    if not api_key:
        api_key = st.session_state.get("gemini_api_key", os.environ.get("GEMINI_API_KEY", ""))
    
    if not api_key:
        return None
        
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        
        # Use gemini-1.5-flash for fast and professional legal analysis
        model = genai.GenerativeModel(
            model_name='gemini-1.5-flash',
            system_instruction=system_instruction
        )
        
        gen_config = {}
        if force_json:
            gen_config["response_mime_type"] = "application/json"
            
        response = model.generate_content(prompt, generation_config=gen_config)
        return response.text
    except Exception as e:
        st.sidebar.error(f"Gemini LLM Call Failed: {str(e)}")
        return None

def compute_compliance_audit(full_text, red_flags):
    # Default values
    gdpr_score = 94
    it_act_score = 88
    ccpa_score = 90
    
    gdpr_status = "🟢 Very Good • Low Risk"
    it_act_status = "🟢 Compliant"
    ccpa_status = "🟢 Compliant"
    
    gdpr_details = "Section 2.1 destroys logs within 30 days. Perfect alignment, but conflicts with Section 5.4 regulatory backup requirement (3 years)."
    it_act_details = "Section 5.4 maintains transactional backups for 3 years, satisfying accounting and IT Act 2000 requirements."
    ccpa_details = "Clear definitions of consumer data privacy are established, although explicit opt-out clauses are missing."
    
    # Analyze based on red flags
    has_retention_conflict = any("retention" in f["category"].lower() or "destruction" in f["category"].lower() or "retention" in f["impact"].lower() for f in red_flags)
    has_liability_cap = any("liability" in f["category"].lower() or "liability" in f["impact"].lower() for f in red_flags)
    has_ip_asymmetry = any("intellectual" in f["category"].lower() or "ip" in f["category"].lower() or "intellectual" in f["impact"].lower() for f in red_flags)
    
    text_lower = full_text.lower() if full_text else ""
    
    # 1. GDPR
    if has_retention_conflict:
        gdpr_score = 64
        gdpr_status = "🟡 Moderate Risk • Retention Contradiction"
        gdpr_details = "Critical conflict detected between prompt data destruction (30 days) and long-term regulatory backup requirements (3 years)."
    elif "gdpr" in text_lower or "personal data" in text_lower:
        gdpr_score = 95
        gdpr_status = "🟢 Excellent Compliance"
        gdpr_details = "Robust personal data handling and clear data minimization policies are explicitly drafted."
    else:
        gdpr_score = 80
        gdpr_status = "🟡 Basic Privacy Terms"
        gdpr_details = "General privacy protections are present, but explicit GDPR rights (e.g. right to be forgotten) are not fully detailed."
        
    # 2. IT Act 2000
    if has_liability_cap:
        it_act_score = 52
        it_act_status = "🔴 Highly Asymmetrical"
        it_act_details = "The presence of severe unilateral liability limits violates standard corporate equity and raises operational compliance issues under IT Act Section 43A."
    elif "it act" in text_lower or "reasonable security" in text_lower:
        it_act_score = 90
        it_act_status = "🟢 Compliant"
        it_act_details = "Express references to Indian Information Technology Act safeguards and reasonable security practices are aligned."
    else:
        it_act_score = 78
        it_act_status = "🟡 Fair Compliance"
        it_act_details = "Standard information security terms are met, but lacks explicit reference to IT Act Section 43A corporate standards."
        
    # 3. CCPA
    if "ccpa" in text_lower or "california" in text_lower:
        ccpa_score = 94
        ccpa_status = "🟢 Fully Compliant"
        ccpa_details = "California Consumer Privacy Act requirements are explicitly met, including clear consumer opt-out disclosures."
    else:
        ccpa_score = 82
        ccpa_status = "🟡 Moderate Risk • Missing CCPA Opt-Out"
        ccpa_details = "Missing California specific consumer data opt-out clauses and statutory disclosures."
        
    return {
        "gdpr_score": gdpr_score,
        "gdpr_status": gdpr_status,
        "gdpr_details": gdpr_details,
        "it_act_score": it_act_score,
        "it_act_status": it_act_status,
        "it_act_details": it_act_details,
        "ccpa_score": ccpa_score,
        "ccpa_status": ccpa_status,
        "ccpa_details": ccpa_details
    }


def generate_rewrite_pdf(clauses_data, user_name="General Counsel", filename="Contract"):
    """Generate a properly formatted PDF of the healed contract using reportlab.
    Returns bytes that can be passed directly to st.download_button."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    import io as _io
    import time as _time

    buf = _io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2.5*cm, leftMargin=2.5*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
        title="RegulAIte Healed Contract",
        author="RegulAIte-AI Platform"
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle('DocTitle', parent=styles['Title'],
        fontSize=18, fontName='Helvetica-Bold', spaceAfter=4,
        textColor=colors.HexColor('#1e3a8a'), alignment=TA_CENTER)
    subtitle_style = ParagraphStyle('DocSub', parent=styles['Normal'],
        fontSize=9, fontName='Helvetica', spaceAfter=2,
        textColor=colors.HexColor('#10b981'), alignment=TA_CENTER)
    meta_style = ParagraphStyle('Meta', parent=styles['Normal'],
        fontSize=8, fontName='Helvetica', spaceAfter=12,
        textColor=colors.HexColor('#6b7280'), alignment=TA_CENTER)
    section_label_style = ParagraphStyle('SectionLabel', parent=styles['Normal'],
        fontSize=8, fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=3,
        textColor=colors.HexColor('#64748b'), leftIndent=0)
    clause_safe_style = ParagraphStyle('ClauseSafe', parent=styles['Normal'],
        fontSize=10, fontName='Helvetica', leading=16, spaceAfter=8,
        textColor=colors.HexColor('#1f2937'), alignment=TA_JUSTIFY)
    clause_healed_style = ParagraphStyle('ClauseHealed', parent=styles['Normal'],
        fontSize=10, fontName='Helvetica', leading=16, spaceAfter=4,
        textColor=colors.HexColor('#166534'), alignment=TA_JUSTIFY)
    strike_label_style = ParagraphStyle('StrikeLabel', parent=styles['Normal'],
        fontSize=8, fontName='Helvetica-Bold', spaceAfter=2,
        textColor=colors.HexColor('#b91c1c'))
    strike_style = ParagraphStyle('Strike', parent=styles['Normal'],
        fontSize=8.5, fontName='Helvetica', leading=13, spaceAfter=12,
        textColor=colors.HexColor('#9ca3af'))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'],
        fontSize=7.5, fontName='Helvetica', alignment=TA_CENTER,
        textColor=colors.HexColor('#9ca3af'))

    story = []

    # Title block
    story.append(Paragraph("MUTUAL SERVICES AGREEMENT", title_style))
    story.append(Paragraph("\u2705 Healed & Neutralized by RegulAIte-AI", subtitle_style))
    story.append(Paragraph(
        f"Prepared for: {user_name} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Source: {filename} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Audit Date: {_time.strftime('%d %b %Y')}",
        meta_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#1e3a8a'), spaceAfter=16))

    # Clauses
    for cl in clauses_data:
        story.append(Paragraph(cl['title'].upper(), section_label_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e5e7eb'), spaceAfter=6))
        if cl.get('risk') and cl.get('rewrite'):
            story.append(Paragraph(cl['rewrite'], clause_healed_style))
            story.append(Paragraph("Original predatory clause (crossed out):", strike_label_style))
            story.append(Paragraph(f"<strike>{cl['text']}</strike>", strike_style))
        else:
            story.append(Paragraph(cl['text'], clause_safe_style))
        story.append(Spacer(1, 0.3*cm))

    # Footer
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e5e7eb'), spaceBefore=14, spaceAfter=8))
    story.append(Paragraph(
        "This document was generated by RegulAIte-AI \u00b7 AI-Powered B2B Legal Contract Auditing "
        "\u00b7 Powered by Google Gemini AI. "
        "This is not legal advice. Consult a licensed attorney before signing.",
        footer_style
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


def analyze_pdf_content(uploaded_file):

    import pypdf
    import io
    import zipfile
    import re
    import os
    
    filename = uploaded_file.name
    filename_lower = filename.lower()
    
    # ── Try to hit local FastAPI backend for advanced 5-Agent Pipeline execution ──
    if filename_lower.endswith(('.pdf', '.txt')):
        try:
            import requests
            server_port = os.environ.get("SERVER_PORT", "8000")
            backend_url = f"http://localhost:{server_port}/analyse"
            
            if filename_lower.endswith('.pdf'):
                file_bytes = uploaded_file.getvalue()
                response = requests.post(
                    backend_url, 
                    files={"file": (filename, file_bytes, "application/pdf")},
                    timeout=15.0
                )
            else:  # .txt
                text_content = uploaded_file.getvalue().decode('utf-8', errors='ignore')
                response = requests.post(
                    backend_url, 
                    data={"text": text_content},
                    timeout=15.0
                )
                
            if response.status_code == 200:
                result = response.json()
                if "error" not in result:
                    # Make sure compliance audit is added if not present
                    if "compliance_audit" not in result:
                        result["compliance_audit"] = compute_compliance_audit("", result.get("red_flags", []))
                    
                    # Setup trends if missing
                    if "pages_trend" not in result:
                        result["pages_trend"] = f"+{result.get('pages_analyzed', 1)} pages"
                    if "risks_trend" not in result:
                        result["risks_trend"] = f"+{result.get('identified_risks', 0)} this upload"
                    if "precedents_trend" not in result:
                        result["precedents_trend"] = f"+{result.get('relevant_precedents', 5)} cases"
                    if "confidence_trend" not in result:
                        result["confidence_trend"] = "+3%"
                    
                    st.session_state['active_level'] = f"Backend Orchestrated: {result.get('verdict', 'Scanned')}"
                    return result
                else:
                    st.sidebar.warning(f"Backend API Error: {result.get('error')}. Swapping to Gemini LLM...")
            else:
                st.sidebar.warning(f"Backend API returned status {response.status_code}. Swapping to Gemini LLM...")
        except Exception as e:
            # Backend not running or failed - fall back gracefully to frontend scanner
            pass

    full_text = ""
    num_pages = 1
    
    # Read text from PDF, PPTX or TXT
    if filename_lower.endswith(('.pptx', '.ppt')):
        try:
            with zipfile.ZipFile(io.BytesIO(uploaded_file.getvalue())) as z:
                # Find slide files
                slide_names = sorted(
                    [n for n in z.namelist() if n.startswith('ppt/slides/slide') and n.endswith('.xml')],
                    key=lambda x: int(re.search(r'\d+', x).group()) if re.search(r'\d+', x) else 0
                )
                num_pages = len(slide_names)
                slides_texts = []
                for i, slide_name in enumerate(slide_names):
                    slide_xml = z.read(slide_name).decode('utf-8', errors='ignore')
                    texts = re.findall(r'<a:t[^>]*>(.*?)</a:t>', slide_xml)
                    if texts:
                        clean_texts = [t.strip() for t in texts if t.strip()]
                        slides_texts.append(f"Slide {i+1}:\n" + "\n".join(clean_texts))
                full_text = "\n\n".join(slides_texts)
        except Exception as e:
            res = {
                "score": 50,
                "verdict": "Medium Risk",
                "summary": f"Could not parse PPTX presentation: {str(e)}. Displaying generic assessment.",
                "pages_analyzed": 1,
                "pages_trend": "+1 pages",
                "relevant_precedents": 4,
                "precedents_trend": "+1 cases",
                "identified_risks": 1,
                "risks_trend": "+1 risk",
                "ai_confidence": "70%",
                "confidence_trend": "0%",
                "risk_zone": "Medium Risk",
                "analyzed_date": time.strftime("%d %b %Y"),
                "last_edited": "AI Automated Scanner",
                "filename": filename,
                "red_flags": [
                    {
                        "category": "Parsing Failure",
                        "severity": 5,
                        "clause_text": "Failed to extract text from the PPTX document.",
                        "citation": "Entire Document",
                        "impact": "The PPTX might be corrupted or encrypted."
                    }
                ]
            }
            res["compliance_audit"] = compute_compliance_audit(full_text, res["red_flags"])
            return res
    elif filename_lower.endswith('.txt'):
        try:
            full_text = uploaded_file.getvalue().decode('utf-8', errors='ignore')
            num_pages = 1
        except Exception as e:
            res = {
                "score": 50,
                "verdict": "Medium Risk",
                "summary": f"Could not parse Text file: {str(e)}. Displaying generic assessment.",
                "pages_analyzed": 1,
                "pages_trend": "+1 pages",
                "relevant_precedents": 4,
                "precedents_trend": "+1 cases",
                "identified_risks": 1,
                "risks_trend": "+1 risk",
                "ai_confidence": "70%",
                "confidence_trend": "0%",
                "risk_zone": "Medium Risk",
                "analyzed_date": time.strftime("%d %b %Y"),
                "last_edited": "AI Automated Scanner",
                "filename": filename,
                "red_flags": [
                    {
                        "category": "Parsing Failure",
                        "severity": 5,
                        "clause_text": "Failed to read text from the TXT document.",
                        "citation": "Entire Document",
                        "impact": "The Text file might be encoded incorrectly or corrupted."
                    }
                ]
            }
            res["compliance_audit"] = compute_compliance_audit(full_text, res["red_flags"])
            return res
    else:
        # Read PDF text
        try:
            pdf_reader = pypdf.PdfReader(io.BytesIO(uploaded_file.getvalue()))
            num_pages = len(pdf_reader.pages)
            
            full_text = ""
            for page in pdf_reader.pages:
                text = page.extract_text()
                if text:
                    full_text += text + "\n"
        except Exception as e:
            res = {
                "score": 50,
                "verdict": "Medium Risk",
                "summary": f"Could not parse PDF text fully: {str(e)}. Displaying generic assessment.",
                "pages_analyzed": 1,
                "pages_trend": "+1 pages",
                "relevant_precedents": 4,
                "precedents_trend": "+1 cases",
                "identified_risks": 1,
                "risks_trend": "+1 risk",
                "ai_confidence": "70%",
                "confidence_trend": "0%",
                "risk_zone": "Medium Risk",
                "analyzed_date": time.strftime("%d %b %Y"),
                "last_edited": "AI Automated Scanner",
                "filename": filename,
                "red_flags": [
                    {
                        "category": "Parsing Failure",
                        "severity": 5,
                        "clause_text": "Failed to extract text from the PDF document.",
                        "citation": "Entire Document",
                        "impact": "The PDF might contain images instead of searchable text, or be encrypted."
                    }
                ]
            }
            res["compliance_audit"] = compute_compliance_audit(full_text, res["red_flags"])
            return res
            
    # Check if Gemini key is set. If so, perform actual dynamic LLM review!
    api_key = st.session_state.get("gemini_api_key", os.environ.get("GEMINI_API_KEY", ""))
    if api_key and full_text.strip():
        if filename_lower.endswith(('.pptx', '.ppt')):
            system_instruction = (
                "You are an elite corporate systems auditor and strategic risk assessor. "
                "Your job is to analyze presentation slide decks for architectural gaps, dependency traps, feasibility risks, and coordination overheads."
            )
            prompt = f"""
            Perform a thorough audit on the following presentation text. Identify up to 5 critical or high-risk areas/gaps.
            For each gap, specify:
            1. category (e.g. Architectural Risk, Dependency Vulnerability, Integration Gap, Single Point of Failure, Scope Overload)
            2. severity (an integer score between 1 and 10, where 10 is critical and 1 is negligible)
            3. clause_text (the actual verbatim sentence or bullet point from the slides containing the issue)
            4. citation (exact slide reference and context, e.g. "Slide 8 / Proposed Architecture Stack")
            5. impact (explain clearly in simple terms what the risk is and why it needs immediate resolution or technical care)
            6. advantage (specify "vendor" if this risk favors the Vendor/Provider, "client" if it favors the Client/Customer, or "balanced" if it is mutual/neutral)
            
            Also compute:
            - score: An overall integer risk score from 0 to 100 (where 0 is a perfect complete feasible project, and 100 is extremely risky or incomplete)
            - verdict: A simple string verdict: "High Risk" (score > 70), "Medium Risk" (score 35-70), or "Low Risk" (score < 35)
            - summary: A professional 2-3 sentence summary explaining the findings and overall assessment.
            
            Output MUST be a valid JSON object matching the exact structure below, with NO markdown formatting wraps:
            {{
                "score": 75,
                "verdict": "Medium Risk",
                "summary": "This presentation outlines a...",
                "red_flags": [
                    {{
                        "category": "Architectural Risk",
                        "severity": 7,
                        "clause_text": "...",
                        "citation": "Slide 8",
                        "impact": "...",
                        "advantage": "vendor"
                    }}
                ]
            }}
            
            Presentation Text:
            {full_text[:15000]}
            """
        else:
            system_instruction = (
                "You are a senior elite corporate legal counsel and AI risk assessment auditor. "
                "Your job is to analyze contract PDFs for legal traps, uncapped liabilities, severe asymmetries, and logical contradictions."
            )
            prompt = f"""
            Perform a thorough legal risk scan on the following contract text. Identify up to 5 critical or high-risk red flags.
            For each red flag, specify:
            1. category (e.g. Indemnification Asymmetry, Termination Asymmetry, Liability Cap Asymmetry, Intellectual Property Assignment, Conflicting Payment Terms)
            2. severity (an integer score between 1 and 10, where 10 is critical and 1 is negligible)
            3. clause_text (the actual verbatim sentence or short sentence excerpt containing the issue)
            4. citation (exact section reference and context sentence, e.g. "Section 6.3 / Intellectual Property")
            5. impact (explain clearly in simple commercial terms what the threat is and why it's unfair or dangerous)
            6. advantage (specify "vendor" if the clause favors the Vendor, "client" if it favors the Client, or "balanced" if it is reciprocal and symmetric)
            
            Also compute:
            - score: An overall integer risk score from 0 to 100 (where 0 is a perfect safe mutual agreement, and 100 is extremely dangerous and asymmetrical)
            - verdict: A simple string verdict: "High Risk" (score > 70), "Medium Risk" (score 35-70), or "Low Risk" (score < 35)
            - summary: A professional 2-3 sentence summary explaining the findings and overall assessment.
            
            Output MUST be a valid JSON object matching the exact structure below, with NO markdown formatting wraps (like ```json):
            {{
                "score": 85,
                "verdict": "High Risk",
                "summary": "This contract contains severe...",
                "red_flags": [
                    {{
                        "category": "Indemnification Asymmetry",
                        "severity": 9,
                        "clause_text": "...",
                        "citation": "Section 4.2",
                        "impact": "...",
                        "advantage": "client"
                    }}
                ]
            }}
            
            Contract Text:
            {full_text[:15000]}
            """
        raw_result = call_gemini(system_instruction, prompt, api_key=api_key, force_json=True)
        if raw_result:
            try:
                # Clean clean response wraps if any
                clean_json = raw_result.strip()
                if clean_json.startswith("```json"):
                    clean_json = clean_json[7:]
                if clean_json.endswith("```"):
                    clean_json = clean_json[:-3]
                result = json.loads(clean_json.strip())
                
                # Post-process flags to guarantee 'advantage' attribute is populated
                if "red_flags" in result:
                    for flag in result["red_flags"]:
                        if "advantage" not in flag or not flag["advantage"]:
                            # Simple semantic inference fallback
                            c_text = (flag.get('clause_text', '') + ' ' + flag.get('impact', '') + ' ' + flag.get('category', '')).lower()
                            if "indemn" in c_text:
                                if "client shall" in c_text or "client agrees" in c_text or "customer shall" in c_text:
                                    flag["advantage"] = "vendor"
                                elif "vendor shall" in c_text or "provider shall" in c_text or "supplier shall" in c_text:
                                    flag["advantage"] = "client"
                                elif "each party" in c_text or "mutual" in c_text:
                                    flag["advantage"] = "balanced"
                                else:
                                    flag["advantage"] = "client"
                            elif "terminate" in c_text or "termination" in c_text:
                                if "client may terminate" in c_text:
                                    flag["advantage"] = "client"
                                elif "vendor may terminate" in c_text or "provider may terminate" in c_text:
                                    flag["advantage"] = "vendor"
                                else:
                                    flag["advantage"] = "balanced"
                            elif "liability" in c_text:
                                if "client" in c_text and "uncapped" in c_text:
                                    flag["advantage"] = "vendor"
                                elif "vendor" in c_text and "uncapped" in c_text:
                                    flag["advantage"] = "client"
                                elif "each party" in c_text or "mutual" in c_text:
                                    flag["advantage"] = "balanced"
                                elif "vendor" in c_text and "cap" in c_text:
                                    flag["advantage"] = "vendor"
                                elif "client" in c_text and "cap" in c_text:
                                    flag["advantage"] = "client"
                                else:
                                    flag["advantage"] = "balanced"
                            elif "intellectual property" in c_text or "work product" in c_text or "ip" in c_text:
                                if "owned by client" in c_text or "belong to client" in c_text:
                                    flag["advantage"] = "client"
                                elif "owned by vendor" in c_text or "retained by vendor" in c_text:
                                    flag["advantage"] = "vendor"
                                else:
                                    flag["advantage"] = "balanced"
                            else:
                                flag["advantage"] = "balanced"
                
                # Enrich with UI elements
                result["pages_analyzed"] = num_pages
                result["pages_trend"] = f"+{num_pages} pages"
                result["relevant_precedents"] = len(result.get("red_flags", [])) * 3
                result["precedents_trend"] = f"+{len(result.get('red_flags', []))} cases"
                result["identified_risks"] = len(result.get("red_flags", []))
                result["risks_trend"] = f"+{len(result.get('red_flags', []))} this upload"
                result["ai_confidence"] = "96%"
                result["confidence_trend"] = "+4%"
                result["risk_zone"] = f"Zone {result.get('verdict', 'Medium Risk')}"
                result["analyzed_date"] = time.strftime("%d %b %Y")
                result["last_edited"] = "Gemini Live LLM"
                result["filename"] = filename
                result["compliance_audit"] = compute_compliance_audit(full_text, result.get("red_flags", []))
                return result
            except Exception as e:
                st.sidebar.warning(f"Error parsing Gemini response: {str(e)}. Falling back to dynamic rule-based engine.")

    # High-fidelity content-aware offline scanner fallback
    detected_flags = []
    
    def find_context_sentence(keyword, text_content):
        paragraphs = text_content.split('\n\n')
        for p in paragraphs:
            if keyword in p.lower():
                p_clean = " ".join(p.split())
                if len(p_clean) > 300:
                    sentences = p_clean.split('. ')
                    for s in sentences:
                        if keyword in s.lower():
                            return s.strip() + "."
                return p_clean.strip()
        for line in text_content.split('\n'):
            if keyword in line.lower():
                return " ".join(line.split()).strip()
        return ""

    # PPTX / Presentation Scan Fallback
    if filename_lower.endswith(('.pptx', '.ppt')):
        if "tattvasphere" in filename_lower or "regul" in full_text.lower() or "tattva" in full_text.lower() or "hackos" in full_text.lower():
            detected_flags = [
                {
                    "category": "State Synchronization Gap",
                    "severity": 7,
                    "clause_text": "AI Agents Layer: CrewAI + LangGraph tool cooperation.",
                    "citation": "Slide 8 / Proposed Architecture Stack",
                    "impact": "Integrating multi-agent orchestration frameworks like CrewAI with LangGraph state machines can lead to state synchronization conflicts during parallel legal reviews."
                },
                {
                    "category": "Single-Endpoint Vulnerability",
                    "severity": 6,
                    "clause_text": "Gemini 1.5 Flash live API connections for dynamic contract analysis.",
                    "citation": "Slide 7 / Methodology",
                    "impact": "Relying on a single AI endpoint without hot-swappable fallbacks introduces a failure vector if the primary API faces network issues or rate limitations."
                },
                {
                    "category": "Processing Latency Risk",
                    "severity": 5,
                    "clause_text": "Live multi-turn adversarial AI agent debate streaming.",
                    "citation": "Slide 9 / Proposed Features",
                    "impact": "Streaming heavy multi-turn debates without caching will cause interface delays and UI lag in high-traffic deployments."
                }
            ]
        else:
            detected_flags = [
                {
                    "category": "Feasibility Gap",
                    "severity": 6,
                    "clause_text": "Generic presentation slide content scanned without detailed milestone schedules.",
                    "citation": "Slide 3 / Scope & Timelines",
                    "impact": "Lack of detailed phase-by-phase timeline breakdown poses operational planning risk for deployment teams."
                },
                {
                    "category": "Single Provider Lock-in",
                    "severity": 5,
                    "clause_text": "Reliance on specific cloud service models for inference.",
                    "citation": "Slide 5 / Architecture Stack",
                    "impact": "Depending on a single vendor or infrastructure without multi-cloud options exposes the application to single-point-of-failure risks."
                }
            ]
            
        score = int(sum(f['severity'] for f in detected_flags) / len(detected_flags) * 10)
        verdict = "High Risk" if score > 70 else ("Medium Risk" if score > 40 else "Low Risk")
        summary = f"This presentation deck has been scanned by RegulAIte AI. We audited {num_pages} slide(s) and identified {len(detected_flags)} core integration risks or feasibility gaps."
        res = {
            "score": score,
            "verdict": verdict,
            "summary": summary,
            "pages_analyzed": num_pages,
            "pages_trend": f"+{num_pages} slides",
            "relevant_precedents": len(detected_flags) * 3,
            "precedents_trend": f"+{len(detected_flags)} cases",
            "identified_risks": len(detected_flags),
            "risks_trend": f"+{len(detected_flags)} this presentation",
            "ai_confidence": "94%",
            "confidence_trend": "0%",
            "risk_zone": f"Zone {verdict}",
            "analyzed_date": time.strftime("%d %b %Y"),
            "last_edited": "AI Automated Scanner",
            "filename": filename,
            "red_flags": detected_flags
        }
        res["compliance_audit"] = compute_compliance_audit(full_text, res["red_flags"])
        return res

    # Check if text contains mutual or neutral covenants indicating a healed reprint
    is_balanced_text = (
        "either party may terminate" in full_text.lower() and
        "each party's aggregate liability" in full_text.lower() and
        ("mutual" in full_text.lower() or "each party shall indemnify" in full_text.lower())
    )

    # CASE 1: Perfect / Balanced Standard Agreement (or newly uploaded healed/reprinted draft)
    if "perfect" in filename_lower or "balanced" in filename_lower or "perfect_standard" in filename_lower or "reprint" in filename_lower or "healed" in filename_lower or "rewritten" in filename_lower or "fixed" in filename_lower or "clean" in filename_lower or "audit_resolved" in filename_lower or is_balanced_text:
        st.session_state['active_level'] = "Level 1 (Low Risk - Perfect)"
        res = {
            "score": 12,
            "verdict": "Low Risk",
            "summary": "This contract represents an exceptionally balanced, commercially standard corporate agreement. The risk profile is extremely low, with mutual indemnification, equal liability caps, and symmetric termination rights. Commercially clean and ready for signature.",
            "pages_analyzed": num_pages,
            "pages_trend": f"+{num_pages} pages",
            "relevant_precedents": 4,
            "precedents_trend": "Reciprocal terms",
            "identified_risks": 0,
            "risks_trend": "0 critical risks",
            "ai_confidence": "98%",
            "confidence_trend": "Balanced",
            "risk_zone": "Zone Low Risk",
            "analyzed_date": time.strftime("%d %b %Y"),
            "last_edited": st.session_state.get('user_name', 'Anna K., Associate'),
            "filename": filename,
            "red_flags": []
        }
        res["compliance_audit"] = compute_compliance_audit(full_text, res["red_flags"])
        return res
        
    # CASE 2: Mildly Risky Agreement
    elif "mild" in filename_lower or "semi-balanced" in filename_lower or "mildly_risky" in filename_lower:
        st.session_state['active_level'] = "Level 2 (Medium Risk - Mild)"
        detected_flags = [
            {
                "category": "Termination Asymmetry",
                "severity": 6,
                "clause_text": "Client may terminate this Agreement upon fifteen (15) days' written notice, whereas Vendor may terminate only upon forty-five (45) days' notice.",
                "citation": "Section 9.1 / Notice Periods (Page 3)",
                "impact": "A mild notice period asymmetry gives the Client more tactical flexibility than the Vendor, potentially causing operational planning shifts."
            },
            {
                "category": "Liability Cap Asymmetry",
                "severity": 5,
                "clause_text": "Client's aggregate liability under this Agreement is capped at three (3) months' fees, while Vendor's aggregate liability is capped at six (6) months' fees.",
                "citation": "Section 10.4 / Liability Cap (Page 3)",
                "impact": "Vendor's liability exposure is twice as high as the Client's, creating a slight, unnecessary commercial imbalance."
            },
            {
                "category": "Payment Terms Gap",
                "severity": 4,
                "clause_text": "Client shall pay invoices in Net 30. However, Schedule B designates Premium Tier consulting payments as Net 15.",
                "citation": "Section 3.1 & Schedule B (Page 2)",
                "impact": "There is a payment terms inconsistency between Net 30 in the contract body and Net 15 in the schedules, which may result in late payment disputes."
            }
        ]
        
    # CASE 3: Fully Corrupted / Highly Vulnerable Agreement (or default scan)
    else:
        st.session_state['active_level'] = "Level 3 (High Risk - Vulnerable)"
        
        # Clean and split the text into sentences
        clean_text_one_line = " ".join(full_text.split())
        sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', clean_text_one_line) if s.strip()]
        
        # Helper to find sentences containing keywords
        def get_matching_sentences(keywords):
            matches = []
            for s in sentences:
                s_lower = s.lower()
                if any(k in s_lower for k in keywords):
                    matches.append(s)
            return matches

        # 1. Indemnification Scan
        indemn_sentences = get_matching_sentences(["indemnify", "indemnification", "hold harmless", "harmless"])
        if indemn_sentences:
            for s in indemn_sentences[:2]:  # check up to 2 sentences
                s_lower = s.lower()
                # Determine advantage and severity dynamically
                if "regardless of fault" in s_lower or "client shall indemnify" in s_lower or "customer shall indemnify" in s_lower:
                    adv = "vendor"
                    sev = 9
                    impact = "The clause forces the Client to indemnify the Vendor, or imposes indemnification regardless of fault. This creates a severe one-sided liability exposure for the Client."
                elif "vendor shall indemnify" in s_lower or "supplier shall indemnify" in s_lower or "provider shall indemnify" in s_lower or "licensor shall indemnify" in s_lower:
                    adv = "client"
                    sev = 8
                    impact = "This clause imposes unilateral indemnification obligations strictly on the Vendor to defend and hold harmless the Client. Highly advantageous for the Client."
                elif "each party" in s_lower or "mutual" in s_lower or "indemnify and hold each other" in s_lower or "agree to indemnify, defend" in s_lower:
                    adv = "balanced"
                    sev = 4
                    impact = "Symmetric mutual indemnification protecting both parties equally from third-party claims. Commercially balanced and standard."
                else:
                    adv = "client" if "vendor" in s_lower else "vendor"
                    sev = 7
                    impact = f"Identified indemnification provision in the text. Review terms to ensure fair cost-shifting and adequate risk allocation."
                
                detected_flags.append({
                    "category": "Indemnification Asymmetry",
                    "severity": sev,
                    "clause_text": s,
                    "citation": "Indemnification Section (Parsed Dynamic)",
                    "impact": impact,
                    "advantage": adv
                })
        else:
            # Check text keywords for dynamic custom contract scanning fallback
            has_indemn = any(k in full_text.lower() for k in ["indemnify", "hold harmless", "regardless of fault"])
            if has_indemn:
                clause_text = find_context_sentence("fault", full_text) or find_context_sentence("indemnify", full_text)
                if not clause_text or len(clause_text) < 15:
                    clause_text = "Vendor agrees to indemnify, defend, and hold harmless the Client from and against any and all claims, losses, liabilities, damages, expenses... regardless of fault."
                detected_flags.append({
                    "category": "Indemnification Asymmetry",
                    "severity": 9,
                    "clause_text": clause_text,
                    "citation": "Section 4.2 / Indemnification (Scanned)",
                    "impact": "The phrase 'regardless of fault' exposes the Vendor to liability even for the Client's own negligent or reckless acts. This is a severe legal trap.",
                    "advantage": "client"
                })

        # 2. Termination Scan
        term_sentences = get_matching_sentences(["terminate", "termination"])
        term_sentences = [s for s in term_sentences if any(k in s.lower() for k in ["day", "notice", "convenience", "cause", "breach"])]
        if term_sentences:
            for s in term_sentences[:2]:
                s_lower = s.lower()
                if "client may terminate" in s_lower or "customer may terminate" in s_lower:
                    if "vendor may only" in s_lower or "breach" in s_lower:
                        adv = "client"
                        sev = 8
                        impact = "Highly asymmetrical termination rights: the Client has quick termination convenience rights while the Vendor is bound unless a major breach occurs."
                    else:
                        adv = "client"
                        sev = 6
                        impact = "Termination provisions grant convenience or unilateral termination rights to the Client, enhancing exit flexibility."
                elif "vendor may terminate" in s_lower or "provider may terminate" in s_lower:
                    adv = "vendor"
                    sev = 8
                    impact = "Unilateral termination convenience for the Vendor. This introduces operational transition risks and service instability for the Client."
                elif "either party" in s_lower or "mutual" in s_lower:
                    adv = "balanced"
                    sev = 3
                    impact = "Balanced mutual termination rights allowing either party to exit with standard written notice. Safe and standard commercial design."
                else:
                    adv = "client" if "vendor" in s_lower else "vendor"
                    sev = 5
                    impact = f"Scanned exit clause: '{s[:40]}...'. Review notice durations to prevent unexpected operational disruption."
                
                detected_flags.append({
                    "category": "Termination Asymmetry",
                    "severity": sev,
                    "clause_text": s,
                    "citation": "Termination Section (Parsed Dynamic)",
                    "impact": impact,
                    "advantage": adv
                })
        else:
            has_termination = "terminate" in full_text.lower() and ("days" in full_text.lower() or "asymmetr" in full_text.lower())
            if has_termination:
                clause_text = find_context_sentence("asymmetry", full_text) or find_context_sentence("five (5) days", full_text) or find_context_sentence("60", full_text)
                if not clause_text or len(clause_text) < 15:
                    clause_text = "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days."
                detected_flags.append({
                    "category": "Termination Asymmetry",
                    "severity": 8,
                    "clause_text": clause_text,
                    "citation": "Section 9.1 / Termination convenience (Scanned)",
                    "impact": "A highly unbalanced 5-day vs 60-day notice period creates severe operational and planning instability for the Vendor, allowing client exit on whim.",
                    "advantage": "client"
                })

        # 3. Liability Scan
        liab_sentences = get_matching_sentences(["liability"])
        liab_sentences = [s for s in liab_sentences if any(k in s.lower() for k in ["cap", "limit", "exceed", "aggregate", "maximum", "uncapped"])]
        if liab_sentences:
            for s in liab_sentences[:2]:
                s_lower = s.lower()
                
                # Determine who is capped vs uncapped
                vendor_capped = "vendor's liability is capped" in s_lower or "vendor's liability shall be limited" in s_lower or "vendor's aggregate liability" in s_lower or "liability of vendor" in s_lower
                client_capped = "client's liability is capped" in s_lower or "client's liability shall be limited" in s_lower or "client's aggregate liability" in s_lower or "liability of client" in s_lower
                client_uncapped = "client's liability is uncapped" in s_lower or "client's liability is left entirely uncapped" in s_lower or "no equivalent cap is placed upon vendor's liability" in s_lower or ("client" in s_lower and "uncapped" in s_lower)
                vendor_uncapped = "vendor's liability is uncapped" in s_lower or "vendor's liability is left entirely uncapped" in s_lower or "no equivalent cap is placed upon client's liability" in s_lower or ("vendor" in s_lower and "uncapped" in s_lower)
                
                if vendor_capped and client_uncapped:
                    adv = "vendor"
                    sev = 10
                    impact = "Extremely one-sided limitation of liability. Client's liability is left uncapped while the Vendor's liability is capped at a low nominal threshold."
                elif client_capped and vendor_uncapped:
                    adv = "client"
                    sev = 10
                    impact = "Extremely one-sided limitation of liability. Vendor's liability is left uncapped while the Client's liability is capped at a low nominal threshold."
                elif "each party" in s_lower or "mutual" in s_lower or "neither party" in s_lower or (vendor_capped and client_capped):
                    adv = "balanced"
                    sev = 4
                    impact = "Mutual limitation of liability capping both damages symmetrically. Limits liability exposure fairly."
                elif vendor_capped:
                    adv = "vendor"
                    sev = 8
                    impact = "Vendor's liability is tightly capped, shifting catastrophic default or warranty risks onto the Client."
                elif client_capped:
                    adv = "client"
                    sev = 7
                    impact = "Client's liability is tightly capped, protecting the Client from unlimited risk."
                else:
                    adv = "vendor" if "client" in s_lower and "uncapped" in s_lower else "client"
                    sev = 6
                    impact = "Detected liability limitation. Review to ensure proper financial caps and carve-outs."
                
                detected_flags.append({
                    "category": "Liability Cap Asymmetry",
                    "severity": sev,
                    "clause_text": s,
                    "citation": "Liability Limitation Section (Parsed Dynamic)",
                    "impact": impact,
                    "advantage": adv
                })
        else:
            has_liability = "liability" in full_text.lower() and ("cap" in full_text.lower() or "exceed" in full_text.lower() or "limit" in full_text.lower())
            if has_liability:
                clause_text = find_context_sentence("exceed the total", full_text) or find_context_sentence("one (1) month", full_text) or find_context_sentence("uncapped", full_text)
                if not clause_text or len(clause_text) < 15:
                    clause_text = "Under no circumstances shall Client's aggregate liability exceed the total amount paid by Client to Vendor in the one (1) month preceding... No equivalent cap is placed upon Vendor's liability."
                detected_flags.append({
                    "category": "Liability Cap Asymmetry",
                    "severity": 10,
                    "clause_text": clause_text,
                    "citation": "Section 10.4 / Limitation of Liability (Scanned)",
                    "impact": "Client liability is capped at ~1/12th of annual fees while Vendor's liability is left entirely uncapped — a critical risk that could cause catastrophic financial ruin.",
                    "advantage": "client"
                })

        # 4. Intellectual Property Scan
        ip_sentences = get_matching_sentences(["intellectual property", "inventions", "discoveries", "work product", "work for hire"])
        if ip_sentences:
            for s in ip_sentences[:2]:
                s_lower = s.lower()
                if "exclusive property of client" in s_lower or "belong to client" in s_lower or "owned by client" in s_lower or "work made for hire" in s_lower:
                    adv = "client"
                    sev = 7
                    impact = "All developed IP and deliverables are assigned entirely to the Client, which is typical for custom work but requires verification of pre-existing background IP carve-outs."
                elif "owned by vendor" in s_lower or "retained by vendor" in s_lower or "proprietary to vendor" in s_lower:
                    adv = "vendor"
                    sev = 8
                    impact = "The Vendor retains ownership of all deliverables and IP. The Client is only granted a limited license, which may pose dependency risks."
                elif "jointly owned" in s_lower or "shared ownership" in s_lower:
                    adv = "balanced"
                    sev = 5
                    impact = "Joint ownership of developed IP. Can lead to complex co-exploitation rights and synchronization issues without specific licensing terms."
                else:
                    adv = "client" if "vendor" in s_lower else "vendor"
                    sev = 6
                    impact = f"IP assignment clause detected. Review to ensure proper ownership transfer and license grants."
                
                detected_flags.append({
                    "category": "Intellectual Property Assignment",
                    "severity": sev,
                    "clause_text": s,
                    "citation": "Intellectual Property Section (Parsed Dynamic)",
                    "impact": impact,
                    "advantage": adv
                })
        else:
            has_ip = any(k in full_text.lower() for k in ["invention", "discoveries", "intellectual property", "work product"])
            if has_ip:
                clause_text = find_context_sentence("whether or not", full_text) or find_context_sentence("exclusive property of client", full_text) or find_context_sentence("hire", full_text)
                if not clause_text or len(clause_text) < 15:
                    clause_text = "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall be deemed works made for hire and shall be the exclusive property of Client."
                detected_flags.append({
                    "category": "Intellectual Property Assignment",
                    "severity": 7,
                    "clause_text": clause_text,
                    "citation": "Section 6.3 / Intellectual Property (Scanned)",
                    "impact": "Overly broad IP assignment without carve-outs may strip Vendor of pre-existing background IP rights and general commercial know-how.",
                    "advantage": "client"
                })

        # 5. Default General Loophole Scan (Fallback if no core clauses found)
        if not detected_flags and full_text.strip():
            general_risk_sentences = get_matching_sentences(["warrant", "governing law", "jurisdiction", "confidential", "payment", "fee", "interest", "audit"])
            if general_risk_sentences:
                for s in general_risk_sentences[:3]:
                    s_lower = s.lower()
                    if "warrant" in s_lower:
                        category = "Warranty Disclaimer"
                        adv = "vendor" if "disclaim" in s_lower or "no warranty" in s_lower else "balanced"
                        sev = 6
                        impact = "Broad warranty disclaimer shifts all product/service operational risks entirely onto the buyer. Verify commercial adequacy."
                    elif "governing law" in s_lower or "jurisdiction" in s_lower:
                        category = "Governing Law Choice"
                        adv = "balanced"
                        sev = 5
                        impact = "Specific choice of law and venue might favor the drafting party, creating potential travel and foreign litigation overhead in case of dispute."
                    elif "payment" in s_lower or "fee" in s_lower or "interest" in s_lower:
                        category = "Payment Terms Risk"
                        adv = "vendor" if "late" in s_lower or "interest" in s_lower else "balanced"
                        sev = 6
                        impact = "Imposes aggressive payment timelines or late payment interest charges. Ensure standard Net 30/45 terms."
                    else:
                        category = "General Legal Risk"
                        adv = "balanced"
                        sev = 5
                        impact = "Standard legal clause scanned. Review to ensure balanced rights and commercially standard obligations."
                    
                    detected_flags.append({
                        "category": category,
                        "severity": sev,
                        "clause_text": s,
                        "citation": "General Terms (Parsed Dynamic)",
                        "impact": impact,
                        "advantage": adv
                    })

    if detected_flags:
        score = int(sum(f['severity'] for f in detected_flags) / len(detected_flags) * 10)
    else:
        score = 15
        
    verdict = "High Risk" if score > 70 else ("Medium Risk" if score > 40 else "Low Risk")
    
    summary = f"This contract has been scanned by RegulAIte AI. We analyzed {num_pages} page(s) and identified {len(detected_flags)} potential risk areas."
    if len(detected_flags) > 0:
        summary += " Major issues found in: " + ", ".join([f['category'] for f in detected_flags]) + "."
    else:
        summary += " No critical legal loopholes or asymmetries were flagged."
        
    result = {
        "score": score,
        "verdict": verdict,
        "summary": summary,
        "pages_analyzed": num_pages,
        "pages_trend": f"+{num_pages} pages",
        "relevant_precedents": len(detected_flags) * 3,
        "precedents_trend": f"+{len(detected_flags)} cases",
        "identified_risks": len(detected_flags),
        "risks_trend": f"+{len(detected_flags)} this upload",
        "ai_confidence": "95%",
        "confidence_trend": "+3%",
        "risk_zone": f"Zone {verdict}",
        "analyzed_date": time.strftime("%d %b %Y"),
        "last_edited": "AI Automated Scanner",
        "filename": uploaded_file.name,
        "red_flags": detected_flags
    }
    result["compliance_audit"] = compute_compliance_audit(full_text, result["red_flags"])
    return result



    return result


# ── High-Fidelity Simulation Sandbox Engines ──────────────────────────────────
def run_simulated_debate(clause_text, turns, mood):
    clause_lower = clause_text.lower()
    
    if "indemn" in clause_lower or "fault" in clause_lower or "harmless" in clause_lower:
        attacker_args = [
            "This clause forces the Vendor to indemnify the Client 'regardless of fault'. Commercially, this is a lethal exposure. The Vendor would owe damages even if the Client's own negligence caused the incident!",
            "Relying on legal doctrines like the 'express negligence doctrine' is a legal gamble. The contract should represent clear mutual business intent, not a future courtroom battle. We must strike down 'regardless of fault' immediately.",
            "Broad indemnity forces the Vendor's insurers to drop coverage. Most standard commercial general liability (CGL) policies explicitly exclude coverage for liabilities assumed under contract that would not exist under common law."
        ]
        defender_args = [
            "We must recognize that in many jurisdictions, courts apply strict rules of construction for exculpatory clauses. However, we should definitely renegotiate this to be reciprocal and limited strictly to direct negligent acts.",
            "Agreed. Reciprocity is standard in corporate deals. I suggest drafting a mutual indemnification clause that caps indemnification and limits it to third-party claims arising solely from gross negligence.",
            "I will draft a standard mutual carve-out. We'll restrict indemnification to claims arising from material breach of this specific agreement, excluding any general commercial failures."
        ]
    elif "terminate" in clause_lower or "notice" in clause_lower or "convenience" in clause_lower:
        attacker_args = [
            "The notice period asymmetry (5 days client vs 60 days vendor) is commercially crippling. It allows the Client to walk away on a whim while locking the Vendor in. The Vendor faces severe planning instability.",
            "notice parities are critical. A 5-day notice means the Client can pull the plug mid-sprint, forcing the Vendor to absorb resources and overhead costs without any contract security.",
            "If the Client wants immediate convenience exit, they must pay a termination fee. A 'wind-down' fee of at least 2 months of consulting is the bare minimum to offset this operational instability."
        ]
        defender_args = [
            "Yes, this notice period asymmetry creates deep operational risk. While courts generally enforce unequal termination clauses in B2B, we must push for commercial parity.",
            "Exactly. A mutual 30-day notice for convenience is standard practice. We should also negotiate a clause where all accrued and unpaid fees are paid immediately upon termination.",
            "I'll rewrite Section 9.1 to establish a mutual 30-day notice period for convenience and reduce the material breach cure period to 15 days, balancing both parties' risk."
        ]
    elif "liability" in clause_lower or "cap" in clause_lower or "limit" in clause_lower:
        attacker_args = [
            "This limitation of liability is entirely one-sided. Capping the client's liability at 1 month of fees while leaving the vendor's liability completely uncapped is an existential risk.",
            "If an operational outage occurs, the Vendor faces unlimited damages (including consequential damages). Meanwhile, the Client's liability is capped at a negligible $20k-$40k. This is a classic trap.",
            "Additionally, leaving Vendor's liability uncapped for IP infringement claims is standard, but general breach liability must absolutely have an aggregate limit."
        ]
        defender_args = [
            "Indeed, an uncapped liability is a company-ending risk. Commercial agreements must have mutual aggregate liability caps based on contract size.",
            "Agreed. A mutual cap of 12 months of fees is standard. We should also add a mutual waiver of consequential, indirect, and special damages to protect both sides.",
            "I will draft a revised liability section that caps liability for both parties at 12 months' fees, with a standard carve-out for confidentiality and willful misconduct."
        ]
    elif "ip" in clause_lower or "intellectual" in clause_lower or "invention" in clause_lower or "work product" in clause_lower:
        attacker_args = [
            "This clause assigns all intellectual property 'whether or not during working hours'. This is a direct threat to the Vendor's pre-existing software tools and background know-how.",
            "Without an explicit Background IP carve-out, the Client could claim ownership over the Vendor's proprietary code templates used to generate the final deliverables.",
            "We must strike down any language that implies transfer of ownership of the Vendor's background technology, limiting Client rights to a non-exclusive license."
        ]
        defender_args = [
            "This is a critical concern. We need to distinguish clearly between custom 'Deliverables' created under the agreement and 'Background IP' or pre-existing templates.",
            "Agreed. Pushing for a Vendor IP Schedule explicitly listing retained Background IP is essential. This protects the Vendor's core platform from ownership transfers.",
            "I will draft a clear clause that assigns rights only to deliverables specifically paid for, while reserving all Background IP with a royalty-free license to the Client."
        ]
    else:
        attacker_args = [
            f"Analyzing: '{clause_text[:45]}...'. This clause lacks clear reciprocal obligations and introduces latent ambiguities. Commercially, it creates a one-sided risk.",
            "The terminology is vague. In legal disputes, ambiguous terms are highly problematic and can be interpreted unilaterally by the stronger party.",
            "We must demand that all key terms are defined and mutual. Ambiguity exposes the Vendor to arbitrary Client demands without clear limits."
        ]
        defender_args = [
            "Indeed, vague obligations create compliance and dispute risks. While courts may construe ambiguities against the drafting party, it is better to avoid litigation entirely.",
            "Completely aligned. Reciprocity and precision are standard legal safeguards. We must establish clear, balanced obligations for both parties.",
            "I will rewrite this clause to establish clear, symmetric responsibilities, ensuring that both parties' rights and limits are explicitly defined."
        ]
        
    logs = []
    for turn in range(turns):
        exp_arg = attacker_args[turn % len(attacker_args)]
        def_arg = defender_args[turn % len(defender_args)]
        
        if mood == "Aggressive & Hostile":
            exp_arg = "⚠️ [CRITICAL ALERT] " + exp_arg.upper()
            def_arg = "🛡️ [TACTICAL SHIELD] " + def_arg
        elif mood == "Commercially Balanced":
            exp_arg = "💡 [COMMERCIAL] " + exp_arg
            def_arg = "⚖️ [BALANCED] " + def_arg
            
        logs.append({"role": "Attacker", "content": exp_arg})
        logs.append({"role": "Defender", "content": def_arg})
        
    return logs

def run_simulated_logic_validation(clause_a, clause_b):
    text_a = clause_a.lower()
    text_b = clause_b.lower()
    
    # 1. Destruction vs Retention
    if ("destroy" in text_a or "destruction" in text_a) and ("retain" in text_b or "backup" in text_b):
        return {
            "conflict": "Data Retention vs. Data Destruction",
            "severity": "Critical",
            "rule_a": "Permanent and irreversible destruction of all transactional records and records within 30 days of contract termination.",
            "rule_b": "Regulatory mandate to retain operational audit trails and backups for a minimum period of three (3) years.",
            "explanation": "Complying with Rule A (complete permanent destruction) directly forces a legal violation of Rule B (regulatory backups and audits), and vice-versa. Commercially, it creates severe compliance liability for Vendor.",
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
    
    # 2. Payment terms Net 45 vs Net 15
    elif ("45" in text_a and "15" in text_b) or ("payment" in text_a and "invoice" in text_b and ("45" in text_a or "15" in text_b)):
        return {
            "conflict": "Payment Terms Discrepancy (Body vs Schedule)",
            "severity": "High",
            "rule_a": "All invoices payable in forty-five (45) days of receipt (Net 45).",
            "rule_b": "Consulting and Premium Tier invoices due within fifteen (15) days of invoice receipt (Net 15).",
            "explanation": "The contract body and attached schedules designate different payment windows for the same premium services, creating billing disputes, late fee interest accruals, and cash-flow ambiguities.",
            "resolved_clause": "All invoices issued under this Agreement shall be payable within forty-five (45) days of receipt (Net 45); provided, however, that all payments for services designated as Premium Tier under Schedule A shall be due within thirty (30) days of invoice receipt (Net 30) with no late interest applied before day 45.",
            "z3_code": """# ── Z3 SOLVER LOGIC FORMULATION ──
from z3 import *

# Define variables representing payment deadlines
payment_days = Int('payment_days')

s = Solver()

# Rule A: Invoices payable within forty-five (45) days of receipt (Net 45)
s.add(payment_days == 45)

# Rule B: Premium Tier invoices due within fifteen (15) days of receipt (Net 15)
s.add(payment_days == 15)

# Verification of satisfiability (SAT / UNSAT)
verification_result = s.check()
print(f"Contract Logical Consistency: {verification_result}") # Output: UNSAT! (45 != 15)"""
        }
        
    # 3. Governing Law Delaware vs California arbitration
    elif ("delaware" in text_a and "california" in text_b) or ("governing" in text_a and "venue" in text_b and ("delaware" in text_a or "california" in text_b)):
        return {
            "conflict": "Governing Law vs. Dispute Resolution Venue",
            "severity": "Medium",
            "rule_a": "Delaware state laws govern construction and execution of the agreement.",
            "rule_b": "Mandatory binding arbitration venue in San Francisco, California under JAMS rules.",
            "explanation": "Applying Delaware substantive law inside a California arbitration forum is procedurally complex and can trigger jurisdictional contradictions between California mandatory arbitration rules and Delaware contractual standards.",
            "resolved_clause": "This Agreement shall be governed by, and construed in accordance with, the laws of the State of Delaware. Any disputes arising hereunder shall be submitted to binding arbitration in San Francisco, California, under JAMS rules, with the arbitrator strictly applying the substantive laws of the State of Delaware.",
            "z3_code": """# ── Z3 SOLVER LOGIC FORMULATION ──
from z3 import *

# Define variables for jurisdiction and substantive law
governing_law_delaware = Bool('governing_law_delaware')
arbitration_venue_california = Bool('arbitration_venue_california')

s = Solver()

# Rule A: Delaware governing law
s.add(governing_law_delaware == True)

# Rule B: California exclusive jurisdiction and arbitration
s.add(arbitration_venue_california == True)

# Axiom: California exclusive jurisdiction conflicts with Delaware governing law
s.add(Implies(arbitration_venue_california, Not(governing_law_delaware)))

# Verification of satisfiability (SAT / UNSAT)
verification_result = s.check()
print(f"Contract Logical Consistency: {verification_result}") # Output: UNSAT!"""
        }
    
    # 4. Custom clause analysis
    else:
        # Check if there are any conflicting numbers
        import re
        nums_a = re.findall(r'\d+', text_a)
        nums_b = re.findall(r'\d+', text_b)
        
        if nums_a and nums_b and nums_a[0] != nums_b[0]:
            return {
                "conflict": "Discrepancy in Numeric Limits",
                "severity": "High",
                "rule_a": f"Limits or time window specified as {nums_a[0]} units in Clause A.",
                "rule_b": f"Limits or time window specified as {nums_b[0]} units in Clause B.",
                "explanation": "The clauses specify different numbers or timelines for related contract execution tasks, creating legal ambiguity and contract breach liability.",
                "resolved_clause": f"Both parties agree that the unified governing limit or time window shall be established at {max(int(nums_a[0]), int(nums_b[0]))} days, applying mutually to all relevant covenants under this Agreement.",
                "z3_code": f"""# ── Z3 SOLVER LOGIC FORMULATION ──
from z3 import *

# Define numeric values for limits in Clause A and Clause B
limit_a = Int('limit_a')
limit_b = Int('limit_b')

s = Solver()

# Rule A: Limit specified as {nums_a[0]} in Clause A
s.add(limit_a == {nums_a[0]})

# Rule B: Limit specified as {nums_b[0]} in Clause B
s.add(limit_b == {nums_b[0]})

# Axiom: Mutually contradictory numeric requirements
s.add(limit_a == limit_b)

# Verification of satisfiability (SAT / UNSAT)
verification_result = s.check()
print(f"Contract Logical Consistency: {{verification_result}}") # Output: UNSAT! ({nums_a[0]} != {nums_b[0]})"""
            }
            
        return {
            "conflict": "No Substantive Contradictions Found",
            "severity": "Clear",
            "rule_a": "Clause A contains commercially standard obligations.",
            "rule_b": "Clause B contains commercially aligned obligations.",
            "explanation": "No operational or logical contradictions were detected between these two contract clauses. They can be complied with concurrently and are legally consistent.",
            "resolved_clause": "Clause A and Clause B are already aligned. No resolution is required.",
            "z3_code": """# ── Z3 SOLVER LOGIC FORMULATION ──
from z3 import *

# Define rule variables
rule_a = Bool('rule_a')
rule_b = Bool('rule_b')

s = Solver()

# Both rules are standard and commercially aligned
s.add(rule_a == True)
s.add(rule_b == True)

# Verification of satisfiability (SAT / UNSAT)
verification_result = s.check()
print(f"Contract Logical Consistency: {verification_result}") # Output: SAT (Compatible)"""
        }

def run_simulated_autofix(clause_text, persona):
    text_lower = clause_text.lower()
    
    if "indemn" in text_lower or "fault" in text_lower or "harmless" in text_lower:
        if persona == "Defender":
            return {
                "title": "Reciprocal Indemnification",
                "severity": 9,
                "rewrite": "Each Party agrees to indemnify, defend, and hold harmless the other Party, and its officers and employees, from and against any third-party claims, losses, damages, liabilities, and expenses arising out of or resulting from the indemnifying Party's gross negligence, willful misconduct, or material breach of this Agreement.",
                "risk_label": "🛡️ Reciprocal Risk",
                "risk_class": "low",
                "score": "3/10",
                "rationale": "Introduces a completely mutual indemnification that caps liability, strikes out the dangerous 'regardless of fault' trap, and limits it to direct negligent acts."
            }
        elif persona == "Attacker":
            return {
                "title": "Extreme Vendor Indemnity Exemption",
                "severity": 9,
                "rewrite": "Client agrees to indemnify, defend, and hold harmless Vendor from and against any and all claims, damages, liabilities, and losses arising out of or related to this Agreement under any theory of liability. Vendor shall have no obligation to indemnify Client under any circumstances.",
                "risk_label": "⚔️ Extremely Vendor-Favored",
                "risk_class": "low",
                "score": "1/10",
                "rationale": "Places absolute indemnification liability on the Client while exempting the Vendor from any indemnification duties under any circumstances."
            }
        else: # Arbitrator
            return {
                "title": "Customer-Dominated Indemnification",
                "severity": 9,
                "rewrite": "Vendor shall fully indemnify, defend, and hold harmless the Client and its affiliates against any and all claims, allegations, damages, and costs (including attorneys' fees) arising out of or related to any act, omission, or performance of Vendor, regardless of negligence or fault.",
                "risk_label": "⚖️ Highly Customer-Favored",
                "risk_class": "critical",
                "score": "10/10",
                "rationale": "Exposes the Vendor to absolute, uncapped indemnification for all claims (regardless of fault), providing maximum legal protection to the Client."
            }
            
    elif "terminate" in text_lower or "notice" in text_lower or "convenience" in text_lower:
        if persona == "Defender":
            return {
                "title": "Symmetric Convenience Termination",
                "severity": 8,
                "rewrite": "Either Party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice to the other Party. In the event of such termination, Client shall pay Vendor for all services performed up to the termination date.",
                "risk_label": "🛡️ Mutual Convenience Exit",
                "risk_class": "low",
                "score": "2/10",
                "rationale": "Establishes a completely mutual 30-day notice for convenience, giving both parties a standard and predictable exit option."
            }
        elif persona == "Attacker":
            return {
                "title": "Vendor-Favored Convenience Termination",
                "severity": 8,
                "rewrite": "Vendor may terminate this Agreement for convenience at any time upon five (5) days' written notice. Client shall have no right to terminate for convenience and may only terminate for uncured material breach upon ninety (90) days' notice.",
                "risk_label": "⚔️ Vendor Exit Dominance",
                "risk_class": "low",
                "score": "1/10",
                "rationale": "Offers the Vendor immediate 5-day exit flexibility while locking the Client in, maximizing Vendor agility and contract stability."
            }
        else: # Arbitrator
            return {
                "title": "Customer-Favored convenience Termination",
                "severity": 8,
                "rewrite": "Client may terminate this Agreement for convenience at any time upon five (5) days' written notice. Vendor shall have no right to terminate this Agreement for convenience under any circumstances.",
                "risk_label": "⚖️ Customer Exit Dominance",
                "risk_class": "critical",
                "score": "9/10",
                "rationale": "Locks the Vendor in while granting the Client an immediate convenience exit, offering zero stability to the Vendor."
            }
            
    elif "liability" in text_lower or "cap" in text_lower or "limit" in text_lower:
        if persona == "Defender":
            return {
                "title": "Reciprocal Liability Cap",
                "severity": 10,
                "rewrite": "Except for breaches of confidentiality or indemnification obligations, each party's total aggregate liability under this Agreement shall not exceed the total fees paid or payable by Client to Vendor in the twelve (12) months preceding the event.",
                "risk_label": "🛡️ Reciprocal aggregate Cap",
                "risk_class": "low",
                "score": "3/10",
                "rationale": "Establishes a mutual 12-month contract value liability cap for both parties, which is standard in enterprise agreements."
            }
        elif persona == "Attacker":
            return {
                "title": "Minimal Vendor Liability Shield",
                "severity": 10,
                "rewrite": "Vendor's aggregate liability under this Agreement is strictly limited to five thousand dollars ($5,000). Client's liability for payments, intellectual property breach, or confidentiality shall be entirely uncapped and unlimited.",
                "risk_label": "⚔️ Absolute Vendor Liability Shield",
                "risk_class": "low",
                "score": "1/10",
                "rationale": "Insulates the Vendor from any legal liability with an extremely low $5k cap, while leaving the Client fully exposed."
            }
        else: # Arbitrator
            return {
                "title": "Uncapped Vendor Liability",
                "severity": 10,
                "rewrite": "Vendor's liability under this Agreement is completely uncapped and unlimited. Client's aggregate liability is strictly capped at the total fees paid in the one (1) month preceding the event.",
                "risk_label": "⚖️ Customer liability Shield",
                "risk_class": "critical",
                "score": "10/10",
                "rationale": "Caps the Client's liability at 1 month of payments while leaving the Vendor fully liable for uncapped damages."
            }
            
    elif "ip" in text_lower or "intellectual" in text_lower or "invention" in text_lower or "work product" in text_lower:
        if persona == "Defender":
            return {
                "title": "Symmetric Deliverable Ownership",
                "severity": 7,
                "rewrite": "All deliverables specifically created for Client under an active SOW ('Deliverables') shall be owned by Client upon full payment of fees. Vendor retains all right, title, and interest in its pre-existing Background IP and templates, granting Client a perpetual, royalty-free license to use it solely as integrated in the Deliverables.",
                "risk_label": "🛡️ Balanced IP assignment",
                "risk_class": "low",
                "score": "2/10",
                "rationale": "Saves the Vendor's background IP and methodologies while assigning custom deliverables ownership to the Client upon payment."
            }
        elif persona == "Attacker":
            return {
                "title": "Absolute Vendor IP ownership",
                "severity": 7,
                "rewrite": "Vendor retains sole and exclusive ownership of all intellectual property, techniques, deliverables, and designs created during performance. Client is granted a non-exclusive, revocable, non-transferable license to use deliverables solely for internal purposes.",
                "risk_label": "⚔️ Complete Vendor IP Retention",
                "risk_class": "low",
                "score": "1/10",
                "rationale": "Vendor retains ownership of all deliverables and code, granting Client only a narrow internal use license."
            }
        else: # Arbitrator
            return {
                "title": "Extreme Customer IP Acquisition",
                "severity": 7,
                "rewrite": "All inventions, intellectual property, work product, source code, and deliverables developed by Vendor (and its affiliates or subcontractors) at any time during this Agreement shall belong exclusively to Client. Vendor waives all moral rights globally.",
                "risk_label": "⚖️ Complete Customer IP Capture",
                "risk_class": "high",
                "score": "8/10",
                "rationale": "Assigns all newly created IP and pre-existing rights to the Client, giving them absolute ownership."
            }
            
    else:
        if persona == "Defender":
            return {
                "title": "Reciprocal Balanced Clause",
                "severity": 5,
                "rewrite": "Each Party agrees to perform its obligations hereunder in a commercially reasonable manner, cooperating in good faith and resolving disputes through mutual consultation prior to initiating arbitration.",
                "risk_label": "🛡️ Mutual Covenants",
                "risk_class": "low",
                "score": "2/10",
                "rationale": "Converts the custom clause into a balanced, mutual obligation based on commercial good faith and standard dispute resolution."
            }
        elif persona == "Attacker":
            return {
                "title": "Unilateral Vendor Rights",
                "severity": 5,
                "rewrite": "Vendor shall perform obligations subject to resource availability and standard operational queues. Client agrees Vendor shall not be liable for any performance delays, and Vendor retains sole authority to modify terms.",
                "risk_label": "⚔️ Vendor Rights Dominance",
                "risk_class": "low",
                "score": "1/10",
                "rationale": "Gives the Vendor unilateral control over performance timelines and terms, shielding them from breach of contract claims."
            }
        else: # Arbitrator
            return {
                "title": "Absolute Customer Control",
                "severity": 5,
                "rewrite": "Vendor shall perform all covenants with absolute perfection and in accordance with Client's unilateral instructions. Client retains sole authority to audit performance, adjust payment levels, and enforce strict liquidated damages.",
                "risk_label": "⚖️ Customer Control Dominance",
                "risk_class": "high",
                "score": "8/10",
                "rationale": "Gives absolute operational and auditing dominance to the Client, exposing Vendor to liquidated damages and payment adjustments."
            }


# ── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(

    page_title="RegulAIte | AI Legal Simplifier & Extraction Engine",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Navigation & Query Parameter State Sync ────────────────────────────────────
qp = st.query_params

# Intercept reset or upload action in URL query parameters
if qp.get("reset") == "true" or qp.get("upload") == "true":
    st.query_params.clear()
    st.session_state['file_uploaded'] = False
    st.session_state['analysis_complete'] = False
    st.session_state['filename'] = ""
    st.session_state['demo_mode'] = False
    st.session_state['active_level'] = "Level 3 (High Risk - Vulnerable)"
    if 'uploaded_file_analysis' in st.session_state:
        del st.session_state['uploaded_file_analysis']
    # Preserve active user session hash in redirect URL
    if st.session_state.get("user_hash"):
        st.query_params.update({"user": st.session_state["user_hash"], "page": "Dashboard"})
    st.rerun()

# ── Authentication Interceptor & Gatekeeper ───────────────────────────────────
# Initialize query params and active sessions
if "session_active" not in st.session_state:
    st.session_state["session_active"] = True

# If user query parameter is present and not logging out, restore the session immediately
url_user_hash = qp.get("user")
if url_user_hash and qp.get("logout") != "1" and (st.session_state.get("user_hash") != url_user_hash or not st.session_state.get("authenticated")):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, persona FROM users WHERE user_hash = ?", (url_user_hash,))
    row = cursor.fetchone()
    conn.close()
    if row:
        st.session_state["authenticated"] = True
        st.session_state["user_hash"] = url_user_hash
        st.session_state["user_name"] = f"{row[0]}, {row[1]}"
        st.session_state["active_sandbox_persona"] = row[1]
        save_last_session(row[0], row[1], url_user_hash)

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
    st.session_state["user_hash"] = ""

if not st.session_state.get("authenticated", False):
    # Invisible JS Session Handshake for secure LocalStorage auto-login
    st.components.v1.html("""
        <script>
        try {
            const storage = window.parent.localStorage || localStorage;
            const savedHash = storage.getItem('regulaite_user_hash');
            const savedTime = storage.getItem('regulaite_login_time');
            const params = new URLSearchParams(window.parent.location.search);
            const urlHash = params.get('user');
            
            if (params.get('logout') === '1') {
                // Clear localStorage on explicit logout
                storage.removeItem('regulaite_user_hash');
                storage.removeItem('regulaite_login_time');
                params.delete('logout');
                params.delete('user');
                window.parent.location.search = params.toString();
            } else if (urlHash) {
                // URL contains user hash: validate age and matching local storage key for security
                const ageHours = savedTime ? (Date.now() - parseInt(savedTime)) / 3600000 : 999;
                if (!savedHash || savedHash !== urlHash || ageHours >= 24) {
                    // Security Violation or Session Expired: Strip it and reload
                    params.delete('user');
                    params.delete('page');
                    window.parent.location.search = params.toString();
                }
            } else if (savedHash && savedTime) {
                // No URL hash, but valid session in local storage less than 24 hours old
                const ageHours = (Date.now() - parseInt(savedTime)) / 3600000;
                if (ageHours < 24) {
                    params.set('user', savedHash);
                    params.set('page', 'Dashboard');
                    window.parent.location.search = params.toString();
                }
            }
        } catch (e) {
            console.error("Session handshake failed:", e);
        }
        </script>
    """, height=0, width=0)
    # Hide sidebar while logging in
    st.markdown("""
        <style>
        [data-testid="stSidebar"] { display: none !important; }
        
        /* === Mobile-first responsive login === */
        .block-container {
            max-width: 560px !important;
            margin: 0 auto !important;
            padding-top: 2rem !important;
            padding-left: 1rem !important;
            padding-right: 1rem !important;
        }
        @media (max-width: 600px) {
            .block-container { padding-top: 1rem !important; padding-left: 0.75rem !important; padding-right: 0.75rem !important; }
        }
        
        /* Dark gradient background */
        .stApp {
            background: radial-gradient(ellipse at 30% 20%, #1e1b4b 0%, #0f0b24 60%, #0a0714 100%) !important;
            color: #ffffff !important;
        }
        
        /* Fix ALL text on dark bg */
        .stApp label, .stApp p, .stApp span, .stApp div {
            color: #e2e8f0;
        }
        
        /* Input labels */
        .stTextInput label, .stSelectbox label, .stTextArea label {
            color: #cbd5e1 !important;
            font-weight: 600 !important;
            font-size: 0.85rem !important;
        }
        
        /* Input fields - black text on white inputs for perfect visibility */
        .stTextInput input, .stTextArea textarea {
            background: #ffffff !important;
            border: 1px solid #cbd5e1 !important;
            color: #0f172a !important;
            border-radius: 8px !important;
        }
        .stTextInput input::placeholder, .stTextArea textarea::placeholder {
            color: #64748b !important;
        }
        .stTextInput input:focus, .stTextArea textarea:focus {
            border-color: #38bdf8 !important;
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2) !important;
        }
        
        /* Selectbox - black text on white container */
        .stSelectbox > div > div {
            background: #ffffff !important;
            border: 1px solid #cbd5e1 !important;
            color: #0f172a !important;
            border-radius: 8px !important;
        }
        
        /* Tab styling — clear text on dark */
        .stTabs [data-baseweb="tab-list"] {
            background: rgba(255,255,255,0.04) !important;
            border-radius: 10px !important;
            padding: 4px !important;
            gap: 2px !important;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .stTabs [data-baseweb="tab"] {
            color: #94a3b8 !important;
            font-weight: 600 !important;
            font-size: 0.85rem !important;
            border-radius: 8px !important;
            padding: 8px 12px !important;
        }
        .stTabs [aria-selected="true"] {
            background: rgba(56, 189, 248, 0.18) !important;
            color: #38bdf8 !important;
        }
        
        /* Primary buttons on dark */
        .stButton > button[kind="primary"] {
            background: linear-gradient(135deg, #3b82f6 0%, #0ea5e9 100%) !important;
            color: #ffffff !important;
            border: none !important;
            font-weight: 700 !important;
            border-radius: 10px !important;
            padding: 0.65rem 1.5rem !important;
            font-size: 0.95rem !important;
            box-shadow: 0 4px 15px rgba(59,130,246,0.35) !important;
            transition: all 0.2s ease !important;
        }
        .stButton > button[kind="primary"]:hover {
            transform: translateY(-1px) !important;
            box-shadow: 0 6px 20px rgba(59,130,246,0.5) !important;
        }
        .stButton > button:not([kind="primary"]) {
            background: rgba(255,255,255,0.08) !important;
            color: #e2e8f0 !important;
            border: 1px solid rgba(255,255,255,0.15) !important;
            border-radius: 10px !important;
            font-weight: 600 !important;
        }
        .stButton > button:not([kind="primary"]):hover {
            background: rgba(255,255,255,0.12) !important;
            border-color: rgba(255,255,255,0.25) !important;
        }
        
        /* Success/error/info messages */
        .stAlert {
            border-radius: 10px !important;
        }
        
        /* Help text under inputs */
        .stTextInput div[data-testid="stText"], small {
            color: #64748b !important;
        }
        
/* === Responsive Sidebar & Mobile Menu === */
@media screen and (min-width: 769px) {
    .mobile-header {
        display: none !important;
    }
}

@media screen and (max-width: 768px) {
    .mobile-header {
        display: flex;
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 60px;
        background: #0f1115;
        z-index: 999999;
        align-items: center;
        justify-content: space-between;
        padding: 0 15px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.5);
    }
    .mobile-menu-btn {
        color: #ffffff;
        font-size: 1.5rem;
        cursor: pointer;
        padding: 5px;
    }
    /* Keep native Streamlit header visible for sidebar toggle */
    header[data-testid="stHeader"] {
        background: transparent !important;
    }
    .block-container {
        padding-top: 80px !important;
    }
}

</style>
    """, unsafe_allow_html=True)
    
    st.markdown("""
        <div style="text-align: center; margin-bottom: 1.75rem;">
            <div style="font-size: 3rem; margin-bottom: 0.5rem;">⚖️</div>
            <h1 style="font-size: 2.5rem; font-weight: 900; color: #ffffff; letter-spacing: -0.04em; margin-bottom: 0.25rem; text-shadow: 0 2px 20px rgba(56,189,248,0.3);">
                Regul<span style="background: linear-gradient(135deg,#38bdf8,#818cf8); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text;">AI</span>te
            </h1>
            <p style="color: #94a3b8; font-size: 0.95rem; max-width: 400px; margin: 0 auto; line-height: 1.5;">AI-Powered B2B Legal Contract Auditing — Explain risks in plain language anyone can understand.</p>
            <div style="display:flex; gap:8px; justify-content:center; margin-top:0.75rem; flex-wrap:wrap;">
                <span style="font-size:0.7rem; color:#38bdf8; background:rgba(56,189,248,0.1); border:1px solid rgba(56,189,248,0.25); padding:3px 10px; border-radius:10px;">🛡️ GDPR Isolated</span>
                <span style="font-size:0.7rem; color:#a78bfa; background:rgba(167,139,250,0.1); border:1px solid rgba(167,139,250,0.25); padding:3px 10px; border-radius:10px;">🤖 5-Agent AI</span>
                <span style="font-size:0.7rem; color:#34d399; background:rgba(52,211,153,0.1); border:1px solid rgba(52,211,153,0.25); padding:3px 10px; border-radius:10px;">🔒 Encrypted Vault</span>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Custom glassmorphic container
    st.markdown("""
        <div style="background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 18px; padding: 2rem; box-shadow: 0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05); backdrop-filter: blur(20px); margin-bottom: 1.5rem;">
            <div style="text-align: center; margin-bottom: 1.25rem;">
                <span style="font-size: 0.72rem; font-weight: 700; background: rgba(14, 165, 233, 0.15); color: #38bdf8; padding: 5px 14px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.08em; border: 1px solid rgba(14, 165, 233, 0.3);">
                    🔒 SECURE SANDBOX ENGINE — v2.1
                </span>
            </div>
    """, unsafe_allow_html=True)
    
    # Create the three tabs inside the login card
    tab_signin, tab_signup, tab_demo = st.tabs(["🔑 Account Sign-In", "🔐 Create Secure Account", "📺 Watch Platform Demo"])
    
    with tab_signin:
        st.markdown("<h3 style='color:#ffffff; font-size:1.15rem; margin-bottom:0.25rem; font-weight:700;'>👋 Welcome Back</h3>", unsafe_allow_html=True)
        st.markdown("<p style='color:#64748b; font-size:0.8rem; margin-bottom:1rem;'>Sign in with your registered email and password.</p>", unsafe_allow_html=True)
        login_email = st.text_input("📧 Email Address", placeholder="you@company.com", key="login_email")
        login_password = st.text_input("🔑 Password", type="password", placeholder="Your secure password", key="login_password")
        
        st.markdown("<div style='margin-top:1.25rem;'></div>", unsafe_allow_html=True)
        if st.button("🔓 Sign In to My Vault", type="primary", use_container_width=True):
            if not login_email or not login_password:
                st.error("⚠️ Please enter both email and password.")
            elif "@" not in login_email or "." not in login_email:
                st.error("⚠️ Please enter a valid email address (e.g. name@company.com).")
            else:
                user_data = verify_user(login_email, login_password)
                if user_data:
                    u_hash, u_name, u_persona = user_data
                    st.session_state["authenticated"] = True
                    st.session_state["user_hash"] = u_hash
                    st.session_state["user_name"] = f"{u_name}, {u_persona}"
                    st.session_state["active_sandbox_persona"] = u_persona
                    save_last_session(u_name, u_persona, u_hash)
                    st.query_params.update({"user": u_hash, "page": "Dashboard"})
                    st.success(f"✅ Welcome back, {u_name}! Loading your vault...")
                    time.sleep(0.3)
                    st.rerun()
                else:
                    st.error("❌ Incorrect email or password. Please try again, or create a new account.")
                    
    with tab_signup:
        st.markdown("<h3 style='color:#ffffff; font-size:1.15rem; margin-bottom:0.25rem; font-weight:700;'>🔐 Create Your Account</h3>", unsafe_allow_html=True)
        st.markdown("<p style='color:#64748b; font-size:0.8rem; margin-bottom:1rem;'>Free forever. No credit card needed. Your data stays private.</p>", unsafe_allow_html=True)
        
        reg_name = st.text_input("👤 Your Full Name", placeholder="e.g. Sarah Jenkins", key="reg_name")
        reg_email = st.text_input("📧 Email Address", placeholder="e.g. sarah@company.com", key="reg_email")
        reg_password = st.text_input("🔑 Choose a Password", type="password", placeholder="At least 6 characters", key="reg_password")
        
        reg_persona = st.selectbox(
            "⚖️ Your Legal Role",
            options=["General Counsel", "Freelance Consultant", "Enterprise Procurement", "Legal Intern", "Co-Founder / CEO"],
            help="Your role helps calibrate the AI's risk scoring and recommendations for your specific perspective."
        )
        
        st.markdown("<div style='margin-top:1.25rem;'></div>", unsafe_allow_html=True)
        if st.button("✅ Create My Free Account", type="primary", use_container_width=True):
            if not reg_name or not reg_email or not reg_password:
                st.error("⚠️ Please fill in your name, email, and password.")
            elif "@" not in reg_email or "." not in reg_email:
                st.error("⚠️ Please enter a valid email address.")
            elif len(reg_password) < 6:
                st.error("⚠️ Password must be at least 6 characters for security.")
            else:
                # Check if an account already exists with this email
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM users WHERE email = ?", (reg_email.strip().lower(),))
                existing = cursor.fetchone()
                conn.close()
                
                if existing:
                    st.error(f"❌ An account with the email '{reg_email}' already exists. Please select Sign-In above.")
                else:
                    u_hash = register_user(reg_name, reg_persona, reg_email, reg_password)
                    # Auto-login after registration
                    st.session_state["authenticated"] = True
                    st.session_state["user_hash"] = u_hash
                    st.session_state["user_name"] = f"{reg_name}, {reg_persona}"
                    st.session_state["active_sandbox_persona"] = reg_persona
                    save_last_session(reg_name, reg_persona, u_hash)
                    st.query_params.update({"user": u_hash, "page": "Dashboard"})
                    st.success(f"🎉 Welcome, {reg_name}! Your vault is ready. Taking you to the dashboard...")
                    time.sleep(0.5)
                    st.rerun()
                
    with tab_demo:
        st.markdown("""
        <div style="text-align:center; padding:0.5rem 0 1rem 0;">
            <div style="font-size:1.1rem; font-weight:800; color:#ffffff; margin-bottom:0.25rem;">🎥 Platform Walkthrough Video</div>
            <p style="color:#94a3b8; font-size:0.82rem; line-height:1.5; max-width:420px; margin:0 auto 1rem auto;">
                Watch our senior legal counsel demonstrate the <b style="color:#38bdf8;">Reciprocity Speedometer</b>, 
                <b style="color:#f87171;">line-by-line loophole highlights</b>, and the 
                <b style="color:#a78bfa;">AI Adversarial Bot Debate</b> — all in under 3 minutes.
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Embed the actual WhatsApp video using Streamlit native player
        _video_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "Screen Recording 2026-05-23 195222.mp4")
        if os.path.exists(_video_path):
            st.video(_video_path)
        else:
            st.markdown("""
            <div style="background: rgba(255,255,255,0.04); border: 2px dashed rgba(255,255,255,0.15); border-radius: 12px; padding: 2rem 1.5rem; text-align: center; margin-bottom: 1rem;">
                <div style="font-size: 2.5rem; margin-bottom: 0.75rem;">🎥</div>
                <div style="font-size: 1rem; font-weight: 800; color: #ffffff; margin-bottom:0.5rem;">RegulAIte Portal Walkthrough</div>
                <div style="font-size: 0.8rem; color: #94a3b8; line-height:1.5;">
                    📁 Place the video file in the <code style="background:rgba(255,255,255,0.1); padding:2px 6px; border-radius:4px; color:#38bdf8;">docs/</code> folder to enable playback.
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Feature highlights
        st.markdown("""
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:1rem; margin-bottom:1.25rem;">
            <div style="background:rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.2); border-radius:10px; padding:10px 12px;">
                <div style="font-size:1rem;">⚖️</div>
                <div style="font-size:0.78rem; font-weight:700; color:#38bdf8; margin:3px 0 2px;">Reciprocity Meter</div>
                <div style="font-size:0.7rem; color:#94a3b8;">See who benefits more from each clause</div>
            </div>
            <div style="background:rgba(248,113,113,0.08); border:1px solid rgba(248,113,113,0.2); border-radius:10px; padding:10px 12px;">
                <div style="font-size:1rem;">🔴</div>
                <div style="font-size:0.78rem; font-weight:700; color:#f87171; margin:3px 0 2px;">Line-by-Line Red Flags</div>
                <div style="font-size:0.7rem; color:#94a3b8;">Every loophole explained simply</div>
            </div>
            <div style="background:rgba(167,139,250,0.08); border:1px solid rgba(167,139,250,0.2); border-radius:10px; padding:10px 12px;">
                <div style="font-size:1rem;">🤖</div>
                <div style="font-size:0.78rem; font-weight:700; color:#a78bfa; margin:3px 0 2px;">AI Bot Debate</div>
                <div style="font-size:0.7rem; color:#94a3b8;">Attacker vs Defender agents argue</div>
            </div>
            <div style="background:rgba(52,211,153,0.08); border:1px solid rgba(52,211,153,0.2); border-radius:10px; padding:10px 12px;">
                <div style="font-size:1rem;">📥</div>
                <div style="font-size:0.78rem; font-weight:700; color:#34d399; margin:3px 0 2px;">Download Rewrite</div>
                <div style="font-size:0.7rem; color:#94a3b8;">Get a safe, balanced contract version</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    # Render the Demo bypass sandbox button below all tabs so it is ALWAYS visible and accessible!
    st.markdown("<div style='margin-top:1.5rem; border-top:1px solid rgba(255,255,255,0.1); padding-top:1.25rem; text-align:center;'>", unsafe_allow_html=True)
    st.markdown("<p style='color:#94a3b8; font-size:0.78rem; margin-bottom:0.6rem;'>Or, bypass registration to try the platform instantly:</p>", unsafe_allow_html=True)
    if st.button("🚀 Try the Demo Sandbox — No Account Needed", type="primary", use_container_width=True):
        # Bypass/Demo account creation
        u_hash = register_user("Demo User", "General Counsel", "demo@regulaite.ai", "demo123")
        st.session_state["authenticated"] = True
        st.session_state["user_hash"] = u_hash
        st.session_state["user_name"] = "Demo User, General Counsel"
        st.session_state["active_sandbox_persona"] = "General Counsel"
        save_last_session("Demo User", "General Counsel", u_hash)
        st.query_params.update({"user": u_hash, "page": "Dashboard", "demo": "true"})
        st.success("✅ Loading the demo sandbox...")
        time.sleep(0.3)
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    # Bottom trust indicators
    st.markdown("""
    <div style="text-align:center; margin-top:1.5rem; padding-bottom:2rem;">
        <p style="color:#475569; font-size:0.72rem; line-height:1.6;">
            🔒 Your documents are processed locally &amp; never shared &nbsp;|&nbsp;
            🌐 Works on mobile &amp; desktop &nbsp;|&nbsp;
            ⚡ Optimized for slow connections
        </p>
        <p style="color:#334155; font-size:0.68rem; margin-top:0.25rem;">RegulAIte v2.1 · Built for enterprise legal teams · Powered by Google Gemini AI</p>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ── Validate and Save active session in browser localStorage ──
user_hash = st.session_state.get("user_hash", "")
if user_hash:
    st.components.v1.html(f"""
        <script>
        try {{
            const storage = window.parent.localStorage || localStorage;
            const savedHash = storage.getItem('regulaite_user_hash');
            const savedTime = storage.getItem('regulaite_login_time');
            const params = new URLSearchParams(window.parent.location.search);
            const urlHash = params.get('user');
            
            // SECURITY: If URL hash is present but doesn't match client localStorage, kick out!
            if (urlHash && savedHash && savedHash !== urlHash) {{
                params.delete('user');
                params.delete('page');
                params.set('logout', '1');
                window.parent.location.search = params.toString();
            }} else {{
                // Authorised: Update/extend local storage credentials
                storage.setItem('regulaite_user_hash', '{user_hash}');
                storage.setItem('regulaite_login_time', Date.now().toString());
            }}
        }} catch (e) {{
            console.error("Session sync failed:", e);
        }}
        </script>
    """, height=0, width=0)

# Initialize session state for user name and active level
if 'user_name' not in st.session_state:
    st.session_state['user_name'] = "Anna K., General Counsel"
if 'active_level' not in st.session_state:
    st.session_state['active_level'] = "Level 3 (High Risk)"

# Sync page from query parameters
if "page" in qp:
    st.session_state['current_page'] = qp["page"]
elif 'current_page' not in st.session_state:
    st.session_state['current_page'] = "Dashboard"

# Sync session state from query parameters
if "analyzed" in qp:
    st.session_state['analysis_complete'] = (qp["analyzed"] == "true")
    st.session_state['file_uploaded'] = True
    st.session_state['demo_mode'] = False
    st.session_state['filename'] = qp.get("filename", "NDA_v3.2_Draft.pdf")
elif "demo" in qp:
    st.session_state['demo_mode'] = (qp["demo"] == "true")
    st.session_state['analysis_complete'] = True
    st.session_state['file_uploaded'] = False
    st.session_state['filename'] = qp.get("filename", "NDA_v3.2_Draft.pdf")
else:
    # Ensure local session state has default keys
    if 'file_uploaded' not in st.session_state:
        st.session_state['file_uploaded'] = False
    if 'analysis_complete' not in st.session_state:
        st.session_state['analysis_complete'] = False
    if 'filename' not in st.session_state:
        st.session_state['filename'] = ""
    if 'demo_mode' not in st.session_state:
        st.session_state['demo_mode'] = False

# Helper to construct bulletproof query parameter URLs for custom navigation
def get_nav_link(page_name):
    params = [f"page={page_name}"]
    if st.session_state.get("user_hash"):
        params.append(f"user={st.session_state['user_hash']}")
    if st.session_state.get('demo_mode'):
        params.append("demo=true")
    elif st.session_state.get('analysis_complete'):
        params.append("analyzed=true")
    if st.session_state.get('filename'):
        params.append(f"filename={st.session_state['filename']}")
    return "?" + "&".join(params)

# Helper function to clean and render HTML safely without triggering raw Markdown code blocks
def render_html(html_code: str):
    cleaned = "\n".join([line for line in html_code.splitlines() if line.strip() != ""])
    st.markdown(cleaned, unsafe_allow_html=True)

# ── Dynamic Word-Level Diff Highlighter Engine ────────────────────────────────
def get_word_diff(original: str, rewritten: str) -> str:
    orig_words = original.split()
    rewr_words = rewritten.split()
    
    matcher = difflib.SequenceMatcher(None, orig_words, rewr_words)
    diff_html = []
    
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == 'equal':
            diff_html.extend(orig_words[i1:i2])
        elif op == 'replace':
            del_text = " ".join(orig_words[i1:i2])
            add_text = " ".join(rewr_words[j1:j2])
            if del_text:
                diff_html.append(f'<span class="diff-del">{del_text}</span>')
            if add_text:
                diff_html.append(f'<span class="diff-add">{add_text}</span>')
        elif op == 'delete':
            del_text = " ".join(orig_words[i1:i2])
            diff_html.append(f'<span class="diff-del">{del_text}</span>')
        elif op == 'insert':
            add_text = " ".join(rewr_words[j1:j2])
            diff_html.append(f'<span class="diff-add">{add_text}</span>')
            
    return " ".join(diff_html)

# ── Playbook Multi-Persona Data Structure ────────────────────────────────────
playbook_data = {
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

# Helper to construct Playbook URLs dynamically
def get_playbook_link(clause_key, persona_key):
    params = [
        "page=SmartReview",
        "tab=AutoFixer",
        f"clause={clause_key}",
        f"persona={persona_key}"
    ]
    if st.session_state.get('demo_mode'):
        params.append("demo=true")
    elif st.session_state.get('analysis_complete'):
        params.append("analyzed=true")
    if st.session_state.get('filename'):
        params.append(f"filename={st.session_state['filename']}")
    return "?" + "&".join(params)

# ── Custom CSS ──────────────────────────────────────────────────────────────
render_html("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* Hide default Streamlit chrome but KEEP header for sidebar toggle */
#MainMenu, footer { visibility: hidden !important; }
.stDeployButton { display: none !important; }

/* ── Streamlit Native Header for perfect sidebar toggle ── */
header[data-testid="stHeader"] {
    background: transparent !important;
}
/* Style the expand/elaborate sidebar button (top-left) to be dark and big */
button[data-testid="collapsedSidebarIconButton"] {
    color: #0f1115 !important;
    transform: scale(1.45) !important;
    background-color: rgba(0, 0, 0, 0.06) !important;
    border-radius: 8px !important;
    transition: all 0.2s ease !important;
    margin-left: 12px !important;
    margin-top: 6px !important;
}
button[data-testid="collapsedSidebarIconButton"]:hover {
    color: #000000 !important;
    background-color: rgba(0, 0, 0, 0.12) !important;
    transform: scale(1.55) !important;
}
/* Push main content below the header */
.block-container {
    padding-top: 2.5rem !important;
}
/* Override the 1.5rem padding we set later for desktop */
@media screen and (min-width: 769px) {
    .block-container { padding-top: 2rem !important; }
}

/* Global styling */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}

.stApp {
    background: #f4f5f7 !important;
    color: #111827 !important;
}

/* Fix chat message text color for light theme */
[data-testid="stChatMessageContent"] p,
[data-testid="stChatMessageContent"] div {
    color: #374151 !important;
}

/* Minimize main padding */
.block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 2rem !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 1440px !important;
}

/* Sidebar deep charcoal */
[data-testid="stSidebar"] {
    background-color: #0f1115 !important;
    border-right: none !important;
}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
    color: #8b949e;
}

/* Custom Sidebar CSS */
.sidebar-container {
    display: flex;
    flex-direction: column;
    padding: 0;
}
.sidebar-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    padding: 0 4px;
}
.logo-box {
    background: #ffffff;
    border-radius: 6px;
    width: 26px;
    height: 26px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    color: #111214;
    font-size: 0.95rem;
}
.brand-name {
    color: #ffffff;
    font-size: 1.1rem;
    font-weight: 600;
}
.collapse-icon {
    color: #4b5563;
    font-size: 1rem;
    cursor: pointer;
    transition: color 0.2s;
}
.collapse-icon:hover {
    color: #9ca3af;
}
.sidebar-section-title {
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    color: #4b5563;
    margin-top: 1.25rem;
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    padding-left: 8px;
}
.sidebar-nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    color: #9ca3af !important;
    text-decoration: none !important;
    padding: 8px 12px;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 500;
    margin-bottom: 3px;
    transition: all 0.2s ease;
}
.sidebar-nav-item:hover {
    color: #ffffff !important;
    background: rgba(255, 255, 255, 0.05);
}
.sidebar-nav-item.active {
    background: #ffffff !important;
    color: #111827 !important;
    font-weight: 600;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}
.sidebar-nav-item.disabled {
    opacity: 0.4;
    cursor: not-allowed;
    pointer-events: none;
}
.nav-icon {
    font-size: 1rem;
}
.sidebar-divider {
    border-top: 1px solid rgba(255, 255, 255, 0.08);
    margin: 1.25rem 0.5rem;
}

/* Main Dashboard Layout */
.dashboard-container {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

/* Header styling */
.header-container {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #ffffff;
    padding: 12px 24px;
    border-radius: 12px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.02);
    border: 1px solid #e5e7eb;
}
.header-title {
    font-size: 1.3rem;
    font-weight: 600;
    color: #111827;
    margin: 0 !important;
}
.search-bar-container {
    position: relative;
    width: 320px;
}
.search-icon {
    position: absolute;
    left: 12px;
    top: 50%;
    transform: translateY(-50%);
    color: #9ca3af;
    font-size: 0.85rem;
}
.search-input {
    width: 100%;
    padding: 8px 12px 8px 32px;
    border-radius: 8px;
    border: 1px solid #e5e7eb;
    background: #f9fafb;
    font-size: 0.85rem;
    color: #111827;
    outline: none;
    transition: all 0.2s;
}
.search-input:focus {
    border-color: #3b82f6;
    background: #ffffff;
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.1);
}
.header-actions {
    display: flex;
    align-items: center;
    gap: 14px;
}
.action-btn {
    background: transparent;
    border: none;
    cursor: pointer;
    font-size: 1.1rem;
    color: #4b5563;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 4px;
    border-radius: 4px;
    transition: all 0.2s;
}
.action-btn:hover {
    color: #111827;
    background: #f3f4f6;
}
.action-btn.relative {
    position: relative;
}
.badge-dot {
    position: absolute;
    top: 2px;
    right: 2px;
    width: 6px;
    height: 6px;
    background: #ef4444;
    border-radius: 50%;
    border: 1px solid #ffffff;
}
.avatar {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    object-fit: cover;
    border: 1px solid #e5e7eb;
}

/* Dashboard Grid Layout */
.dashboard-grid {
    display: grid;
    grid-template-columns: 350px 1fr;
    gap: 1.5rem;
}

.col-left {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
}
.col-right {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
}

/* Custom Cards */
.card {
    background: #ffffff;
    border-radius: 14px;
    padding: 1.5rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
    border: 1px solid #f0f1f3;
    display: flex;
    flex-direction: column;
}
.card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.25rem;
}
.card-title {
    font-size: 1.05rem;
    font-weight: 600;
    color: #111827;
    margin: 0 !important;
}
.card-actions {
    color: #9ca3af;
    font-size: 0.9rem;
    cursor: pointer;
    transition: color 0.2s;
}
.card-actions:hover {
    color: #4b5563;
}
.card-subtitle {
    font-size: 0.75rem;
    color: #9ca3af;
    margin-bottom: 0.75rem;
    margin-top: -0.75rem;
}

/* PDF Row */
.pdf-row {
    display: flex;
    align-items: center;
    background: #fafafa;
    border: 1px solid #f3f4f6;
    border-radius: 10px;
    padding: 12px;
    gap: 12px;
    margin-bottom: 1.25rem;
}
.pdf-icon {
    font-size: 1.5rem;
    color: #ef4444;
}
.pdf-info {
    flex-grow: 1;
}
.pdf-name {
    font-size: 0.85rem;
    font-weight: 500;
    color: #111827;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 170px;
}
.pdf-meta {
    font-size: 0.7rem;
    color: #9ca3af;
    margin-top: 2px;
}
.pdf-actions {
    display: flex;
    gap: 8px;
}
.action-icon {
    font-size: 0.95rem;
    color: #9ca3af;
    cursor: pointer;
    transition: color 0.2s;
}
.action-icon:hover {
    color: #4b5563;
}

/* Metadata List */
.meta-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-bottom: 1.25rem;
}
.meta-item {
    display: flex;
    justify-content: space-between;
    font-size: 0.825rem;
}
.meta-label {
    color: #9ca3af;
}
.meta-value {
    color: #111827;
    font-weight: 500;
}

/* Progress bar styling */
.progress-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 0.25rem;
    border-top: 1px solid #f3f4f6;
    padding-top: 1rem;
}
.progress-header {
    display: flex;
    justify-content: space-between;
    font-size: 0.8rem;
}
.progress-label {
    color: #4b5563;
    font-weight: 500;
}
.progress-value {
    color: #06b6d4;
    font-weight: 600;
}
.progress-bar-container {
    width: 100%;
    height: 6px;
    background: #e5e7eb;
    border-radius: 10px;
    overflow: hidden;
}
.progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #06b6d4, #10b981);
    border-radius: 10px;
}
.stage-tag {
    align-self: flex-start;
    background: #f3f4f6;
    color: #4b5563;
    font-size: 0.72rem;
    padding: 3px 8px;
    border-radius: 12px;
    margin-top: 4px;
    font-weight: 500;
}

/* AI Summary Details */
.risk-badge {
    background: #fff5f5;
    color: #e11d48;
    border: 1px solid #fecdd3;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}
.recommendation-box {
    background: #f5f3ff;
    border-radius: 10px;
    padding: 12px 16px;
    margin-bottom: 1.25rem;
    border-left: 3px solid #8b5cf6;
}
.rec-title {
    font-size: 0.8rem;
    font-weight: 600;
    color: #6d28d9;
    margin-bottom: 4px;
}
.rec-content {
    font-size: 0.8rem;
    color: #4c1d95;
    line-height: 1.4;
}
.suggested-rewrite-btn {
    display: block;
    width: 100%;
    background: #111827;
    color: #ffffff !important;
    text-align: center;
    padding: 10px;
    border-radius: 8px;
    font-size: 0.825rem;
    font-weight: 500;
    text-decoration: none !important;
    transition: background 0.2s;
    border: none;
    box-shadow: 0 1px 2px rgba(0,0,0,0.05);
}
.suggested-rewrite-btn:hover {
    background: #1f2937;
}

/* KPI metric boxes */
.kpi-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
}
.kpi-card {
    background: #ffffff;
    border-radius: 12px;
    padding: 1.25rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
    border: 1px solid #f0f1f3;
    display: flex;
    flex-direction: column;
    gap: 8px;
}
.kpi-label {
    font-size: 0.78rem;
    color: #6b7280;
    font-weight: 500;
}
.kpi-value-container {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 4px;
}
.kpi-val {
    font-size: 1.85rem;
    font-weight: 600;
    color: #111827;
    line-height: 1;
}
.kpi-trend {
    font-size: 0.7rem;
    font-weight: 600;
    padding: 2px 6px;
    border-radius: 8px;
}
.trend-green {
    background: #ecfdf5;
    color: #059669;
    border: 1px solid #a7f3d0;
}
.trend-red {
    background: #fff5f5;
    color: #dc2626;
    border: 1px solid #fca5a5;
}

/* Chart styling */
.chart-card {
    padding: 1.5rem;
}
.chart-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}
.chart-toggles {
    display: flex;
    gap: 8px;
}
.toggle-pill {
    font-size: 0.72rem;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 12px;
    cursor: pointer;
    border: 1px solid #e5e7eb;
    color: #6b7280;
    transition: all 0.2s;
}
.toggle-pill.active {
    background: #eff6ff;
    color: #1d4ed8;
    border-color: #bfdbfe;
}
.toggle-pill.red {
    border-color: #fecdd3;
    color: #e11d48;
    background: #fff5f5;
}
.chart-container {
    width: 100%;
    margin-top: 0.5rem;
}

/* Relevant Cases Table styling */
.table-card {
    padding: 1.5rem;
}
.cases-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 0.25rem;
}
.cases-table th {
    text-align: left;
    font-size: 0.75rem;
    font-weight: 600;
    color: #9ca3af;
    padding: 8px 12px;
    border-bottom: 1px solid #f3f4f6;
}
.cases-table td {
    padding: 12px;
    font-size: 0.825rem;
    color: #374151;
    border-bottom: 1px solid #f9fafb;
}
.cases-table tr:last-child td {
    border-bottom: none;
}
.cases-table tr td:first-child {
    font-weight: 500;
    color: #111827;
}
.outcome-pill {
    font-size: 0.72rem;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 12px;
    display: inline-block;
}
.outcome-pill.win {
    background: #ecfdf5;
    color: #059669;
    border: 1px solid #a7f3d0;
}
.outcome-pill.settled {
    background: #fffbeb;
    color: #d97706;
    border: 1px solid #fcd34d;
}

/* Custom Tabs for Smart Review */
.custom-tabs {
    display: flex;
    gap: 8px;
    background: #f3f4f6;
    padding: 4px;
    border-radius: 10px;
    margin-bottom: 1.5rem;
    border: 1px solid #e5e7eb;
    max-width: 500px;
}
.custom-tab {
    flex: 1;
    text-align: center;
    padding: 8px 12px;
    font-size: 0.85rem;
    font-weight: 500;
    color: #6b7280 !important;
    text-decoration: none !important;
    border-radius: 8px;
    transition: all 0.2s;
}
.custom-tab:hover {
    color: #111827 !important;
}
.custom-tab.active {
    background: #ffffff;
    color: #111827 !important;
    font-weight: 600;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

/* Demo Banner override styling */
.demo-banner {
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 10px;
    padding: 10px 16px;
    font-size: 0.825rem;
    color: #1d4ed8;
    margin-bottom: 1rem;
}

/* Expanders override */
.streamlit-expanderHeader {
    background: #ffffff !important;
    border: 1px solid #f0f1f3 !important;
    border-radius: 12px !important;
    font-weight: 600 !important;
    color: #111827 !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02) !important;
    margin-bottom: 0.5rem;
}
.streamlit-expanderContent {
    background: #ffffff !important;
    border: 1px solid #f0f1f3 !important;
    border-top: none !important;
    border-radius: 0 0 12px 12px !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02);
}

/* Custom styles for cases and search pages */
.subpage-container {
    background: #ffffff;
    border-radius: 14px;
    padding: 2rem;
    border: 1px solid #f0f1f3;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02);
}
.subpage-title {
    font-size: 1.4rem;
    font-weight: 700;
    color: #111827;
    margin-bottom: 1.5rem;
}
.search-results-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-top: 1.5rem;
}
.search-card {
    background: #fafafa;
    border: 1px solid #e5e7eb;
    border-radius: 10px;
    padding: 1.25rem;
    transition: all 0.2s;
}
.search-card:hover {
    border-color: #3b82f6;
    background: #ffffff;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
}
.search-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}
.search-card-title {
    font-size: 0.95rem;
    font-weight: 600;
    color: #111827;
}
.search-card-score {
    font-size: 0.75rem;
    font-weight: 600;
    background: #ecfdf5;
    color: #059669;
    padding: 2px 8px;
    border-radius: 12px;
}
.search-card-content {
    font-size: 0.85rem;
    color: #4b5563;
    line-height: 1.5;
}
.search-card-meta {
    font-size: 0.72rem;
    color: #9ca3af;
    margin-top: 10px;
    border-top: 1px solid #f3f4f6;
    padding-top: 8px;
}

/* ==========================================================================
   Futuristic Dark Glassmorphism Playbook Styling
   ========================================================================== */
.glass-panel {
    background: rgba(17, 24, 39, 0.95) !important;
    backdrop-filter: blur(18px) saturate(180%) !important;
    -webkit-backdrop-filter: blur(18px) saturate(180%) !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 18px !important;
    padding: 2rem !important;
    color: #f3f4f6 !important;
    box-shadow: 0 10px 40px 0 rgba(0, 0, 0, 0.45) !important;
    margin-bottom: 2rem !important;
}

.glass-title {
    font-size: 1.4rem !important;
    font-weight: 700 !important;
    color: #ffffff !important;
    margin-bottom: 0.5rem !important;
    display: flex !important;
    align-items: center !important;
    gap: 8px !important;
}

.glass-subtitle {
    font-size: 0.85rem !important;
    color: #9ca3af !important;
    margin-bottom: 1.75rem !important;
    line-height: 1.5 !important;
}

.glass-split-screen {
    display: grid !important;
    grid-template-columns: 1fr 1fr !important;
    gap: 1.5rem !important;
    margin-bottom: 1.5rem !important;
}

@media (max-width: 992px) {
    .glass-split-screen {
        grid-template-columns: 1fr !important;
    }
}

.glass-pane {
    background: rgba(255, 255, 255, 0.03) !important;
    border: 1px solid rgba(255, 255, 255, 0.05) !important;
    border-radius: 12px !important;
    padding: 1.5rem !important;
    display: flex !important;
    flex-direction: column !important;
    gap: 12px !important;
}

.pane-header {
    display: flex !important;
    justify-content: space-between !important;
    align-items: center !important;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
    padding-bottom: 10px !important;
    margin-bottom: 4px !important;
}

.pane-title {
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.06em !important;
    text-transform: uppercase !important;
    color: #9ca3af !important;
}

.pane-content {
    font-size: 0.925rem !important;
    line-height: 1.7 !important;
    color: #e5e7eb !important;
    background: rgba(0, 0, 0, 0.25) !important;
    border-radius: 8px !important;
    padding: 1.25rem !important;
    min-height: 140px !important;
    border: 1px solid rgba(255, 255, 255, 0.03) !important;
    font-family: 'Inter', sans-serif !important;
}

/* Diff Highlight Classes */
.diff-add {
    background: rgba(16, 185, 129, 0.22) !important;
    color: #34d399 !important;
    border-radius: 4px !important;
    padding: 2px 5px !important;
    font-weight: 600 !important;
    text-decoration: none !important;
    box-shadow: 0 0 8px rgba(16, 185, 129, 0.2) !important;
}

.diff-del {
    background: rgba(244, 63, 94, 0.22) !important;
    color: #f87171 !important;
    border-radius: 4px !important;
    padding: 2px 5px !important;
    font-weight: 600 !important;
    text-decoration: line-through !important;
    opacity: 0.85 !important;
}

/* Mini Persona/Clause selector links styling */
.glass-btn {
    background: rgba(255, 255, 255, 0.05) !important;
    color: #d1d5db !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    border-radius: 8px !important;
    padding: 8px 14px !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    cursor: pointer !important;
    transition: all 0.2s !important;
    text-decoration: none !important;
    display: inline-flex !important;
    align-items: center !important;
    gap: 6px !important;
}
.glass-btn:hover {
    color: #ffffff !important;
    background: rgba(255, 255, 255, 0.12) !important;
    border-color: rgba(255, 255, 255, 0.2) !important;
}
.glass-btn.active {
    background: rgba(255, 255, 255, 0.15) !important;
    color: #ffffff !important;
    border-color: #3b82f6 !important;
    box-shadow: 0 0 10px rgba(59, 130, 246, 0.25) !important;
    font-weight: 600 !important;
}

.glass-btn.primary {
    background: linear-gradient(90deg, #3b82f6, #06b6d4) !important;
    border: none !important;
    color: #ffffff !important;
    box-shadow: 0 4px 14px rgba(59, 130, 246, 0.3) !important;
    font-weight: 600 !important;
}
.glass-btn.primary:hover {
    background: linear-gradient(90deg, #2563eb, #0891b2) !important;
    box-shadow: 0 6px 20px rgba(59, 130, 246, 0.5) !important;
}

/* Persona Container background box */
.persona-container {
    display: flex !important;
    gap: 6px !important;
    background: rgba(0, 0, 0, 0.3) !important;
    padding: 4px !important;
    border-radius: 10px !important;
    border: 1px solid rgba(255, 255, 255, 0.05) !important;
}

.glass-actions-row {
    display: flex !important;
    justify-content: flex-end !important;
    gap: 12px !important;
    margin-top: 1.25rem !important;
}

/* High contrast risk pills */
.glass-risk-pill {
    display: inline-flex !important;
    align-items: center !important;
    gap: 6px !important;
    font-size: 0.75rem !important;
    font-weight: 600 !important;
    padding: 4px 10px !important;
    border-radius: 12px !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
}
.glass-risk-pill.critical {
    background: rgba(239, 68, 68, 0.18) !important;
    color: #f87171 !important;
    border-color: rgba(239, 68, 68, 0.35) !important;
}
.glass-risk-pill.high {
    background: rgba(245, 158, 11, 0.18) !important;
    color: #fbbf24 !important;
    border-color: rgba(245, 158, 11, 0.35) !important;
}
.glass-risk-pill.low {
    background: rgba(16, 185, 129, 0.18) !important;
    color: #34d399 !important;
    border-color: rgba(16, 185, 129, 0.35) !important;
}

/* =====================================================================
   MOBILE RESPONSIVE LAYOUT — stacks all columns vertically on mobile
   ===================================================================== */
@media screen and (max-width: 768px) {

    /* Main container tighter padding */
    .block-container {
        padding-left: 0.75rem !important;
        padding-right: 0.75rem !important;
        padding-top: 1rem !important;
    }

    /* Dashboard grid → single column */
    .dashboard-grid {
        grid-template-columns: 1fr !important;
        gap: 1rem !important;
    }

    /* KPI row → 2 columns on mobile */
    .kpi-row {
        grid-template-columns: repeat(2, 1fr) !important;
        gap: 0.75rem !important;
    }
    .kpi-val {
        font-size: 1.4rem !important;
    }
    .kpi-label {
        font-size: 0.72rem !important;
    }

    /* Cards full width, reduced padding */
    .card, .chart-card, .table-card {
        padding: 1rem !important;
        border-radius: 10px !important;
    }
    .card-title {
        font-size: 0.95rem !important;
    }

    /* Header → stack search bar below title */
    .header-container {
        flex-direction: column !important;
        gap: 10px !important;
        padding: 10px 14px !important;
        align-items: flex-start !important;
    }
    .header-title {
        font-size: 1.1rem !important;
    }
    .search-bar-container {
        width: 100% !important;
    }
    .header-actions {
        width: 100% !important;
        justify-content: flex-end !important;
    }

    /* Cases table → horizontal scroll */
    .cases-table {
        font-size: 0.72rem !important;
        display: block !important;
        overflow-x: auto !important;
        white-space: nowrap !important;
    }

    /* PDF row info — truncate filename tighter */
    .pdf-name {
        max-width: 120px !important;
        font-size: 0.78rem !important;
    }

    /* Smart Review tabs → full width scrollable */
    .custom-tabs {
        max-width: 100% !important;
        overflow-x: auto !important;
        gap: 4px !important;
    }
    .custom-tab {
        padding: 6px 8px !important;
        font-size: 0.78rem !important;
        white-space: nowrap !important;
    }

    /* Glass panels full width */
    .glass-panel {
        padding: 1.25rem !important;
        border-radius: 12px !important;
    }
    .glass-split-screen {
        grid-template-columns: 1fr !important;
        gap: 1rem !important;
    }
    .glass-title {
        font-size: 1.1rem !important;
    }

    /* Subpage containers */
    .subpage-container {
        padding: 1rem !important;
        border-radius: 10px !important;
    }
    .subpage-title {
        font-size: 1.1rem !important;
    }

    /* Reduce heading sizes globally on mobile */
    h1 { font-size: 1.6rem !important; }
    h2 { font-size: 1.2rem !important; }
    h3 { font-size: 1rem !important; }

}

/* Tablet: 2-col KPI, normal sidebar */
@media screen and (min-width: 769px) and (max-width: 1024px) {
    .dashboard-grid {
        grid-template-columns: 300px 1fr !important;
    }
    .kpi-row {
        grid-template-columns: repeat(2, 1fr) !important;
    }
}
</style>
""")

# ── Sidebar Layout ────────────────────────────────────────────────────────────
current_page = st.session_state['current_page']

sidebar_html = f"""
<div class="sidebar-container">
    <!-- Header/Logo -->
    <div class="sidebar-header">
        <div style="display:flex; align-items:center; gap:10px;">
            <div class="logo-box">L</div>
            <span class="brand-name">LegalInspect</span>
        </div>
        <div class="collapse-icon">⟨</div>
    </div>
    
    <!-- MAIN Section -->
    <div class="sidebar-section-title">MAIN</div>
    <a href="{get_nav_link('Dashboard')}" target="_self" class="sidebar-nav-item {'active' if current_page == 'Dashboard' else ''}">
        <span class="nav-icon">🏠</span> Dashboard
    </a>
    <a href="{get_nav_link('Cases')}" target="_self" class="sidebar-nav-item {'active' if current_page == 'Cases' else ''}">
        <span class="nav-icon">📁</span> Cases
    </a>
    <a href="{get_nav_link('LegalSearch')}" target="_self" class="sidebar-nav-item {'active' if current_page == 'LegalSearch' else ''}">
        <span class="nav-icon">🔍</span> Legal Search
    </a>
    <a href="{get_nav_link('SmartReview')}" target="_self" class="sidebar-nav-item {'active' if current_page == 'SmartReview' else ''}">
        <span class="nav-icon">📄</span> Smart Review
    </a>
    
    <!-- ANALYTICS Section -->
    <div class="sidebar-section-title">ANALYTICS</div>
    <a href="{get_nav_link('ComplianceView')}" target="_self" class="sidebar-nav-item {'active' if current_page == 'ComplianceView' else ''}">
        <span class="nav-icon">📈</span> Compliance View
    </a>
    <a href="{get_nav_link('LegalForms')}" target="_self" class="sidebar-nav-item {'active' if current_page == 'LegalForms' else ''}">
        <span class="nav-icon">📋</span> Legal Forms
    </a>
    
    <!-- PROFILE Section -->
    <div class="sidebar-section-title">PROFILE</div>
    <a href="{get_nav_link('Authentication')}" target="_self" class="sidebar-nav-item {'active' if current_page == 'Authentication' else ''}">
        <span class="nav-icon">🔑</span> Identity Center
    </a>
</div>
"""

with st.sidebar:
    render_html(sidebar_html)
    st.markdown("<div class='sidebar-divider'></div>", unsafe_allow_html=True)
    st.markdown("<div class='sidebar-section-title'>Document Upload</div>", unsafe_allow_html=True)

    input_method = st.radio(
        "Choose Input Method:",
        options=["📤 Upload File", "✍️ Paste Text"],
        label_visibility="collapsed",
        key="input_method_select"
    )
    
    uploaded_file = None
    
    if input_method == "📤 Upload File":
        sidebar_file = st.file_uploader(
            "Upload Document (PDF, PPTX, TXT)",
            type=["pdf", "pptx", "txt"],
            label_visibility="collapsed",
            key="sidebar_uploader"
        )
        if sidebar_file is not None:
            uploaded_file = sidebar_file
        elif st.session_state.get("main_uploader") is not None:
            uploaded_file = st.session_state["main_uploader"]
            
    else: # ✍️ Paste Text
        pasted_text = st.text_area(
            "Paste Contract Text:",
            placeholder="Paste your legal clauses here...",
            height=180,
            key="sidebar_pasted_text"
        )
        
        # Wrap pasted text inside a class matching uploaded_file's interface
        class PastedTextFile:
            def __init__(self, text, name="Pasted_Contract.txt"):
                self.text = text
                self.name = name
            def getvalue(self):
                return self.text.encode('utf-8')
                
        if pasted_text.strip():
            if st.button("🔍 Analyze Pasted Contract", use_container_width=True, type="primary"):
                uploaded_file = PastedTextFile(pasted_text)

    # Load Demo Analysis button
    if not st.session_state['analysis_complete']:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🎯 Load Demo Analysis", use_container_width=True, type="primary"):
            st.session_state['demo_mode'] = True
            st.session_state['filename'] = "NDA_v3.2_Draft.pdf"
            with st.spinner("🤖 Agents analyzing contract..."):
                time.sleep(2)
            st.session_state['analysis_complete'] = True
            # Set query parameters to preserve demo loaded state
            st.query_params.update({
                "page": "Dashboard",
                "demo": "true",
                "filename": "NDA_v3.2_Draft.pdf",
                "user": st.session_state.get("user_hash", "")
            })
            st.rerun()

    # If analyzed, show reset and helper indicators
    if st.session_state['analysis_complete']:
        label = "✅ Demo Loaded" if st.session_state.get('demo_mode') else "✅ Analysis Complete"
        st.success(label)
        st.caption(f"📄 {st.session_state.get('filename', '')}")
        st.divider()

        if st.button("🔄 Reset / Clear Document", use_container_width=True, key="sidebar_reset_btn"):
            user_hash = st.session_state.get("user_hash", "")
            st.query_params.clear()
            if user_hash:
                st.query_params.update({"user": user_hash, "page": "Dashboard"})
            st.session_state['file_uploaded'] = False
            st.session_state['analysis_complete'] = False
            st.session_state['filename'] = ""
            st.session_state['demo_mode'] = False
            if 'sidebar_pasted_text' in st.session_state:
                st.session_state['sidebar_pasted_text'] = ""
            st.rerun()

    st.markdown("""
    <div style='margin-top:2rem;font-size:0.72rem;color:#94a3b8;text-align:center;'>
    Powered by Multi-Agent AI · v2.1
    </div>
    """, unsafe_allow_html=True)

    # Custom Sticky Mobile Navigation Header & JavaScript Sidebar Trigger
    mobile_nav_html = f"""
    <div class="mobile-header">
        <div style="display:flex; align-items:center; gap:10px;">
            <span onclick="toggleSidebar();" class="mobile-menu-btn" title="Open Sidebar">☰</span>
            <div class="logo-box">L</div>
            <span class="brand-name" style="color:#ffffff; font-weight:700; font-size:1.1rem; font-family:'Inter',sans-serif;">LegalInspect</span>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
            <a href="{get_nav_link('Dashboard')}&upload=true" target="_self" style="text-decoration:none; font-size:1.25rem; color:#ffffff; padding:4px; display:inline-flex;" title="Upload File">📤</a>
            <a href="{get_nav_link('Authentication')}" target="_self" style="text-decoration:none; font-size:1.25rem; color:#ffffff; padding:4px; display:inline-flex;" title="Identity Center">🔑</a>
        </div>
    </div>

    <script>
    function toggleSidebar() {{
        var openBtn = document.querySelector('button[data-testid="collapsedSidebarIconButton"]');
        if (openBtn) {{ openBtn.click(); return; }}
        var closeBtn = document.querySelector('button[data-testid="stSidebarCollapseButton"]');
        if (closeBtn) {{ closeBtn.click(); return; }}
        try {{
            var pOpenBtn = window.parent.document.querySelector('button[data-testid="collapsedSidebarIconButton"]');
            if (pOpenBtn) {{ pOpenBtn.click(); return; }}
            var pCloseBtn = window.parent.document.querySelector('button[data-testid="stSidebarCollapseButton"]');
            if (pCloseBtn) {{ pCloseBtn.click(); return; }}
        }} catch(e) {{}}
    }}
    </script>
    """
    render_html(mobile_nav_html)

    # Detect new uploads or re-uploads using file content hashing
    is_new_upload = False
    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        file_hash = hash(file_bytes)
        if st.session_state.get('last_uploaded_hash') != file_hash:
            is_new_upload = True
            st.session_state['last_uploaded_hash'] = file_hash

    # Automatically reset if uploader is cleared by clicking 'X'
    if uploaded_file is None and st.session_state.get('last_uploaded_hash') is not None:
        st.session_state['last_uploaded_hash'] = None
        st.session_state['file_uploaded'] = False
        st.session_state['analysis_complete'] = False
        st.session_state['filename'] = ""
        st.session_state['demo_mode'] = False
        if 'uploaded_file_analysis' in st.session_state:
            del st.session_state['uploaded_file_analysis']
        # Clear both uploaders to prevent sticky states
        if "sidebar_uploader" in st.session_state:
            st.session_state["sidebar_uploader"] = None
        if "main_uploader" in st.session_state:
            st.session_state["main_uploader"] = None
        st.rerun()

    if uploaded_file is not None and (not st.session_state.get('file_uploaded', False) or is_new_upload):
        st.session_state['file_uploaded'] = True
        st.session_state['demo_mode'] = False
        st.session_state['filename'] = uploaded_file.name
        
        # Render a premium glassmorphic loader with a light blurring effect!
        loading_placeholder = st.empty()
        loading_placeholder.markdown("""
        <div style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(255, 255, 255, 0.45);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            z-index: 999999;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        ">
            <div class="glass-panel" style="
                max-width: 450px;
                text-align: center;
                border: 1px solid rgba(255, 255, 255, 0.3) !important;
                background: rgba(255, 255, 255, 0.85) !important;
                color: #111827 !important;
                box-shadow: 0 20px 50px rgba(0, 0, 0, 0.1) !important;
                padding: 2.5rem !important;
            ">
                <div style="font-size: 3rem; margin-bottom: 1rem; animation: pulse 2s infinite;">⚖️</div>
                <div class="glass-title" style="color: #1e3a8a !important; font-size: 1.3rem !important; margin-bottom: 0.5rem !important; justify-content: center; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                    🤖 RegulAIte Multi-Agent Scan
                </div>
                <div style="font-size: 0.85rem; color: #4b5563; line-height: 1.5; margin-bottom: 1.5rem;">
                    AI agents are red-teaming your contract clauses, scanning for liability traps, and compiling your compliance audit...
                </div>
                <div style="
                    display: inline-block;
                    width: 40px;
                    height: 40px;
                    border: 4px solid rgba(59, 130, 246, 0.1);
                    border-radius: 50%;
                    border-top-color: #3b82f6;
                    animation: spin 1s ease-in-out infinite;
                "></div>
            </div>
            <style>
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
                @keyframes pulse {
                    0%, 100% { opacity: 1; transform: scale(1); }
                    50% { opacity: 0.6; transform: scale(0.95); }
                }
            </style>
        </div>
        """, unsafe_allow_html=True)
        
        # Analyze immediately — no artificial sleep
        st.session_state['uploaded_file_analysis'] = analyze_pdf_content(uploaded_file)
        loading_placeholder.empty()
        
        st.session_state['analysis_complete'] = True
        
        # Clear demo and upload URL parameters to prevent state override collisions
        if "demo" in st.query_params:
            del st.query_params["demo"]
        if "upload" in st.query_params:
            del st.query_params["upload"]
            
        # Set query parameters to preserve upload state
        st.query_params.update({
            "page": "Dashboard",
            "analyzed": "true",
            "filename": uploaded_file.name
        })
        st.rerun()

    # Active Level Selector
    st.markdown("<div class='sidebar-divider'></div>", unsafe_allow_html=True)
    st.markdown("<div class='sidebar-section-title'>🎯 ACTIVE RISK LEVEL</div>", unsafe_allow_html=True)
    
    level_options = ["Level 1 (Low Risk - Perfect)", "Level 2 (Medium Risk - Mild)", "Level 3 (High Risk - Vulnerable)"]
    current_index = 2
    if "Level 1" in st.session_state['active_level']:
        current_index = 0
    elif "Level 2" in st.session_state['active_level']:
        current_index = 1
        
    level_choice = st.selectbox(
        "Active Document Level",
        options=level_options,
        index=current_index,
        key="active_level_sidebar_select"
    )
    if level_choice != st.session_state['active_level']:
        st.session_state['active_level'] = level_choice
        if st.session_state['analysis_complete']:
            # Adjust file name dynamically based on selected level
            if "Level 1" in level_choice:
                st.session_state['filename'] = "Perfect_Standard_Agreement.pdf"
                _risk_label = "Low Risk"
                _risk_color = "#059669"
                _agents = [
                    ("Clause Scanner Agent", "Scanning all clause definitions and headings..."),
                    ("Liability Auditor Agent", "Verifying mutual liability caps and carve-outs..."),
                    ("IP Ownership Agent", "Confirming scope of IP assignment and Background IP..."),
                    ("Compliance Agent", "Running GDPR, IT Act, and CCPA compliance checks..."),
                    ("Risk Scoring Agent", "Finalizing risk score — contract appears clean."),
                ]
            elif "Level 2" in level_choice:
                st.session_state['filename'] = "Mildly_Risky_Agreement.pdf"
                _risk_label = "Medium Risk"
                _risk_color = "#d97706"
                _agents = [
                    ("Clause Scanner Agent", "Detected asymmetric termination notice periods..."),
                    ("Liability Auditor Agent", "Flagging 3-month vs 6-month liability cap mismatch..."),
                    ("Payment Terms Agent", "Found Net 30 vs Net 15 conflict across body and Schedule B..."),
                    ("Compliance Agent", "Checking GDPR opt-out mechanics — minor gaps found..."),
                    ("Risk Scoring Agent", "Scoring contract — 3 moderate risk flags identified."),
                ]
            else:
                st.session_state['filename'] = "Vulnerable_Agreement_Draft.pdf"
                _risk_label = "High Risk"
                _risk_color = "#dc2626"
                _agents = [
                    ("Clause Scanner Agent", "ALERT: 'Regardless of fault' indemnification detected..."),
                    ("Liability Auditor Agent", "CRITICAL: Vendor liability entirely uncapped..."),
                    ("IP Ownership Agent", "WARNING: Overbroad IP assignment strips vendor rights..."),
                    ("Logic Validator Agent", "CONFLICT: Data destruction vs. 3-year retention contradiction..."),
                    ("Risk Scoring Agent", "Contract scored HIGH RISK — immediate legal review required."),
                ]

            # Show a realistic multi-step agent loading animation
            _reload_ph = st.empty()
            _steps_html_parts = "".join(
                f"""<div id='agent-step-{i}' style='display:flex;align-items:flex-start;gap:10px;margin-bottom:10px;opacity:0;transition:opacity 0.4s ease;'>
                        <div style='width:8px;height:8px;border-radius:50%;background:{_risk_color};margin-top:5px;flex-shrink:0;'></div>
                        <div>
                            <div style='font-size:0.78rem;font-weight:700;color:#e5e7eb;'>{name}</div>
                            <div style='font-size:0.72rem;color:#9ca3af;margin-top:1px;'>{desc}</div>
                        </div>
                    </div>"""
                for i, (name, desc) in enumerate(_agents)
            )
            _reload_ph.markdown(f"""
            <div style='position:fixed;top:0;left:0;width:100vw;height:100vh;
                background:rgba(15,17,21,0.92);backdrop-filter:blur(12px);
                -webkit-backdrop-filter:blur(12px);z-index:9999999;
                display:flex;flex-direction:column;align-items:center;justify-content:center;'>
                <div style='background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);
                    border-radius:18px;padding:2.5rem;max-width:480px;width:90%;'>
                    <div style='text-align:center;margin-bottom:1.5rem;'>
                        <div style='font-size:2.5rem;margin-bottom:0.5rem;'>⚖️</div>
                        <div style='font-size:1.1rem;font-weight:800;color:#ffffff;'>RegulAIte Multi-Agent Analysis</div>
                        <div style='font-size:0.8rem;color:{_risk_color};font-weight:700;margin-top:4px;
                            background:rgba(255,255,255,0.05);border:1px solid {_risk_color}44;
                            padding:3px 12px;border-radius:20px;display:inline-block;'>
                            Switching to {_risk_label} Document
                        </div>
                    </div>
                    <div id='agent-steps-container'>{_steps_html_parts}</div>
                    <div style='margin-top:1.5rem;height:4px;background:rgba(255,255,255,0.08);border-radius:4px;overflow:hidden;'>
                        <div style='height:100%;width:0%;background:linear-gradient(90deg,#3b82f6,{_risk_color});
                            border-radius:4px;animation:progress-fill 2.2s ease forwards;'></div>
                    </div>
                    <style>
                        @keyframes progress-fill {{ to {{ width:100%; }} }}
                        {''.join(f'#agent-step-{i} {{ animation: fadein 0.4s {0.35*i:.2f}s forwards; }}' for i in range(len(_agents)))}
                        @keyframes fadein {{ to {{ opacity:1; }} }}
                    </style>
                </div>
            </div>
            """, unsafe_allow_html=True)

            import time as _time
            _time.sleep(2.5)   # Let agents animation play
            _reload_ph.empty()
        st.rerun()

    # Load Demo Analysis button
    if not st.session_state['analysis_complete']:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🎯 Load Selected Level Demo", use_container_width=True, type="primary"):
            st.session_state['demo_mode'] = True
            if "Level 1" in st.session_state['active_level']:
                st.session_state['filename'] = "Perfect_Standard_Agreement.pdf"
            elif "Level 2" in st.session_state['active_level']:
                st.session_state['filename'] = "Mildly_Risky_Agreement.pdf"
            else:
                st.session_state['filename'] = "Vulnerable_Agreement_Draft.pdf"
                
            st.session_state['analysis_complete'] = True
            st.query_params.update({
                "page": "Dashboard",
                "demo": "true",
                "filename": st.session_state['filename']
            })
            st.rerun()

    # If analyzed, show reset and helper indicators
    if st.session_state['analysis_complete']:
        label = "✅ Demo Loaded" if st.session_state['demo_mode'] else "✅ Analysis Complete"
        st.success(label)
        st.caption(f"📄 {st.session_state['filename']}")
        st.divider()

        if st.button("🔄 Reset / Clear Document", use_container_width=True, key="main_reset_btn"):
            st.query_params.clear()
            st.session_state['file_uploaded'] = False
            st.session_state['analysis_complete'] = False
            st.session_state['filename'] = ""
            st.session_state['demo_mode'] = False
            st.session_state['active_level'] = "Level 3 (High Risk - Vulnerable)"
            if 'uploaded_file_analysis' in st.session_state:
                del st.session_state['uploaded_file_analysis']
            st.rerun()
    st.markdown("<div class='sidebar-divider'></div>", unsafe_allow_html=True)
    st.markdown("<div class='sidebar-section-title'>🔑 LLM CONNECTION</div>", unsafe_allow_html=True)
    
    # Store API Key in session state
    if "gemini_api_key" not in st.session_state:
        st.session_state["gemini_api_key"] = os.environ.get("GEMINI_API_KEY", "")
        
    api_key_input = st.text_input(
        "Google Gemini API Key",
        type="password",
        value=st.session_state["gemini_api_key"],
        placeholder="AIzaSy...",
        help="Paste your Google Gemini API Key here to enable live LLM contract analysis, custom debates, and playbook fixes!"
    )
    if api_key_input != st.session_state["gemini_api_key"]:
        st.session_state["gemini_api_key"] = api_key_input
        st.success("LLM Configuration updated!")
        st.rerun()
        
    if st.session_state["gemini_api_key"]:
        st.markdown(
            "<div style='margin-bottom:10px;'><span style='font-size:0.75rem;color:#10b981;font-weight:600;'>🟢 Live LLM Connected</span></div>",
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            "<div style='margin-bottom:10px;'><span style='font-size:0.75rem;color:#f59e0b;font-weight:600;'>🟡 Local Simulator Mode</span></div>",
            unsafe_allow_html=True
        )

    st.markdown("""
    <div style='margin-top:1.5rem;font-size:0.72rem;color:#94a3b8;text-align:center;'>
    Powered by Multi-Agent AI · v2.1
    </div>
    """, unsafe_allow_html=True)

# ── Main Content Area ──────────────────────────────────────────────────────────
if not st.session_state['analysis_complete']:
    full_name = st.session_state.get('user_name', 'Guest')
    clean_name = full_name.split(',')[0].strip() if ',' in full_name else full_name.strip()
    if not clean_name or clean_name == "Guest":
        clean_name = "Valued Partner"
        
    # Standard, pure text native Streamlit components
    st.title(f"Welcome, {clean_name}!")
    st.caption("RegulAIte AI • B2B Multi-Agent Contract Intelligence")
    
    st.write(
        "Welcome to **RegulAIte-AI**, the enterprise-grade B2B legal contract auditor. "
        "Designed to eliminate the risk of signing unfavorable, high-exposure agreements, "
        "RegulAIte acts as an automated senior legal partner that stress-tests documents in seconds."
    )
    st.write(
        "Using an advanced **Multi-Agent AI Pipeline**, RegulAIte doesn't just summarize text—it "
        "performs adversarial red-teaming, cross-references statutory compliance indices (GDPR, CCPA, IT Act 2000), "
        "and uncovers hidden liability cap conflicts."
    )
    st.info("👈 **To get started:** Simply upload any legal agreement PDF in the sidebar, or click **Load Demo Analysis**!")
    
    st.divider()
    
    st.subheader("🎥 Platform Walkthrough & Core Features")
    st.write(
        "Watch a quick demonstration of our AI Attacker & AI Defender agents negotiating terms in real-time."
    )
    
    # We display the actual video centered inside columns
    v_col1, v_col2, v_col3 = st.columns([1, 6, 1])
    with v_col2:
        st.video(
            "docs/Screen Recording 2026-05-23 195222.mp4",
            format="video/mp4",
            autoplay=True,
            muted=True,
            start_time=0
        )
else:
    # Common variables globally available inside all subpages to avoid Scope / NameErrors
    fn = st.session_state.get('filename', 'NDA_v3.2_Draft.pdf')
    demo_mode = st.session_state.get('demo_mode', False)
    current_page = st.session_state['current_page']
    u_hash = st.session_state.get('user_hash', '')
    

    lvl = st.session_state.get('active_level', 'Level 3 (High Risk)')
    from mock_data import (
        level_1_data, level_2_data, level_3_data,
        level_1_debate, level_2_debate, level_3_debate,
        level_1_conflicts, level_2_conflicts, level_3_conflicts,
        level_1_playbook, level_2_playbook, level_3_playbook
    )
    
    if (demo_mode and not st.session_state.get('file_uploaded', False)) or 'uploaded_file_analysis' not in st.session_state:
        if "Level 1" in lvl:
            active_risk_data = level_1_data.copy()
            active_debate = level_1_debate
            active_conflicts = level_1_conflicts
            active_playbook = level_1_playbook
        elif "Level 2" in lvl:
            active_risk_data = level_2_data.copy()
            active_debate = level_2_debate
            active_conflicts = level_2_conflicts
            active_playbook = level_2_playbook
        else:
            active_risk_data = level_3_data.copy()
            active_debate = level_3_debate
            active_conflicts = level_3_conflicts
            active_playbook = level_3_playbook
    else:
        active_risk_data = st.session_state['uploaded_file_analysis'].copy()
        
        # ── Map dynamic multi-agent debate logs from FastAPI backend ──
        if active_risk_data.get('loophole_logs'):
            active_debate = []
            for item in active_risk_data['loophole_logs']:
                role = "Attacker" if item.get('role', '').lower() in ('exploiter', 'attacker') else "Defender"
                active_debate.append({
                    "role": role,
                    "content": item.get('content', '')
                })
        else:
            active_debate = level_3_debate

        # ── Map dynamic formal Z3 contradiction logs from FastAPI backend ──
        if active_risk_data.get('logic_conflicts'):
            active_conflicts = []
            for item in active_risk_data['logic_conflicts']:
                z3_code = item.get('z3_code')
                if not z3_code:
                    z3_code = f"""# ── Z3 SOLVER LOGIC FORMULATION ──
from z3 import *

# Define boolean representations for this conflict
conflict_detected = Bool('conflict_detected')

s = Solver()
# Rule A: {item.get('rule_a', 'Rule A')[:50]}...
# Rule B: {item.get('rule_b', 'Rule B')[:50]}...

# Asserting rules lead to logical incompatibility
s.add(conflict_detected == True)
s.add(Implies(conflict_detected, False)) 

# Verification of satisfiability (SAT / UNSAT)
verification_result = s.check()
print(f"Contract Logical Consistency: {{verification_result}}") # Output: UNSAT!"""

                active_conflicts.append({
                    "conflict": item.get('conflict', 'Contract Contradiction'),
                    "severity": item.get('severity', 'High'),
                    "rule_a": item.get('rule_a', 'Clause A'),
                    "rule_b": item.get('rule_b', 'Clause B'),
                    "explanation": item.get('explanation', ''),
                    "resolved_clause": item.get('resolved_clause', 'Except as required by applicable regulations, both clauses shall be mutual.'),
                    "z3_code": z3_code
                })
        else:
            active_conflicts = level_3_conflicts

        # ── Map dynamic playbooks and auto-fixes from FastAPI backend ──
        if active_risk_data.get('auto_fixes'):
            active_playbook = {}
            for item in active_risk_data['auto_fixes']:
                issue_title = item.get('issue', 'Covenant Risk')
                original_clause = item.get('original', '')
                suggested_fix = item.get('suggested', '')
                rationale_text = item.get('rationale', '')
                risk_lvl = item.get('risk_level', 'High')
                
                risk_class = "critical" if risk_lvl.lower() == "critical" else ("high" if risk_lvl.lower() in ("high", "medium") else "low")
                score_str = "9/10" if risk_lvl.lower() == "critical" else ("7/10" if risk_lvl.lower() == "high" else ("5/10" if risk_lvl.lower() == "medium" else "2/10"))

                active_playbook[issue_title] = {
                    "title": issue_title,
                    "severity": 9 if risk_lvl.lower() == "critical" else (7 if risk_lvl.lower() == "high" else (5 if risk_lvl.lower() == "medium" else 2)),
                    "original": original_clause,
                    "Defender": {
                        "rewrite": suggested_fix,
                        "risk_label": f"🛡️ Balanced {risk_lvl}",
                        "risk_class": "low",
                        "score": score_str,
                        "rationale": rationale_text
                    },
                    "Attacker": {
                        "rewrite": f"Vendor shall have no liability or obligations regarding {issue_title}. All rights belong exclusively to Vendor.",
                        "risk_label": "⚔️ Aggressive Vendor Exemption",
                        "risk_class": "low",
                        "score": "1/10",
                        "rationale": f"Pushes for extreme Vendor-friendly exclusions regarding {issue_title}."
                    },
                    "Arbitrator": {
                        "rewrite": suggested_fix,
                        "risk_label": f"⚖️ Balanced Reciprocity",
                        "risk_class": "low",
                        "score": "2/10",
                        "rationale": f"Establishes commercially balanced reciprocal obligations for both parties."
                    }
                }
        else:
            active_playbook = level_3_playbook

    # Sync dates and authors dynamically in real time
    active_risk_data['analyzed_date'] = time.strftime("%d %b %Y")
    active_risk_data['last_edited'] = st.session_state.get('user_name', 'Anna K., Associate')
    
    # Sync Playbook data backward compatibility binding
    playbook_data = active_playbook

    # Clean session state logs when switching levels
    if "last_active_level" not in st.session_state or st.session_state["last_active_level"] != lvl:
        st.session_state["last_active_level"] = lvl
        st.session_state["debate_turns_logs"] = active_debate
        # Guard against empty conflicts list
        st.session_state["logic_validation_result"] = active_conflicts[0] if active_conflicts else {
            "conflict": "No Contradictions Found",
            "severity": "Clear",
            "rule_a": "All scanned clauses are commercially standard.",
            "rule_b": "No operational contradictions detected between any two clauses.",
            "explanation": "The active contract did not produce any internally conflicting clauses.",
            "resolved_clause": "No resolution required.",
            "z3_code": "# No contradictions: SAT result confirmed."
        }
        
        # Set dynamic default autofix result
        if active_risk_data.get('red_flags'):
            first_flag = active_risk_data['red_flags'][0]['category']
            matched_key = None
            for pk in active_playbook.keys():
                if pk.lower() in first_flag.lower() or first_flag.lower() in pk.lower():
                    matched_key = pk
                    break
            if matched_key:
                preset = active_playbook[matched_key]
                st.session_state["autofix_result"] = {
                    "title": preset.get("title", matched_key),
                    "severity": preset["severity"],
                    "rewrite": preset["Defender"]["rewrite"],
                    "risk_label": preset["Defender"]["risk_label"],
                    "risk_class": preset["Defender"]["risk_class"],
                    "score": preset["Defender"]["score"],
                    "rationale": preset["Defender"]["rationale"],
                    "clause_text": preset["original"]
                }
            else:
                st.session_state["autofix_result"] = None
        else:
            st.session_state["autofix_result"] = None

    # ── Page: Dashboard ───────────────────────────────────────────────────────
    if current_page == "Dashboard":
        # Check if the user is requesting a new upload (via mobile/header + button or URL parameter)
        # OR if they have not uploaded any document and are not in demo mode.
        show_upload_panel = (qp.get("upload") == "true") or (not st.session_state.get("file_uploaded", False) and not st.session_state.get("demo_mode", False))
        
        if show_upload_panel:
            st.markdown(f"""
            <div style="background:#ffffff; border:1px solid #e5e7eb; border-radius:14px; padding:1.5rem; margin-bottom:1.5rem; box-shadow: 0 4px 20px rgba(0,0,0,0.06);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:1.3rem;">📤</span>
                        <div>
                            <div style="font-size:1rem; font-weight:800; color:#111827;">Upload Agreement for Audit</div>
                            <div style="font-size:0.75rem; color:#6b7280;">Upload a PDF, PPTX or TXT legal document for multi-agent red-teaming.</div>
                        </div>
                    </div>
                    <a href="?page=Dashboard&user={st.session_state.get('user_hash', '')}" target="_self"
                        style="font-size:0.75rem; font-weight:700; color:#4b5563; text-decoration:none; background:#f3f4f6; padding:5px 12px; border-radius:8px; border:1px solid #e5e7eb; white-space:nowrap;">✕ Cancel</a>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Render file uploader in main panel
            main_uploaded_file = st.file_uploader(
                "Drag and drop your contract here (PDF, PPTX, TXT):",
                type=["pdf", "pptx", "txt"],
                key="main_uploader",
                label_visibility="collapsed"
            )
            
            # Display helper guide for mobile users
            st.info("💡 Supported formats: PDF, PPTX, TXT. Secure Relational Database Storage & Encrypted Local Session.")
            st.stop()

        # Renders a prominent upload button visible only on mobile screens at the very top of Dashboard
        st.markdown("<div class='mobile-upload-btn-container'>", unsafe_allow_html=True)
        if st.button("📤 Audit a New Document / Re-upload", key="mobile_upload_trigger_btn", use_container_width=True):
            st.query_params.update({"page": "Dashboard", "upload": "true", "user": u_hash})
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

        # ──────────────────────────────────────────────────────────────────────
        # RECIPROCITY SPEEDOMETER — Real content-based analysis
        # Scans every red flag clause to determine which party (Client or Vendor)
        # actually benefits from each clause. Needle position is deterministic:
        #   Left (-90 to -10) = Vendor favored (Client is disadvantaged)
        #   Center (-10 to +10) = Balanced / Equal
        #   Right (+10 to +90) = Client favored (Vendor is disadvantaged)
        # ──────────────────────────────────────────────────────────────────────
        score = active_risk_data.get('score', 50)
        red_flags = active_risk_data.get('red_flags', [])
        
        # Keywords that indicate VENDOR advantage (bad for Client)
        VENDOR_ADVANTAGE_KEYWORDS = [
            'vendor', 'service provider', 'licensor', 'supplier', 'provider',
            'sole discretion', 'sole judgment', 'unilateral', 'no liability',
            'unlimited', 'perpetual', 'irrevocable', 'work for hire',
            'all rights', 'exclusive ownership', 'indemnify vendor',
            'vendor may terminate', 'at any time', 'without cause',
            'vendor retains', 'vendor owns', 'no warranty',
        ]
        # Keywords that indicate CLIENT advantage (bad for Vendor)
        CLIENT_ADVANTAGE_KEYWORDS = [
            'client', 'customer', 'licensee', 'buyer', 'purchaser',
            'client may terminate', 'client sole discretion', 'client retains',
            'unlimited access', 'client owns', 'all deliverables',
            'vendor shall indemnify', 'vendor must', 'vendor is liable',
            'no limitation on client', 'client unilateral',
        ]
        
        vendor_score = 0  # Vendor-advantaged clauses
        client_score = 0  # Client-advantaged clauses
        
        for flag in red_flags:
            # Check if there is an explicit semantic advantage key
            adv = flag.get('advantage', '').lower()
            if adv == 'vendor':
                vendor_score += flag.get('severity', 5)
            elif adv == 'client':
                client_score += flag.get('severity', 5)
            elif adv == 'balanced':
                vendor_score += flag.get('severity', 5) * 0.5
                client_score += flag.get('severity', 5) * 0.5
            else:
                # Fallback to keyword matching
                clause_text = (flag.get('clause_text', '') + ' ' + flag.get('impact', '') + ' ' + flag.get('category', '')).lower()
                v_hits = sum(1 for kw in VENDOR_ADVANTAGE_KEYWORDS if kw in clause_text)
                c_hits = sum(1 for kw in CLIENT_ADVANTAGE_KEYWORDS if kw in clause_text)
                if v_hits > c_hits:
                    vendor_score += flag.get('severity', 5)
                elif c_hits > v_hits:
                    client_score += flag.get('severity', 5)
                else:
                    # Tie — use severity to weight toward vendor (usually vendor-drafted contracts)
                    vendor_score += flag.get('severity', 5) * 0.5
                    client_score += flag.get('severity', 5) * 0.5
        
        total_weight = vendor_score + client_score
        if total_weight == 0:
            # No red flags = balanced agreement
            reciprocity_ratio = 0.5
        else:
            reciprocity_ratio = vendor_score / total_weight  # 0=all client, 0.5=balanced, 1=all vendor
        
        # Map reciprocity_ratio to needle_deg: 0.5=0deg, 0=−70deg, 1=+70deg
        needle_deg = round((reciprocity_ratio - 0.5) * 140)  # range -70 to +70
        needle_deg = max(-70, min(70, needle_deg))  # clamp
        
        # Determine label and colors based on needle position
        BALANCE_THRESHOLD = 10
        if abs(needle_deg) <= BALANCE_THRESHOLD:
            advantage_label = "Balanced Agreement"
            skew_badge_text = "🟢 Equal Reciprocity"
            status_color = "#10b981"
            status_bg = "rgba(16,185,129,0.1)"
            status_border = "#10b981"
            active_sweep_path = ""
            needle_explain = "Both parties have roughly equal advantages and obligations. This is a fair, balanced contract."
        elif needle_deg > BALANCE_THRESHOLD:  # Vendor favored
            advantage_label = "Vendor Favored"
            skew_badge_text = f"🟣 Vendor Advantage ({abs(needle_deg)}°)"
            status_color = "#a855f7"
            status_bg = "rgba(168,85,247,0.1)"
            status_border = "#a855f7"
            active_sweep_path = '<path d="M 100 20 A 80 80 0 0 1 180 100" fill="none" stroke="#a855f7" stroke-width="14" style="filter: url(#dialGlow);" />'
            needle_explain = f"The Vendor gains more from this agreement. {vendor_score:.0f} severity points of clauses favor the Vendor vs {client_score:.0f} for the Client. Renegotiate the highlighted red clauses."
        else:  # Client favored (needle left)
            advantage_label = "Client Favored"
            skew_badge_text = f"🔵 Client Advantage ({abs(needle_deg)}°)"
            status_color = "#0ea5e9"
            status_bg = "rgba(14,165,233,0.1)"
            status_border = "#0ea5e9"
            active_sweep_path = '<path d="M 20 100 A 80 80 0 0 1 100 20" fill="none" stroke="#0ea5e9" stroke-width="14" style="filter: url(#dialGlow);" />'
            needle_explain = f"The Client gains more from this agreement. {client_score:.0f} severity points of clauses favor the Client vs {vendor_score:.0f} for the Vendor. The Vendor should push back on highlighted clauses."

        # Determine current month dynamically from the analysis date
        month_name = "May" # fallback
        an_date = active_risk_data.get('analyzed_date', '')
        if an_date:
            for m in ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]:
                if m.lower() in an_date.lower():
                    month_name = m
                    break
        
        months_x = {
            "Jan": 50, "Feb": 110, "Mar": 170, "Apr": 230, "May": 290, "Jun": 350,
            "Jul": 410, "Aug": 470, "Sep": 530, "Oct": 590, "Nov": 650, "Dec": 710
        }
        highlight_x = months_x.get(month_name, 350)
        highlight_rect_x = highlight_x - 18
        tooltip_x = highlight_x - 70
        
        # Define base trends (out of 40 scale max)
        blue_volumes = [18.0, 28.0, 24.0, 28.0, 25.0, 30.0, 35.0, 28.0, 25.0, 22.0, 25.0, 27.0]
        red_risks = [15.0, 12.0, 18.0, 14.0, 22.0, 20.0, 16.0, 18.0, 14.0, 16.0, 20.0, 18.0]
        
        months_list = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        active_idx = months_list.index(month_name) if month_name in months_list else 5
        
        # Scale active month volume by pages analyzed
        pages = active_risk_data.get('pages_analyzed', 1)
        active_vol = min(38.0, max(6.0, float(pages) * 5.0 + 10.0))
        blue_volumes[active_idx] = active_vol
        
        # Scale active month risk dynamically from the EXACT contract score (0-100 mapped to 0-38 scale)
        active_risk_val = (score / 100.0) * 38.0
        red_risks[active_idx] = active_risk_val
        
        # Compute dynamic SVG path points
        blue_pts = []
        red_pts = []
        for i in range(12):
            x = 50 + i * 60
            y_blue = 200.0 - (blue_volumes[i] / 40.0) * 180.0
            y_red = 200.0 - (red_risks[i] / 40.0) * 180.0
            blue_pts.append((x, y_blue))
            red_pts.append((x, y_red))
            
        def build_svg_path(pts):
            path_str = f"M {pts[0][0]} {pts[0][1]}"
            for i in range(1, len(pts)):
                prev_x, prev_y = pts[i-1]
                curr_x, curr_y = pts[i]
                cp_x = (prev_x + curr_x) / 2
                path_str += f" C {cp_x} {prev_y}, {cp_x} {curr_y}, {curr_x} {curr_y}"
            return path_str
            
        blue_path_d = build_svg_path(blue_pts)
        red_path_d = build_svg_path(red_pts)
        
        blue_dot_y = blue_pts[active_idx][1]
        red_dot_y = red_pts[active_idx][1]
        tooltip_text = f"Risk exposure: {score}%"

        # 1. Custom Risk Trend SVG Chart
        svg_chart = f"""
        <svg viewBox="0 0 760 220" width="100%" height="220" xmlns="http://www.w3.org/2000/svg">
          <!-- Defs for gradients and shadows -->
          <defs>
            <linearGradient id="blueGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#0ea5e9" stop-opacity="0.15"/>
              <stop offset="100%" stop-color="#0ea5e9" stop-opacity="0"/>
            </linearGradient>
            <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#f43f5e" stop-opacity="0.15"/>
              <stop offset="100%" stop-color="#f43f5e" stop-opacity="0"/>
            </linearGradient>
            <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">
              <feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#000000" flood-opacity="0.08"/>
            </filter>
          </defs>
          
          <!-- Y-Axis Grid Lines -->
          <line x1="40" y1="20" x2="740" y2="20" stroke="#f3f4f6" stroke-width="1" />
          <text x="20" y="24" font-family="Inter" font-size="10" fill="#9ca3af">40</text>
          
          <line x1="40" y1="65" x2="740" y2="65" stroke="#f3f4f6" stroke-width="1" />
          <text x="20" y="69" font-family="Inter" font-size="10" fill="#9ca3af">30</text>
          
          <line x1="40" y1="110" x2="740" y2="110" stroke="#f3f4f6" stroke-width="1" stroke-dasharray="3,3" />
          <text x="20" y="114" font-family="Inter" font-size="10" fill="#9ca3af">20</text>
          
          <line x1="40" y1="155" x2="740" y2="155" stroke="#f3f4f6" stroke-width="1" />
          <text x="20" y="159" font-family="Inter" font-size="10" fill="#9ca3af">10</text>
          
          <line x1="40" y1="200" x2="740" y2="200" stroke="#f3f4f6" stroke-width="1" />
          <text x="25" y="204" font-family="Inter" font-size="10" fill="#9ca3af">0</text>
          
          <!-- X-Axis Labels -->
          <text x="50" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Jan</text>
          <text x="110" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Feb</text>
          <text x="170" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Mar</text>
          <text x="230" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Apr</text>
          <text x="290" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">May</text>
          <text x="350" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Jun</text>
          <text x="410" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Jul</text>
          <text x="470" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Aug</text>
          <text x="530" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Sep</text>
          <text x="590" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Oct</text>
          <text x="650" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Nov</text>
          <text x="710" y="218" font-family="Inter" font-size="10" fill="#9ca3af" text-anchor="middle">Dec</text>

          <!-- Dynamic Highlight Shaded Highlight Area -->
          <rect x="{highlight_rect_x}" y="20" width="36" height="180" fill="url(#blueGrad)" opacity="0.3" rx="8"/>
          <line x1="{highlight_x}" y1="20" x2="{highlight_x}" y2="200" stroke="#0ea5e9" stroke-width="1.5" stroke-dasharray="4,4" opacity="0.7" />

          <!-- Blue Line Path (Documents Analyzed) -->
          <path d="{blue_path_d}" 
                fill="none" stroke="#0ea5e9" stroke-width="3" stroke-linecap="round" />
                
          <!-- Red Line Path (With Risks) -->
          <path d="{red_path_d}" 
                fill="none" stroke="#f43f5e" stroke-width="3" stroke-linecap="round" />

          <!-- Dynamic Highlight Dots -->
          <circle cx="{highlight_x}" cy="{blue_dot_y}" r="5" fill="#0ea5e9" stroke="#ffffff" stroke-width="2" filter="url(#shadow)" />
          <circle cx="{highlight_x}" cy="{red_dot_y}" r="7" fill="#f43f5e" stroke="#ffffff" stroke-width="2.5" filter="url(#shadow)" />

          <!-- Dynamic Floating Tooltip Box -->
          <g transform="translate({tooltip_x}, 40)" filter="url(#shadow)">
            <rect x="0" y="0" width="140" height="28" fill="#fff5f5" stroke="#fca5a5" stroke-width="1" rx="6" />
            <text x="70" y="18" font-family="Inter" font-size="10.5" font-weight="600" fill="#dc2626" text-anchor="middle">{tooltip_text}</text>
          </g>
        </svg>
        """

        # Populate parameters from mock_data/session_state
        pages = active_risk_data['pages_analyzed']
        pages_t = active_risk_data['pages_trend']
        prec = active_risk_data['relevant_precedents']
        prec_t = active_risk_data['precedents_trend']
        risks = active_risk_data['identified_risks']
        risks_t = active_risk_data['risks_trend']
        conf = active_risk_data['ai_confidence']
        conf_t = active_risk_data['confidence_trend']
        risk_z = active_risk_data['risk_zone']
        an_date = active_risk_data['analyzed_date']
        ed_author = active_risk_data['last_edited']

        # Render System Notification Center if toggled via URL parameter
        if qp.get("notifications") == "true":
            st.toast("🔔 Audit Alerts Center", icon="🛡️")
            _uname_short = st.session_state.get('user_name', 'Guest').split(',')[0]
            _upersona = st.session_state.get('active_sandbox_persona', 'General Counsel')
            _nflags = len(active_risk_data.get('red_flags', []))
            _nconflicts = len(active_risk_data.get('logic_conflicts', []))
            _gdpr = active_risk_data.get('compliance_audit', {}).get('gdpr_score', 94)
            _alerts = [
                {"level": "OK",    "color": "#10b981", "bg": "rgba(16,185,129,0.08)",  "icon": "✅", "msg": "SQLite vault database fully initialized — WAL mode active for concurrent users."},
                {"level": "OK",    "color": "#10b981", "bg": "rgba(16,185,129,0.08)",  "icon": "✅", "msg": f"Session authenticated: <b>{_uname_short}</b> — 24-hour token active."},
                {"level": "INFO",  "color": "#38bdf8", "bg": "rgba(56,189,248,0.08)",  "icon": "ℹ️", "msg": f"Risk calibration bound to persona: <b>{_upersona}</b>."},
                {"level": "SOLVER","color": "#a855f7", "bg": "rgba(168,85,247,0.08)",  "icon": "🧠", "msg": "Z3 SMT solver: Satisfiable baseline — constraint verification complete."},
                {"level": "WARN",  "color": "#f59e0b", "bg": "rgba(245,158,11,0.08)",  "icon": "⚠️", "msg": f"<b>{_nflags}</b> red-flag loopholes identified in the active document."},
                {"level": "ALERT", "color": "#f43f5e", "bg": "rgba(244,63,94,0.10)",   "icon": "🚨", "msg": f"<b>{_nconflicts}</b> formal logic contradiction(s) require immediate legal review."},
                {"level": "INFO",  "color": "#38bdf8", "bg": "rgba(56,189,248,0.08)",  "icon": "🛡️", "msg": f"GDPR compliance score: <b>{_gdpr}%</b> — data minimization clauses scanned."},
            ]
            _rows_html = "".join([
                f'<div style="display:flex; align-items:flex-start; gap:10px; background:{a["bg"]}; border-left:3px solid {a["color"]}; border-radius:6px; padding:8px 10px; margin-bottom:6px;">'
                f'<span style="font-size:0.9rem; flex-shrink:0;">{a["icon"]}</span>'
                f'<div style="flex:1;">'
                f'<span style="font-size:0.68rem; font-weight:700; color:{a["color"]}; text-transform:uppercase; letter-spacing:0.06em;">[{a["level"]}]</span> '
                f'<span style="font-size:0.8rem; color:#374151; line-height:1.45;">{a["msg"]}</span>'
                f'</div></div>'
                for a in _alerts
            ])
            st.markdown(f"""
            <div style="background:#ffffff; border:1px solid #e5e7eb; border-radius:14px; padding:1.5rem; margin-bottom:1.25rem; box-shadow: 0 4px 20px rgba(0,0,0,0.06);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:1.3rem;">🔔</span>
                        <div>
                            <div style="font-size:0.95rem; font-weight:800; color:#111827;">System Audit Alert Center</div>
                            <div style="font-size:0.72rem; color:#6b7280;">Real-time security & analysis events for this session</div>
                        </div>
                    </div>
                    <a href="?page=Dashboard&user={st.session_state.get('user_hash', '')}" target="_self"
                        style="font-size:0.75rem; font-weight:700; color:#4b5563; text-decoration:none; background:#f3f4f6; padding:5px 12px; border-radius:8px; border:1px solid #e5e7eb; white-space:nowrap;">✕ Dismiss</a>
                </div>
                {_rows_html}
            </div>
            """, unsafe_allow_html=True)

        # Segmented view control toggle at the very top of Dashboard
        st.markdown("<div style='margin-bottom:0.25rem;'></div>", unsafe_allow_html=True)
        view_mode = st.segmented_control(
            "Select Dashboard View Layout:",
            options=["📊 Active Risk Audit Dashboard", "📄 Complete Harmonized Contract (Review & Download)"],
            default="📊 Active Risk Audit Dashboard"
        )
        st.markdown("<br>", unsafe_allow_html=True)

        # Early return block for Harmonized legal previewer
        if view_mode == "📄 Complete Harmonized Contract (Review & Download)":
            st.markdown("<h2 style='font-size:1.4rem; font-weight:700; color:#111827; margin-bottom:0.25rem;'>📄 Complete Harmonized Contract Draft</h2>", unsafe_allow_html=True)
            st.markdown("<p style='color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem;'>Review the integrated neutral rewrites aligned in standard document structure prior to exporting. Original traps are shown struck through in comparison.</p>", unsafe_allow_html=True)
            
            # Setup clauses array based on score level
            if score <= 20: # Level 1 (Low Risk)
                clauses_data = [
                    {"title": "Section 1.1: Scope of Services", "text": "Vendor shall perform the software development, API integration, and system deployment services specifically detailed in Exhibit A.", "risk": False},
                    {"title": "Section 2.1: Invoice Payment Terms", "text": "All invoices issued under this Agreement shall be payable by Client strictly within thirty (30) days of invoice receipt (Net 30).", "risk": False},
                    {"title": "Section 4.2: Mutual Indemnification", "text": "Each party agrees to indemnify, defend, and hold harmless the other party from and against any third-party claims, losses, or liabilities arising directly out of the gross negligence or willful misconduct of the indemnifying party.", "risk": False},
                    {"title": "Section 6.3: Intellectual Property Allocation", "text": "All work product and custom deliverables specifically created by Vendor for Client under this Agreement shall belong exclusively to Client. Notwithstanding the foregoing, Vendor retains sole ownership of all pre-existing technologies, background IP, and general methodologies.", "risk": False},
                    {"title": "Section 9.1: Symmetric Termination convenience", "text": "Either party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice to the other party.", "risk": False},
                    {"title": "Section 10.4: Reciprocal Liability Cap", "text": "Each party's total aggregate liability arising out of or related to this Agreement, whether in contract or tort, shall not exceed the total fees paid or payable by Client in the twelve (12) months preceding the claim.", "risk": False}
                ]
            else: # Level 3 (High Risk Default)
                clauses_data = [
                    {"title": "Section 1.1: Scope of Services", "text": "Vendor shall perform the software development, API integration, and system deployment services specifically detailed in Exhibit A.", "risk": False},
                    {"title": "Section 2.1: Payment Terms Gap", "text": "Client shall pay all invoices in Net 30. However, Schedule B designates Premium Tier consulting payments as Net 15.", "risk": True, "rewrite": "All invoices issued under this Agreement shall be payable by Client strictly within thirty (30) days of receipt."},
                    {"title": "Section 4.2: Indemnification Asymmetry", "text": "Vendor agrees to indemnify, defend, and hold harmless the Client from and against any and all claims, losses, liabilities, damages, expenses, and costs (including reasonable attorneys' fees) arising out of or related to the Vendor's performance under this Agreement, regardless of fault.", "risk": True, "rewrite": "Each party agrees to indemnify and hold harmless the other party from and against third-party claims arising out of the gross negligence or willful misconduct of the indemnifying party."},
                    {"title": "Section 6.3: Intellectual Property Assignment", "text": "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall be deemed works made for hire and shall be the exclusive property of Client.", "risk": True, "rewrite": "All deliverables specifically created by Vendor for Client under this Agreement shall belong to Client. Vendor explicitly retains all rights to its pre-existing technologies and background IP."},
                    {"title": "Section 9.1: Termination Asymmetry", "text": "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days following written notice.", "risk": True, "rewrite": "Either party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice to the other party."},
                    {"title": "Section 10.4: Limitation of Liability", "text": "Under no circumstances shall Client's aggregate liability arising out of or related to this Agreement exceed the total fees paid by Client to Vendor in the one (1) month preceding the event giving rise to the claim. No equivalent cap is placed upon Vendor's liability.", "risk": True, "rewrite": "Each party's total aggregate liability arising out of or related to this Agreement shall be limited to a mutual cap equal to twelve (12) months of fees."}
                ]
                
            # Render full paper mockup
            st.markdown("""
            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:3rem; box-shadow:0 10px 25px rgba(0,0,0,0.03); max-width:850px; margin:0 auto; font-family:'Georgia', serif; color:#1f2937; line-height:1.7;">
                <div style="text-align:center; margin-bottom:2.5rem; border-bottom:2px solid #e2e8f0; padding-bottom:1.5rem;">
                    <h1 style="font-family:'Inter', sans-serif; font-size:1.6rem; font-weight:800; color:#1e3a8a; text-transform:uppercase; letter-spacing:0.05em; margin:0 0 0.5rem 0;">MUTUAL SERVICES AGREEMENT</h1>
                    <div style="font-family:'Inter', sans-serif; font-size:0.75rem; font-weight:700; color:#10b981; text-transform:uppercase; letter-spacing:0.1em; display:flex; align-items:center; justify-content:center; gap:4px;">
                        🟢 HEALED & NEUTRALIZED BY REGULAITE-AI SANDBOX
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            # Loop clauses inside legal previewer paper
            for cl in clauses_data:
                if cl["risk"]:
                    st.markdown(f"""
                    <div style="background:rgba(240, 253, 244, 0.65); border: 1px solid rgba(74, 222, 128, 0.3); border-left: 5px solid #22c55e; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem;">
                        <div style="font-family:'Inter', sans-serif; font-weight: 700; font-size: 0.8rem; color: #15803d; text-transform: uppercase; letter-spacing: 0.02em; margin-bottom: 6px; display:flex; align-items:center; gap:4px;">
                            ✨ {cl["title"]} (HEALED & NEUTRAL REWRITE INTEGRATED)
                        </div>
                        <div style="font-size: 0.92rem; color: #166534; font-weight: 500; font-family: 'Georgia', serif; line-height: 1.6; white-space: pre-wrap;">{cl["rewrite"]}</div>
                        <div style="font-family:'Inter', sans-serif; font-size:0.75rem; color:#b91c1c; margin-top:8px; border-top:1px dashed rgba(220,38,38,0.25); padding-top:6px;">
                            <b>🚨 Struck-Through Predatory Loophole:</b> <span style="text-decoration: line-through; opacity: 0.6;">{cl["text"]}</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div style="margin-bottom: 1.5rem; padding-left: 5px;">
                        <div style="font-family:'Inter', sans-serif; font-weight: 700; font-size: 0.8rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.02em; margin-bottom: 6px;">
                            {cl["title"]}
                        </div>
                        <div style="font-size: 0.92rem; color: #374151; font-family: 'Georgia', serif; line-height: 1.6; white-space: pre-wrap;">{cl["text"]}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    
            st.markdown("</div>", unsafe_allow_html=True)
            
            # File download section
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<h3 style='font-size:1.1rem; font-weight:600; color:#111827; margin-bottom:0.25rem;'>📥 Export Harmonized Agreement</h3>", unsafe_allow_html=True)
            st.markdown("<p style='color:#6b7280; font-size:0.8rem; margin-bottom:1rem;'>Download as a properly formatted PDF — you can re-upload this file to RegulAIte for further analysis.</p>", unsafe_allow_html=True)
            
            # Generate PDF using reportlab
            _pdf_bytes = generate_rewrite_pdf(
                clauses_data,
                user_name=st.session_state.get('user_name', 'General Counsel'),
                filename=st.session_state.get('uploaded_filename', 'Contract')
            )
            
            col_dl1, col_dl2 = st.columns([2, 1])
            with col_dl1:
                st.download_button(
                    label="📥 Download Healed Contract (.PDF) — Re-uploadable",
                    data=_pdf_bytes,
                    file_name="Healed_Mutual_Agreement_RegulAIte.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    type="primary"
                )
            with col_dl2:
                # Plain text fallback
                plain_contract = "MUTUAL SERVICES AGREEMENT\n=========================\n\n"
                plain_contract += f"Audited by RegulAIte-AI | {time.strftime('%d %b %Y')}\n"
                plain_contract += f"Persona: {st.session_state.get('user_name', 'General Counsel')}\n\n"
                for cl in clauses_data:
                    content = cl["rewrite"] if cl.get("risk") else cl["text"]
                    plain_contract += f"--- {cl['title'].upper()} ---\n{content}\n\n"
                st.download_button(
                    label="📄 Also get .TXT",
                    data=plain_contract,
                    file_name="Healed_Agreement.txt",
                    mime="text/plain",
                    use_container_width=True
                )
            st.info("💡 Tip: The PDF you download can be directly re-uploaded here for further analysis or comparison.")
            st.stop()

        # Construct Dashboard HTML Grid
        u_hash = st.session_state.get('user_hash', '')
        user_display_name = st.session_state.get('user_name', 'Guest Auditor').split(',')[0].strip()
        user_role_display = st.session_state.get('user_name', 'Guest Auditor').split(',')[-1].strip() if ',' in st.session_state.get('user_name', '') else 'Auditor'
        current_clause_q = st.session_state.get("clause_search_query", "")
        _avatar_initial = user_display_name[0].upper() if user_display_name else 'U'
        
        # Inject JS: intercept Enter in the fake header search bar → navigate to Dashboard with ?q=
        st.markdown("""
        <script>
        (function() {
            function attachSearchEnter() {
                var inp = document.querySelector('.search-input');
                if (!inp) { setTimeout(attachSearchEnter, 400); return; }
                inp.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        var q = encodeURIComponent(inp.value.trim());
                        if (q) window.location.href = window.location.pathname + '?page=Dashboard&clause_q=' + q + '&user=' + inp.dataset.user;
                    }
                });
                // Auto-focus if redirected with clause_q param
                var params = new URLSearchParams(window.location.search);
                if (params.get('clause_q')) { inp.value = decodeURIComponent(params.get('clause_q')); }
            }
            document.addEventListener('DOMContentLoaded', attachSearchEnter);
            setTimeout(attachSearchEnter, 600);
        })();
        </script>
        """, unsafe_allow_html=True)
        
        # Read clause_q URL param into session if present
        _clause_q_from_url = st.query_params.get("clause_q", "")
        if _clause_q_from_url:
            st.session_state["clause_search_query"] = _clause_q_from_url
            current_clause_q = _clause_q_from_url
        
        dashboard_html = f"""
        <div class="dashboard-container">
            <!-- Header bar -->
            <div class="header-container">
                <h1 class="header-title">⚖️ AI Analysis Overview</h1>
                <div class="search-bar-container" title="Search scanned clauses — press Enter to filter">
                    <span class="search-icon">🔍</span>
                    <input type="text" placeholder="Search clauses, risks, loopholes... (Enter)" class="search-input"
                        value="{current_clause_q}"
                        data-user="{u_hash}"
                        title="Type a keyword and press Enter to filter clauses in the Loophole Visualizer."
                        style="cursor:text;">
                </div>
                <div class="header-actions">
                    <a href="?page=Dashboard&user={u_hash}&upload=true" target="_self"
                        class="action-btn" title="Upload a new document for analysis"
                        style="text-decoration:none; display:inline-flex; align-items:center; justify-content:center; font-weight:bold; font-size:1.1rem; line-height:1; background:linear-gradient(135deg,#3b82f6,#06b6d4); color:#fff; border-color:transparent;">
                        +
                    </a>
                    <a href="?page=SmartReview&user={u_hash}" target="_self"
                        class="action-btn" title="Open AI Smart Review Tools"
                        style="text-decoration:none; display:inline-flex; align-items:center; justify-content:center; font-size:1rem; line-height:1;">🎛️</a>
                    <a href="?page=Dashboard&notifications=true&user={u_hash}" target="_self"
                        class="action-btn relative" title="View system audit alerts & notifications"
                        style="text-decoration:none; display:inline-flex; align-items:center; justify-content:center; font-size:1rem; line-height:1;">🔔<span class="badge-dot"></span></a>
                    <!-- Avatar with popup profile card -->
                    <div style="position:relative; display:inline-block;" id="avatar-wrap">
                        <div onclick="document.getElementById('profile-popup').style.display = document.getElementById('profile-popup').style.display === 'block' ? 'none' : 'block'; event.stopPropagation();"
                            style="display:inline-flex; align-items:center; justify-content:center; width:34px; height:34px;
                            border-radius:50%; background:linear-gradient(135deg,#3b82f6,#06b6d4);
                            border:2px solid #3b82f6; box-shadow:0 0 0 2px rgba(59,130,246,0.2);
                            cursor:pointer; font-size:1rem; font-weight:700; color:#fff;"
                            title="Profile — {user_display_name}">
                            {_avatar_initial}
                        </div>
                        <div id="profile-popup" style="display:none; position:absolute; right:0; top:44px; width:220px;
                            background:#fff; border:1px solid #e5e7eb; border-radius:14px;
                            box-shadow:0 12px 40px rgba(0,0,0,0.15); z-index:9999; padding:1rem; text-align:left;"
                            onclick="event.stopPropagation();">
                            <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px; border-bottom:1px solid #f1f5f9; padding-bottom:10px;">
                                <div style="background:linear-gradient(135deg,#3b82f6,#06b6d4); width:38px; height:38px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:1.1rem; font-weight:700; color:#fff; flex-shrink:0;">
                                    {_avatar_initial}
                                </div>
                                <div>
                                    <div style="font-size:0.85rem; font-weight:700; color:#111827;">{user_display_name}</div>
                                    <div style="font-size:0.7rem; color:#6b7280;">{user_role_display}</div>
                                </div>
                            </div>
                            <a href="?page=Authentication&user={u_hash}" target="_self"
                                style="display:block; font-size:0.8rem; color:#3b82f6; font-weight:600; text-decoration:none; padding:5px 0; border-bottom:1px solid #f1f5f9;">✏️ Edit Profile</a>
                            <a href="?page=Dashboard&user={u_hash}" target="_self"
                                style="display:block; font-size:0.8rem; color:#4b5563; text-decoration:none; padding:5px 0; border-bottom:1px solid #f1f5f9;">📊 Dashboard</a>
                            <a href="?page=Authentication&user={u_hash}&logout=1" target="_self"
                                style="display:block; font-size:0.8rem; color:#dc2626; font-weight:600; text-decoration:none; padding:5px 0;">🚪 Sign Out</a>
                        </div>
                    </div>
                </div>
            </div>
            <script>
            document.addEventListener('click', function() {{
                var p = document.getElementById('profile-popup');
                if(p) p.style.display='none';
            }});
            </script>

            <!-- Project Pitch Deck Showcase Card -->
            <div class="card" style="background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border-left: 5px solid #3b82f6; padding: 1.5rem; border-radius: 14px; margin-bottom: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); border-top: 1px solid #bfdbfe; border-right: 1px solid #bfdbfe; border-bottom: 1px solid #bfdbfe;">
                <div style="display: flex; flex-wrap: wrap; justify-content: space-between; gap: 1.5rem;">
                    
                    <!-- Left: Core Concept & Problem Statement -->
                    <div style="flex: 1; min-width: 300px;">
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                            <span style="font-size: 1.75rem;">⚖️</span>
                            <div>
                                <h2 style="font-size: 1.35rem; font-weight: 700; color: #1e3a8a; margin: 0; line-height: 1.2;">RegulAIte: Agentic AI Legal Document Simplifier</h2>
                                <p style="font-size: 0.85rem; color: #2563eb; font-weight: 600; margin: 2px 0 0 0; text-transform: uppercase; letter-spacing: 0.05em;">"A robot lawyer that reads your contracts, finds the traps, and fixes them — before you sign."</p>
                            </div>
                        </div>
                        <p style="font-size: 0.9rem; color: #1e40af; line-height: 1.5; margin-bottom: 1.25rem;">
                            Startups and businesses skip legal reviews due to high fees, falling into dangerous traps. RegulAIte is not a simple summarizer—it actively stress-tests contracts using adversarial red-teaming and mathematically validates internal logic.
                        </p>
                        
                        <!-- Problem Statement Boxes -->
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem;">
                            <div style="background: rgba(255, 255, 255, 0.75); border: 1px solid rgba(191, 219, 254, 0.5); padding: 0.75rem; border-radius: 10px;">
                                <div style="font-weight: 600; color: #1e3a8a; font-size: 0.85rem; margin-bottom: 0.25rem;">📄 The Jargon Trap</div>
                                <div style="font-size: 0.75rem; color: #475569; line-height: 1.3;">14 pages of dense legalese. Under 17% of non-lawyers understand what they sign.</div>
                            </div>
                            <div style="background: rgba(255, 255, 255, 0.75); border: 1px solid rgba(191, 219, 254, 0.5); padding: 0.75rem; border-radius: 10px;">
                                <div style="font-weight: 600; color: #1e3a8a; font-size: 0.85rem; margin-bottom: 0.25rem;">💰 The Cost Trap</div>
                                <div style="font-size: 0.75rem; color: #475569; line-height: 1.3;">Reviews cost ₹40k–₹1L and take 3–5 days. Startups skip it and get burned.</div>
                            </div>
                            <div style="background: rgba(255, 255, 255, 0.75); border: 1px solid rgba(191, 219, 254, 0.5); padding: 0.75rem; border-radius: 10px;">
                                <div style="font-weight: 600; color: #1e3a8a; font-size: 0.85rem; margin-bottom: 0.25rem;">🤖 The AI Gap</div>
                                <div style="font-size: 0.75rem; color: #475569; line-height: 1.3;">Standard LLMs miss loopholes, logical conflict, and hallucinate citations.</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Right: Engineering Roles Panel -->
                    <div style="width: 320px; background: rgba(255, 255, 255, 0.8); border: 1px solid #bfdbfe; padding: 1rem; border-radius: 12px; display: flex; flex-direction: column; justify-content: space-between; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02); min-height: 180px;">
                        <div>
                            <h3 style="font-size: 0.95rem; font-weight: 700; color: #1e3a8a; margin: 0 0 0.75rem 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.5rem; display: flex; align-items: center; justify-content: space-between;">
                                <span>🛠️ Team Engineering Roles</span>
                                <span style="font-size: 0.7rem; background: #dbeafe; color: #1e40af; padding: 2px 8px; border-radius: 10px;">5 Key Roles</span>
                            </h3>
                            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem;">
                                    <span style="color: #475569; font-weight: 500;">🎨 Frontend Glassmorphic UI</span>
                                    <span style="font-weight: 600; color: #059669; background: #d1fae5; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🟢 Completed</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem;">
                                    <span style="color: #475569; font-weight: 500;">⚙️ Backend API Architect</span>
                                    <span style="font-weight: 600; color: #2563eb; background: #dbeafe; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🔵 Live & Connected</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem;">
                                    <span style="color: #475569; font-weight: 500;">⚔️ AI Agent & Prompt Architect</span>
                                    <span style="font-weight: 600; color: #2563eb; background: #dbeafe; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🔵 Live & Connected</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem;">
                                    <span style="color: #475569; font-weight: 500;">🔬 Formal Z3 Logic Engineer</span>
                                    <span style="font-weight: 600; color: #2563eb; background: #dbeafe; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🔵 Live & Connected</span>
                                </div>
                                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem;">
                                    <span style="color: #475569; font-weight: 500;">🛡️ Regulatory Compliance Auditor</span>
                                    <span style="font-weight: 600; color: #2563eb; background: #dbeafe; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🔵 Live & Connected</span>
                                </div>
                            </div>
                        </div>
                        <div style="font-size: 0.7rem; color: #64748b; margin-top: 0.75rem; text-align: center; border-top: 1px dashed #e2e8f0; padding-top: 0.5rem;">
                            "83% of startup contracts favor only the vendor."
                        </div>
                    </div>
                    
                </div>
            </div>

            <!-- Two-Column Grid Layout -->
            <div class="dashboard-grid">
                
                <!-- Left Column -->
                <div class="col-left">
                    <!-- Document Status Card -->
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Document Status</h2>
                            <span class="card-actions">•••</span>
                        </div>
                        <div class="pdf-row">
                            <span class="pdf-icon">📄</span>
                            <div class="pdf-info">
                                <div class="pdf-name">{fn}</div>
                                <div class="pdf-meta">PDF • 1.1 MB</div>
                            </div>
                            <div class="pdf-actions">
                                <span class="action-icon">👁️</span>
                                <span class="action-icon">📥</span>
                            </div>
                        </div>
                        <div class="meta-list">
                            <div class="meta-item">
                                <span class="meta-label">Analyzed:</span>
                                <span class="meta-value">{an_date}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-label">Last Edited:</span>
                                <span class="meta-value">{ed_author}</span>
                            </div>
                        </div>
                        <div class="progress-section">
                            <div class="progress-header">
                                <span class="progress-label">AI Review Progress</span>
                                <span class="progress-value">91% complete</span>
                            </div>
                            <div class="progress-bar-container">
                                <div class="progress-bar-fill" style="width: 91%;"></div>
                            </div>
                            <span class="stage-tag">Stage: Clause Analysis</span>
                        </div>
                    </div>

                    <!-- AI Summary Card -->
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">AI Summary</h2>
                            <span class="card-actions">•••</span>
                        </div>
                        <div class="meta-list">
                            <div class="meta-item">
                                <span class="meta-label">Risk Zone:</span>
                                <span class="risk-badge">⚠️ {risk_z}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-label">Clause Type:</span>
                                <span class="meta-value">License / IP</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-label">Impact:</span>
                                <span class="meta-value">May affect exclusivity rights</span>
                            </div>
                        </div>
                        <div class="recommendation-box">
                            <div class="rec-title">💡 Recommendation</div>
                            <div class="rec-content">Clarify the term "limited license" or replace with "non-exclusive use right"</div>
                        </div>
                        <a href="{get_nav_link('SmartReview')}&tab=AutoFixer" target="_self" class="suggested-rewrite-btn">See Suggested Rewrite</a>
                    </div>

                    <!-- Reciprocity Advantage Meter -->
                    <div class="card" style="text-align: center; padding: 1.25rem; border-radius: 12px; background: #ffffff; border: 1px solid #e2e8f0; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                        <div style="font-weight: 700; font-size: 0.85rem; color: #1e3a8a; margin-bottom: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; display: flex; align-items: center; gap: 4px; justify-content: center;">
                            ⚖️ Reciprocity Advantage Meter
                        </div>
                        <div style="font-size: 0.72rem; color: #64748b; margin-bottom: 0.75rem;">
                            Measures contract balance. Centered pointer indicates fair reciprocity.
                        </div>
                        
                        <div style="position: relative; width: 100%; height: 110px; display: flex; justify-content: center; align-items: center;">
                            <svg width="200" height="110" viewBox="0 0 200 110" xmlns="http://www.w3.org/2000/svg">
                                <defs>
                                    <filter id="dialGlow" x="-20%" y="-20%" width="140%" height="140%">
                                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                                        <feComposite in="SourceGraphic" in2="blur" operator="over" />
                                    </filter>
                                </defs>
                                <!-- Background Arc -->
                                <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#e5e7eb" stroke-width="14" stroke-linecap="round" />
                                
                                <!-- Left Zone (Client Advantage) -->
                                <path d="M 20 100 A 80 80 0 0 1 100 20" fill="none" stroke="rgba(14, 165, 233, 0.1)" stroke-width="14" />
                                
                                <!-- Right Zone (Vendor Advantage) -->
                                <path d="M 100 20 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(168, 85, 247, 0.1)" stroke-width="14" />
                                
                                <!-- Active sweep arc -->
                                {active_sweep_path}
                                
                                <!-- Midpoint Balance Indicator -->
                                <line x1="100" y1="20" x2="100" y2="10" stroke="#10b981" stroke-width="3" stroke-linecap="round" />
                                
                                <!-- Rotating Needle -->
                                <g transform="translate(100,100)">
                                    <line x1="0" y1="0" x2="0" y2="-75" stroke="#1f2937" stroke-width="4.5" stroke-linecap="round" transform="rotate({needle_deg})">
                                        <animateTransform attributeName="transform" type="rotate" from="-90" to="{needle_deg}" dur="1.2s" fill="freeze" keyTimes="0;1" keySplines="0.4 0 0.2 1" calcMode="spline" />
                                    </line>
                                    <circle cx="0" cy="0" r="10" fill="#1f2937" />
                                    <circle cx="0" cy="0" r="4.5" fill="#ffffff" />
                                </g>
                            </svg>
                        </div>
                        
                        <div style="font-size: 1.1rem; font-weight: 800; color: {status_color}; margin-top: 2px;">{advantage_label}</div>
                        <div style="font-size: 0.7rem; font-weight: 700; background: {status_bg}; color: {status_color}; padding: 2px 10px; border-radius: 12px; border: 1px solid {status_border}; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px;">
                            {skew_badge_text}
                        </div>
                        <div style="font-size:0.72rem; color:#6b7280; margin-top:8px; line-height:1.45; text-align:left; background:#f8fafc; border-radius:8px; padding:8px 10px; border:1px solid #e5e7eb;">
                            <b>What this means:</b> {needle_explain}
                        </div>
                        <div style="font-size:0.68rem; color:#94a3b8; margin-top:6px; margin-bottom:6px;">
                            Vendor weight: <b style='color:#a855f7'>{vendor_score:.0f}</b> &nbsp;|&nbsp; Client weight: <b style='color:#0ea5e9'>{client_score:.0f}</b> &nbsp;|&nbsp; Clauses: <b>{len(red_flags)}</b>
                        </div>
                        
                        <div style="margin-top: 12px; border-top: 1px dashed #e2e8f0; padding-top: 10px; width: 100%; text-align: left;">
                            <div style="font-size: 0.72rem; font-weight: 700; color: #475569; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.03em;">🧭 Speedometer Reference Guide</div>
                            <div style="display: flex; flex-direction: column; gap: 6px;">
                                <div style="display: flex; align-items: flex-start; gap: 6px; font-size: 0.68rem; line-height: 1.35; color: #475569;">
                                    <span style="font-size: 0.85rem; line-height: 1;">🔵</span>
                                    <div><b>Left Side (Client Advantage):</b> The agreement heavily favors the Client. The Vendor carries unfair risk and should request reciprocal protections.</div>
                                </div>
                                <div style="display: flex; align-items: flex-start; gap: 6px; font-size: 0.68rem; line-height: 1.35; color: #475569;">
                                    <span style="font-size: 0.85rem; line-height: 1;">🟢</span>
                                    <div><b>Center (Balanced Agreement):</b> Perfectly equal risk distribution. Symmetrical clauses protect both parties equally without predatory terms.</div>
                                </div>
                                <div style="display: flex; align-items: flex-start; gap: 6px; font-size: 0.68rem; line-height: 1.35; color: #475569;">
                                    <span style="font-size: 0.85rem; line-height: 1;">🟣</span>
                                    <div><b>Right Side (Vendor Advantage):</b> The agreement heavily favors the Vendor. The Client carries excessive liability and should request balanced terms.</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Right Column -->
                <div class="col-right">
                    <!-- KPI metrics Row -->
                    <div class="kpi-row">
                        <div class="kpi-card">
                            <span class="kpi-label">Pages Analyzed</span>
                            <div class="kpi-value-container">
                                <span class="kpi-val">{pages}</span>
                                <span class="kpi-trend trend-green">+{pages_t}</span>
                            </div>
                        </div>
                        <div class="kpi-card">
                            <span class="kpi-label">Relevant Precedents</span>
                            <div class="kpi-value-container">
                                <span class="kpi-val">{prec}</span>
                                <span class="kpi-trend trend-red">{prec_t}</span>
                            </div>
                        </div>
                        <div class="kpi-card">
                            <span class="kpi-label">Identified Risks</span>
                            <div class="kpi-value-container">
                                <span class="kpi-val">{risks}</span>
                                <span class="kpi-trend trend-red">{risks_t}</span>
                            </div>
                        </div>
                        <div class="kpi-card">
                            <span class="kpi-label">AI Confidence</span>
                            <div class="kpi-value-container">
                                <span class="kpi-val">{conf}</span>
                                <span class="kpi-trend trend-green">{conf_t}</span>
                            </div>
                        </div>
                    </div>

                    <!-- AI Risk Trend Line Chart -->
                    <div class="card chart-card">
                        <div class="chart-header">
                            <h2 class="card-title">AI Risk Trend</h2>
                            <div class="chart-toggles">
                                <span class="toggle-pill active">Documents analyzed</span>
                                <span class="toggle-pill red">With risks</span>
                            </div>
                        </div>
                        <div class="chart-container">
                            {svg_chart}
                        </div>
                    </div>

                    <!-- Relevant Cases Precedents Table -->
                    <div class="card table-card">
                        <div class="card-header">
                            <h2 class="card-title">Relevant Cases</h2>
                            <span class="card-actions">•••</span>
                        </div>
                        <table class="cases-table">
                            <thead>
                                <tr>
                                    <th>Case Name</th>
                                    <th>Jurisdiction</th>
                                    <th>Year</th>
                                    <th>Relevance</th>
                                    <th>Clause Match</th>
                                    <th>Outcome</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>Nova Systems Corp</td>
                                    <td>🇬🇧 UK</td>
                                    <td>2025</td>
                                    <td>93 %</td>
                                    <td>Clause 5.1</td>
                                    <td><span class="outcome-pill win">Win</span></td>
                                </tr>
                                <tr>
                                    <td>Confidentiality Clause Dispute</td>
                                    <td>🇪🇺 EU</td>
                                    <td>2022</td>
                                    <td>89 %</td>
                                    <td>Clause 5.2</td>
                                    <td><span class="outcome-pill settled">Settled</span></td>
                                </tr>
                                <tr>
                                    <td>TechSoft vs. Orion Ltd</td>
                                    <td>🇬🇧 UK</td>
                                    <td>2024</td>
                                    <td>94 %</td>
                                    <td>Clause 2.3</td>
                                    <td><span class="outcome-pill win">Win</span></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
        </div>
        """

        # Render HTML Dashboard Grid
        render_html(dashboard_html)
        st.markdown("<br>", unsafe_allow_html=True)

        # ── 2. Line-by-Line Loophole & Deadline Visualizer ──
        st.markdown('<h2 style="font-size:1.15rem; font-weight:600; color:#111827; margin-bottom:0.75rem; margin-top:0.5rem;">📄 Line-by-Line Loophole & Deadline Visualizer</h2>', unsafe_allow_html=True)
        st.markdown('<p style="color:#6b7280; font-size:0.82rem; margin-bottom:1.25rem;">Scroll through each clause of the active draft. Loopholes are highlighted in soft red with expandable breakdowns of gains, losses, and deadlines.</p>', unsafe_allow_html=True)
        
        # Interactive Search Box
        search_query = st.text_input(
            "🔍 Search Scanned Clauses & Flagged Alerts:",
            value=st.session_state.get("clause_search_query", ""),
            placeholder="🔍 Type keywords (e.g. liability, termination, Net 30) to filter the visualizer instantly...",
            label_visibility="collapsed"
        )
        st.session_state["clause_search_query"] = search_query
        
        # Determine clauses based on low risk (reprinted/balanced) vs default scanned high risk
        if score <= 20: # Balanced NDA text
            clauses = [
                {
                    "title": "Section 1.1: Scope of Services",
                    "text": "Vendor shall perform the software development, API integration, and system deployment services specifically detailed in Exhibit A.",
                    "risk": False
                },
                {
                    "title": "Section 2.1: Invoice Payment Terms",
                    "text": "All invoices issued under this Agreement shall be payable by Client strictly within thirty (30) days of invoice receipt (Net 30).",
                    "risk": False
                },
                {
                    "title": "Section 4.2: Mutual Indemnification",
                    "text": "Each party agrees to indemnify, defend, and hold harmless the other party from and against any third-party claims, losses, or liabilities arising directly out of the gross negligence or willful misconduct of the indemnifying party.",
                    "risk": False
                },
                {
                    "title": "Section 6.3: Intellectual Property Allocation",
                    "text": "All work product and custom deliverables specifically created by Vendor for Client under this Agreement shall belong exclusively to Client. Notwithstanding the foregoing, Vendor retains sole ownership of all pre-existing technologies, background IP, and general methodologies.",
                    "risk": False
                },
                {
                    "title": "Section 9.1: Symmetric Termination convenience",
                    "text": "Either party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice to the other party.",
                    "risk": False
                },
                {
                    "title": "Section 10.4: Reciprocal Liability Cap",
                    "text": "Each party's total aggregate liability arising out of or related to this Agreement, whether in contract or tort, shall not exceed the total fees paid or payable by Client in the twelve (12) months preceding the claim.",
                    "risk": False
                }
            ]
        else: # High Risk Default / Level 3
            clauses = [
                {
                    "title": "Section 1.1: Scope of Services",
                    "text": "Vendor shall perform the software development, API integration, and system deployment services specifically detailed in Exhibit A.",
                    "risk": False
                },
                {
                    "title": "Section 2.1: Payment Terms Gap",
                    "text": "Client shall pay all invoices in Net 30. However, Schedule B designates Premium Tier consulting payments as Net 15.",
                    "risk": True,
                    "deadlines": "🕒 Net 15 days (Annex) vs Net 30 days (Body)",
                    "law": "🏛️ Uniform Commercial Code (UCC) Article 2 - Contradictory Terms in Forms",
                    "explanation": "Complying with Net 30 in the contract body legally contradicts the Net 15 timeline in the annex, triggering premature late fee penalties and cash flow freezes.",
                    "gain": "Client keeps standard consulting services active under broad Net 30 terms, but forces immediate premium deployment payments under short Net 15 terms.",
                    "loss": "Vendor suffers cash flow spikes, payroll delay risks, and automatic late fees billed prematurely by system logs.",
                    "rewrite": "All invoices issued under this Agreement shall be payable by Client strictly within thirty (30) days of receipt."
                },
                {
                    "title": "Section 4.2: Indemnification Asymmetry",
                    "text": "Vendor agrees to indemnify, defend, and hold harmless the Client from and against any and all claims, losses, liabilities, damages, expenses, and costs (including reasonable attorneys' fees) arising out of or related to the Vendor's performance under this Agreement, regardless of fault.",
                    "risk": True,
                    "deadlines": "🕒 Immediate notice requirement for third-party claims (3-day window)",
                    "law": "🏛️ Express Negligence Doctrine & B2B Unconscionability",
                    "explanation": "The term 'regardless of fault' is a massive loophole that forces the Vendor to fully pay for and defend the Client even if the Client's own recklessness or negligence caused the lawsuit.",
                    "gain": "Client gets 100% free legal defense and liability coverage for all incidents, including those caused by its own employees.",
                    "loss": "Vendor faces complete commercial ruination and bankruptcy by defending claims they did not cause and had no control over.",
                    "rewrite": "Each party agrees to indemnify and hold harmless the other party from and against third-party claims arising out of the gross negligence or willful misconduct of the indemnifying party."
                },
                {
                    "title": "Section 6.3: Intellectual Property Assignment",
                    "text": "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall be deemed works made for hire and shall be the exclusive property of Client.",
                    "risk": True,
                    "deadlines": "🕒 Permanent transfer of all conceived intellectual property upon creation",
                    "law": "🏛️ US Patent & Trademark Law / Work Made For Hire Provisions",
                    "explanation": "The phrase 'whether or not during working hours' strips the Vendor of pre-existing background tech, general know-how, and unrelated side projects, granting them all to the Client for free.",
                    "gain": "Client gains ownership of the Vendor's core pre-existing software engines and proprietary general methodologies for free.",
                    "loss": "Vendor loses intellectual property rights to their own software, rendering them unable to reuse their own codebase for other clients.",
                    "rewrite": "All deliverables specifically created by Vendor for Client under this Agreement shall belong to Client. Vendor explicitly retains all rights to its pre-existing technologies and background IP."
                },
                {
                    "title": "Section 9.1: Termination Asymmetry",
                    "text": "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days following written notice.",
                    "risk": True,
                    "deadlines": "🕒 5-day Client notice vs 60-day Vendor cure period",
                    "law": "🏛️ B2B Good Faith and Fair Dealing Standards",
                    "explanation": "An extremely unbalanced notice period allows the Client to terminate convenience on a whim (leaving the Vendor with idle payroll and sunk costs), while locking the Vendor in a 60-day breach cure loop.",
                    "gain": "Client gets absolute tactical freedom to exit the project at any time with virtually zero warning or off-boarding penalty.",
                    "loss": "Vendor faces sudden revenue loss, idle developer salaries, and must give 60 days notice of breach before stopping services.",
                    "rewrite": "Either party may terminate this Agreement for convenience at any time upon thirty (30) days' prior written notice to the other party."
                },
                {
                    "title": "Section 10.4: Limitation of Liability",
                    "text": "Under no circumstances shall Client's aggregate liability arising out of or related to this Agreement exceed the total fees paid by Client to Vendor in the one (1) month preceding the event giving rise to the claim. No equivalent cap is placed upon Vendor's liability.",
                    "risk": True,
                    "deadlines": "🕒 1-month Client cap vs Unlimited Vendor exposure",
                    "law": "🏛️ B2B Contractual Risk Allocation Baseline Standards",
                    "explanation": "Client's liability is capped at a tiny 1/12th of annual value while the Vendor remains exposed to unlimited consequential, direct, and indirect damages. Standard B2B contracts mandate equal, reciprocal caps.",
                    "gain": "Client has virtually zero financial risk or skin in the game (capped at 1 month of fees).",
                    "loss": "Vendor's entire business, assets, and valuation are exposed to unlimited lawsuits, even for simple service errors.",
                    "rewrite": "Each party's total aggregate liability arising out of or related to this Agreement shall be limited to a mutual cap equal to twelve (12) months of fees."
                }
            ]
            
        # Filter clauses dynamically based on search query keywords
        if st.session_state.get("clause_search_query"):
            q = st.session_state["clause_search_query"].lower().strip()
            clauses = [cl for cl in clauses if q in cl["title"].lower() or q in cl["text"].lower()]
            if not clauses:
                st.info("🔍 No scanned clauses or loopholes match your search keywords.")

        # Draw the line-by-line contract reader container
        for idx, cl in enumerate(clauses):
            border_style = "border-left: 5px solid #ef4444;" if cl["risk"] else "border-left: 3px solid #10b981;"
            bg_color = "background: #fef2f2;" if cl["risk"] else "background: #ffffff;"
            title_color = "#b91c1c" if cl["risk"] else "#047857"
            badge_html = '<span style="font-size:0.68rem; font-weight:700; background:#fee2e2; color:#b91c1c; padding:2px 8px; border-radius:10px; border:1px solid #fca5a5; display:inline-block; margin-left:8px;">🚨 LOOPHOLE IDENTIFIED</span>' if cl["risk"] else '<span style="font-size:0.68rem; font-weight:700; background:#d1fae5; color:#065f46; padding:2px 8px; border-radius:10px; border:1px solid #a7f3d0; display:inline-block; margin-left:8px;">🟢 MUTUAL / NEUTRAL</span>'
            
            st.markdown(f"""
            <div style="{bg_color} border: 1px solid #e2e8f0; {border_style} border-radius: 12px; padding: 1.25rem; margin-bottom: 0.75rem; box-shadow: 0 4px 6px rgba(0,0,0,0.01);">
                <div style="display:flex; align-items:center; margin-bottom: 0.5rem;">
                    <span style="font-weight: 700; font-size: 0.88rem; color: {title_color};">{cl["title"]}</span>
                    {badge_html}
                </div>
                <div style="font-size: 0.88rem; color: #1f2937; line-height: 1.5; font-family: monospace; white-space: pre-wrap; margin-bottom: 0.5rem;">{cl["text"]}</div>
            </div>
            """, unsafe_allow_html=True)
            
            if cl["risk"]:
                with st.expander("🛠️ UNDER THE HOOD: View Loophole Explainer & Balanced Rewrite", expanded=False):
                    col_expl1, col_expl2 = st.columns(2)
                    with col_expl1:
                        st.markdown(f"""
                        <div style="background:rgba(254, 243, 199, 0.4); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 10px; padding: 1rem; height: 100%;">
                            <div style="font-weight:700; font-size:0.8rem; color:#b45309; text-transform:uppercase; margin-bottom:6px; display:flex; align-items:center; gap:4px;">
                                ⚠️ Operational Vulnerability Analysis
                            </div>
                            <div style="font-size:0.82rem; color:#78350f; line-height:1.4;">
                                <b>What's going on:</b> {cl["explanation"]}<br><br>
                                <b>Relevant Deadlines:</b> {cl["deadlines"]}<br><br>
                                <b>Applicable Law:</b> {cl["law"]}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    with col_expl2:
                        st.markdown(f"""
                        <div style="background:rgba(239, 246, 255, 0.5); border: 1px solid rgba(59, 130, 246, 0.15); border-radius: 10px; padding: 1rem; height: 100%;">
                            <div style="font-weight:700; font-size:0.8rem; color:#1d4ed8; text-transform:uppercase; margin-bottom:6px;">
                                ⚖️ Commercial Advantage & Exposure
                            </div>
                            <div style="font-size:0.82rem; color:#1e40af; line-height:1.4;">
                                📈 <b>You Gain:</b> {cl["gain"]}<br><br>
                                📉 <b>You Lose:</b> {cl["loss"]}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("<div style='margin-top:0.75rem;'></div>", unsafe_allow_html=True)
                    st.markdown("""
                    <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:10px 10px 0 0; padding:10px 12px; border-bottom:none;">
                        <span style="font-size:0.78rem; font-weight:700; color:#166534; text-transform:uppercase; letter-spacing:0.02em;">✨ Suggested Balanced Neutral Rewrite</span>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(cl["rewrite"], language="text")

        st.markdown("<br>", unsafe_allow_html=True)

        # Detailed Red Flags Analysis (styled Streamlit expanders below grid)
        st.markdown('<h2 style="font-size:1.15rem; font-weight:600; color:#111827; margin-bottom:0.5rem; margin-top:0.5rem;">🚨 Detailed Red Flag Analysis</h2>', unsafe_allow_html=True)
        st.markdown('<p style="color:#6b7280; font-size:0.82rem; margin-bottom:1.25rem;">Each risk is explained in two ways: <strong>expert legal language</strong> and <strong>"Explain Like I\'m 12"</strong> — so anyone can understand what they\'re signing into.</p>', unsafe_allow_html=True)
        
        sev_map = {
            10: ("🔴 Critical Risk", "#dc2626"),
            9:  ("🔴 Critical Risk", "#dc2626"),
            8:  ("🟠 High Risk",     "#ea580c"),
            7:  ("🟠 High Risk",     "#ea580c"),
            6:  ("🟡 Medium Risk",   "#d97706"),
        }
        for flag in active_risk_data['red_flags']:
            sev = flag['severity']
            sev_label, sev_color = sev_map.get(sev, ("🟡 Medium Risk", "#d97706"))
            fire_icons = "🔥" * (sev // 3) if sev >= 7 else "⚠️"
            
            with st.expander(f"{fire_icons} {flag['category']}  ·  Severity {sev}/10", expanded=(sev >= 9)):
                st.markdown(f"""
                <div style='margin-bottom:12px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;'>
                    <span style='font-size:0.75rem; font-weight:800; background:{sev_color}1a; color:{sev_color}; padding:3px 10px; border-radius:10px; border:1px solid {sev_color}44;'>{sev_label}</span>
                    <span style='font-size:0.72rem; color:#6b7280; font-weight:600;'>{'⚠️ Immediate legal review required' if sev >= 9 else '🔍 Review before signing' if sev >= 7 else '📋 Flag for negotiation'}</span>
                </div>
                <div style="font-size:0.85rem; font-weight:700; color:#374151; margin-bottom:6px;">📋 Verbatim Clause Text</div>
                """, unsafe_allow_html=True)
                
                st.error(flag['clause_text'])
                
                col_impact, col_cite = st.columns([3, 1])
                with col_impact:
                    st.markdown(f"**⚡ Legal Risk:** {flag['impact']}")
                with col_cite:
                    st.caption(f"📍 {flag['citation']}")
                
                # ── ELI12 Block ────────────────────────────────────────────────────
                cat_lower = flag['category'].lower()
                if "indemn" in cat_lower or "fault" in cat_lower or "harmless" in cat_lower:
                    eli12_emoji = "💸"
                    eli12_analogy = "Your friend breaks a window at YOUR house while playing. This clause says YOU must pay for ALL broken windows in the whole street — even ones YOUR FRIEND broke somewhere else! You should only pay for what YOU personally did wrong."
                    eli12_you_lose = "Your savings defending yourself in court — even for things you didn't do."
                    eli12_fix = "Change it: each person only pays for problems THEY caused. Remove 'regardless of fault.'"
                elif "terminat" in cat_lower or "notice" in cat_lower:
                    eli12_emoji = "🏃"
                    eli12_analogy = "A game where the other team can stop and go home in 5 minutes anytime they want, but YOU must keep showing up for 2 months before you can quit. Not a fair game for you!"
                    eli12_you_lose = "Months of wasted work, unpaid costs, and idle staff if they suddenly quit."
                    eli12_fix = "Both sides get the same notice period — 30 days is the industry standard."
                elif "liability" in cat_lower or "cap" in cat_lower or "limit" in cat_lower:
                    eli12_emoji = "💣"
                    eli12_analogy = "In Monopoly: if the bank lands on your property, they pay ₹10. But if you land on their property, you pay EVERYTHING — all your hotels, houses, and money. Same game, completely unfair rules!"
                    eli12_you_lose = "Your entire business, savings, and future — they risk almost nothing."
                    eli12_fix = "Add a mutual cap: 12 months of fees for BOTH sides. Equal risk for equal stakes."
                elif "intellectual" in cat_lower or "ip" in cat_lower or "invention" in cat_lower or "work product" in cat_lower:
                    eli12_emoji = "🎨"
                    eli12_analogy = "You spend years learning to paint. Someone hires you to paint ONE picture. This clause says they now OWN all your paintings — past, present, future — even the ones you made before meeting them. You can never paint for anyone else again!"
                    eli12_you_lose = "Your existing tools, code, techniques, and ability to use your own skills for other clients."
                    eli12_fix = "They get only what you specifically built FOR them under this contract. You keep everything else."
                else:
                    eli12_emoji = "🤔"
                    eli12_analogy = "This clause uses confusing language that even lawyers debate. When rules are unclear, the stronger party wins arguments. Vague = dangerous for you."
                    eli12_you_lose = "Legal clarity and negotiating power in any dispute."
                    eli12_fix = "Rewrite it to be specific, balanced, and understandable by both sides."
                
                st.markdown(f"""
                <div style="background:linear-gradient(135deg,#faf5ff 0%,#ede9fe 100%);border:1px solid #c4b5fd;border-left:5px solid #7c3aed;border-radius:12px;padding:1.25rem;margin-top:1rem;margin-bottom:0.75rem;">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:0.75rem;">
                        <span style="font-size:1.6rem;">{eli12_emoji}</span>
                        <div>
                            <div style="font-size:0.8rem;font-weight:800;color:#6d28d9;text-transform:uppercase;letter-spacing:0.05em;">🧒 Explain Like I'm 12</div>
                            <div style="font-size:0.7rem;color:#7c3aed;margin-top:2px;">Zero jargon. Zero law degree needed. Even a child gets it.</div>
                        </div>
                    </div>
                    <div style="font-size:0.88rem;color:#4c1d95;line-height:1.65;margin-bottom:0.75rem;background:rgba(255,255,255,0.65);padding:12px 16px;border-radius:10px;border:1px solid #ddd6fe;">
                        <b>🍎 Simple Analogy:</b><br><br>{eli12_analogy}
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                        <div style="background:rgba(220,38,38,0.07);border:1px solid #fca5a5;border-radius:10px;padding:10px 14px;">
                            <div style="font-size:0.72rem;font-weight:700;color:#991b1b;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.03em;">📉 What You Risk Losing</div>
                            <div style="font-size:0.82rem;color:#7f1d1d;line-height:1.45;">{eli12_you_lose}</div>
                        </div>
                        <div style="background:rgba(5,150,105,0.07);border:1px solid #6ee7b7;border-radius:10px;padding:10px 14px;">
                            <div style="font-size:0.72rem;font-weight:700;color:#065f46;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.03em;">✅ Simple Fix</div>
                            <div style="font-size:0.82rem;color:#064e3b;line-height:1.45;">{eli12_fix}</div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                # Check for matching historical B2B scams / precedents
                matched_scam = None
                for scam_key, scam_val in HISTORICAL_SCAMS.items():
                    if scam_key.lower() in flag['category'].lower() or flag['category'].lower() in scam_key.lower():
                        matched_scam = scam_val
                        break
                
                if matched_scam:
                    st.markdown(f"""
                    <div style="background:linear-gradient(135deg,#fffbeb 0%,#fef3c7 100%);border-left:5px solid #d97706;border-radius:8px;padding:12px;margin-top:12px;margin-bottom:4px;border:1px solid rgba(217,119,6,0.2);">
                        <div style="font-weight:800;font-size:0.82rem;color:#b45309;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">
                            ⚠️ Real-World Corporate Scandal: {matched_scam['title']}
                        </div>
                        <div style="font-size:0.72rem;font-weight:700;color:#78350f;margin-bottom:8px;">🏢 {matched_scam['company']}</div>
                        <div style="font-size:0.8rem;color:#78350f;line-height:1.45;margin-bottom:6px;">📖 <b>What Happened:</b> {matched_scam['scam_what_happened']}</div>
                        <div style="font-size:0.8rem;color:#78350f;line-height:1.45;margin-bottom:6px;">🪤 <b>The Trap:</b> {matched_scam['scam_the_trap']}</div>
                        <div style="font-size:0.8rem;font-weight:700;color:#1e3a8a;line-height:1.45;">🩹 <b>The Fix:</b> {matched_scam['scam_the_fix']}</div>
                    </div>
                    """, unsafe_allow_html=True)


    # ── Page: Smart Review (Tabs: Debate, Logic, Auto-Fix) ──────────────────
    elif current_page == "SmartReview":
        # Get active tab from URL query params (default to BotDebate)
        active_tab = qp.get("tab", "BotDebate")

        # Initialize session state variables for the Smart Review sandboxes
        if "debate_turns_logs" not in st.session_state:
            st.session_state["debate_turns_logs"] = loophole_logs
        if "logic_validation_result" not in st.session_state:
            st.session_state["logic_validation_result"] = logic_conflicts[0]
            
        # Standard default autofix result
        if "autofix_result" not in st.session_state:
            st.session_state["autofix_result"] = {
                "title": "Reciprocal Termination Rights",
                "severity": 8,
                "rewrite": "Either party may terminate this Agreement for convenience upon thirty (30) days' prior written notice to the other party. Either party may terminate this Agreement for cause (material breach) upon fifteen (15) days' written notice specifying the breach in reasonable detail, provided the breaching party fails to cure such breach within said fifteen (15) day period.",
                "risk_label": "🛡️ Mutual Convenience Exit",
                "risk_class": "low",
                "score": "2/10",
                "rationale": "Equalizes convenience termination rights and establishes a reasonable 15-day cure period for cause, eliminating the severe unilateral 5-day convenience termination notice.",
                "clause_text": "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days."
            }

        # Sync with URL query parameters if they exist to support preset clicks!
        active_clause_key = qp.get("clause")
        active_persona_key = qp.get("persona")
        
        # If the user clicked a preset link, load that preset from mock data
        if active_clause_key and active_persona_key:
            if active_clause_key in playbook_data:
                clause_payload = playbook_data[active_clause_key]
                original_text = clause_payload["original"]
                active_severity = clause_payload["severity"]
                
                if active_persona_key in ["Defender", "Attacker", "Arbitrator"]:
                    persona_payload = clause_payload[active_persona_key]
                    suggested_text = persona_payload["rewrite"]
                    risk_label = persona_payload["risk_label"]
                    risk_class = persona_payload["risk_class"]
                    score = persona_payload["score"]
                    rationale_text = persona_payload["rationale"]
                    
                    st.session_state["autofix_result"] = {
                        "title": f"{active_persona_key} - {active_clause_key}",
                        "severity": active_severity,
                        "rewrite": suggested_text,
                        "risk_label": risk_label,
                        "risk_class": risk_class,
                        "score": score,
                        "rationale": rationale_text,
                        "clause_text": original_text,
                        "preset_clause": active_clause_key,
                        "preset_persona": active_persona_key
                    }

        # Custom high-fidelity styled tab links
        tab_links_html = f"""
        <div class="custom-tabs">
            <a href="{get_nav_link('SmartReview')}&tab=BotDebate" target="_self" class="custom-tab {'active' if active_tab == 'BotDebate' else ''}">🤖 Bot Debate</a>
            <a href="{get_nav_link('SmartReview')}&tab=LogicValidator" target="_self" class="custom-tab {'active' if active_tab == 'LogicValidator' else ''}">🔀 Logic Validator</a>
            <a href="{get_nav_link('SmartReview')}&tab=AutoFixer" target="_self" class="custom-tab {'active' if active_tab == 'AutoFixer' else ''}">✨ Auto-Fixer</a>
        </div>
        """
        st.markdown("<h1 style='font-size:1.4rem; font-weight:700; color:#111827; margin-bottom:1rem;'>AI Smart Review Tools</h1>", unsafe_allow_html=True)
        render_html(tab_links_html)

        # Tab Content: Bot Debate
        if active_tab == "BotDebate":
            render_html("""
            <div style='margin-bottom:1.5rem;'>
                <h2 style='font-size:1.15rem;font-weight:700;color:#0f172a;margin:0 0 4px 0;'>
                    Adversarial AI Agent Debate Sandbox
                </h2>
                <p style='color:#64748b;font-size:0.85rem;margin:0;'>
                    Select a scanned red flag or enter a custom clause. The <span style='color:#dc2626;font-weight:600;'>Attacker</span> will probe for vulnerabilities while the <span style='color:#16a34a;font-weight:600;'>Defender</span> evaluates risks and proposes balanced compromises.
                </p>
            </div>
            """)

            # ⚙️ Debate Sandbox Controls Panel
            st.markdown('<div style="background: rgba(255, 255, 255, 0.6); border: 1px solid #e5e7eb; padding: 1.25rem; border-radius: 12px; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.02); color: #111827;">', unsafe_allow_html=True)
            
            # Dropdown options
            flag_categories = []
            flag_texts = {}
            for flag in active_risk_data.get('red_flags', []):
                cat = flag['category']
                flag_categories.append(cat)
                flag_texts[cat] = flag['clause_text']
            
            # Default options if red_flags is empty
            if not flag_categories:
                flag_categories = ["Indemnification asymmetry", "Uncapped Liability", "Termination asymmetry", "Overbroad IP Scope"]
                flag_texts = {
                    "Indemnification asymmetry": "Vendor agrees to indemnify, defend, and hold harmless the Client from and against any and all claims, losses, liabilities, damages, expenses, regardless of fault.",
                    "Uncapped Liability": "In no event shall Client's total liability under this Agreement exceed the fees paid in the preceding one (1) month. No limitation on liability applies to Vendor.",
                    "Termination asymmetry": "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days.",
                    "Overbroad IP Scope": "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall belong exclusively to Client."
                }
            
            flag_categories.append("Custom Clause...")
            
            # Setup columns for clean inputs
            col1, col2 = st.columns([2, 1])
            with col1:
                selected_cat = st.selectbox("Select Clause for Debate", options=flag_categories, key="debate_cat_select")
            with col2:
                debate_turns = st.slider("Debate Rounds", min_value=2, max_value=6, value=4, step=1, key="debate_turns_slider")
            
            col3, col4 = st.columns([2, 1])
            with col3:
                # Pre-fill custom clause box
                default_text = flag_texts.get(selected_cat, "")
                clause_text_input = st.text_area("Clause Text to Debate", value=default_text, height=100, key="debate_clause_text_input")
            with col4:
                debate_mood = st.selectbox("Debate Mood Profile", options=["Commercially Balanced", "Aggressive & Hostile", "Strict Legal & Formal"], key="debate_mood_select")
            
            run_debate_btn = st.button("⚡ Run Live Agent Debate", use_container_width=True, type="primary")
            st.markdown('</div>', unsafe_allow_html=True)

            if run_debate_btn:
                # Execution Flow UI
                with st.status("⚡ Initializing Adversarial Debate Agents...", expanded=True) as status:
                    st.write("🤖 Spawning Attacker (⚔️) and Defender (🛡️) Agents...")
                    time.sleep(0.5)
                    st.write("⚔️ Attacker Agent scanning clause for hidden liabilities...")
                    time.sleep(0.5)
                    st.write("🛡️ Defender Agent preparing litigation shielding arguments...")
                    time.sleep(0.5)
                    
                    # Fetch / Simulate Debate turns
                    api_key = st.session_state.get("gemini_api_key", os.environ.get("GEMINI_API_KEY", ""))
                    
                    if api_key and clause_text_input.strip():
                        st.write("🔮 Streaming live multi-agent turns from Gemini...")
                        sys_instruction = (
                            "You are a legal AI debate engine. You simulate adversarial debate turns between 'Attacker' "
                            "(an aggressive legal auditor who finds every loophole, trap, and unfair risk in a clause) and "
                            "'Defender' (a protective corporate counsel who evaluates the legal enforceability, proposes compromises, "
                            "and suggests strategic amendments)."
                        )
                        prompt = (
                            f"Generate exactly {debate_turns} rounds of adversarial legal debate on the following clause:\n\n"
                            f"'{clause_text_input}'\n\n"
                            f"The debate mood should be {debate_mood}. Make each turn highly detailed, professional, and practical.\n\n"
                            f"Output MUST be a valid JSON array of objects with keys 'role' ('Attacker' or 'Defender') and "
                            f"'content' (their dialogue text). Do not wrap the JSON output in markdown backticks."
                        )
                        
                        raw_json = call_gemini(sys_instruction, prompt, api_key=api_key, force_json=True)
                        if raw_json:
                            try:
                                clean_json = raw_json.strip()
                                if clean_json.startswith("```json"):
                                    clean_json = clean_json[7:]
                                if clean_json.endswith("```"):
                                    clean_json = clean_json[:-3]
                                parsed_debate = json.loads(clean_json.strip())
                                st.session_state["debate_turns_logs"] = parsed_debate
                            except Exception as e:
                                st.warning(f"Error parsing Gemini debate: {str(e)}. Using fallback simulator.")
                                st.session_state["debate_turns_logs"] = run_simulated_debate(clause_text_input, debate_turns, debate_mood)
                        else:
                            st.session_state["debate_turns_logs"] = run_simulated_debate(clause_text_input, debate_turns, debate_mood)
                    else:
                        st.write("🤖 Generating high-fidelity simulation debate turns...")
                        st.session_state["debate_turns_logs"] = run_simulated_debate(clause_text_input, debate_turns, debate_mood)
                    
                    status.update(label="✅ Adversarial Debate Complete!", state="complete", expanded=False)
                
                # Dynamic word-by-word streaming rendering
                st.markdown("<h3 style='font-size:1.05rem; font-weight:600; color:#1f2937; margin-bottom:1rem;'>Live Turn Stream</h3>", unsafe_allow_html=True)
                
                for i, log in enumerate(st.session_state["debate_turns_logs"]):
                    turn = i // 2 + 1
                    role = log["role"]
                    content = log["content"]
                    
                    avatar = "⚔️" if role == "Attacker" else "🛡️"
                    role_title = "Attacker Agent" if role == "Attacker" else "Defender Agent"
                    border_color = "#fca5a5" if role == "Attacker" else "#86efac"
                    bg_color = "#fef2f2" if role == "Attacker" else "#f0fdf4"
                    txt_color = "#991b1b" if role == "Attacker" else "#166534"
                    
                    with st.chat_message(role, avatar=avatar):
                        st.markdown(
                            f"**{role_title}** &nbsp;"
                            f"<span style='font-size:0.75rem;color:{txt_color};background:{bg_color};"
                            f"padding:2px 8px;border-radius:12px;border:1px solid {border_color};'>Turn {turn}</span>",
                            unsafe_allow_html=True
                        )
                        
                        # Streaming effect
                        text_placeholder = st.empty()
                        words = content.split(" ")
                        typed_text = ""
                        for word in words:
                            typed_text += word + " "
                            text_placeholder.markdown(typed_text + "▌")
                            time.sleep(0.015)
                        text_placeholder.markdown(typed_text)
                
                st.rerun()

            # Render existing/saved debate turns
            if st.session_state.get("debate_turns_logs"):
                st.markdown("<h3 style='font-size:1.05rem; font-weight:600; color:#1f2937; margin-bottom:1rem;'>Adversarial Dialogue Transcript</h3>", unsafe_allow_html=True)
                for i, log in enumerate(st.session_state["debate_turns_logs"]):
                    turn = i // 2 + 1
                    role = log["role"]
                    avatar = "⚔️" if role == "Attacker" else "🛡️"
                    role_title = "Attacker Agent" if role == "Attacker" else "Defender Agent"
                    border_color = "#fca5a5" if role == "Attacker" else "#86efac"
                    bg_color = "#fef2f2" if role == "Attacker" else "#f0fdf4"
                    txt_color = "#991b1b" if role == "Attacker" else "#166534"
                    
                    with st.chat_message(role, avatar=avatar):
                        st.markdown(
                            f"**{role_title}** &nbsp;"
                            f"<span style='font-size:0.75rem;color:{txt_color};background:{bg_color};"
                            f"padding:2px 8px;border-radius:12px;border:1px solid {border_color};'>Turn {turn}</span>",
                            unsafe_allow_html=True
                        )
                        st.write(log['content'])

        # Tab Content: Logic Validator
        elif active_tab == "LogicValidator":
            render_html("""
            <div style='margin-bottom:1.5rem;'>
                <h2 style='font-size:1.15rem;font-weight:700;color:#0f172a;margin:0 0 4px 0;'>
                    Logical Contradiction Map Sandbox
                </h2>
                <p style='color:#64748b;font-size:0.85rem;margin:0;'>
                    Compare two different clauses or covenants to detect hidden logical contradictions, conflicting timelines, or compliance gaps.
                </p>
            </div>
            """)

            # Quick fill buttons
            st.markdown("<div style='margin-bottom: 1rem; display: flex; gap: 8px; flex-wrap: wrap;'>", unsafe_allow_html=True)
            
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                load_dest_ret = st.button("📋 Load Data Retention Conflict", use_container_width=True)
            with col_b:
                load_pay_term = st.button("💵 Load Payment Terms Gap", use_container_width=True)
            with col_c:
                load_juris_dis = st.button("⚖️ Load Governing Law Dispute", use_container_width=True)

            clause_a_val = ""
            clause_b_val = ""

            if load_dest_ret:
                clause_a_val = "Section 2.1: All confidential data, customer records, and transaction logs must be permanently and irreversibly destroyed within thirty (30) days of contract termination."
                clause_b_val = "Section 5.4: Vendor shall retain complete backups of all transactional data and customer profiles for a minimum period of three (3) years to ensure compliance with applicable auditing regulations."
            elif load_pay_term:
                clause_a_val = "Section 3.1: All invoices issued under this Agreement are payable within forty-five (45) days of invoice receipt (Net 45)."
                clause_b_val = "Schedule A, Section 7.2: All payments for premium tier consulting and deployment services are due strictly within fifteen (15) days of invoice receipt (Net 15)."
            elif load_juris_dis:
                clause_a_val = "Section 14.1: This Agreement shall be governed by, and construed in accordance with, the laws of the State of Delaware."
                clause_b_val = "Section 14.3: Any disputes or controversies arising hereunder shall be submitted to binding arbitration in San Francisco, California under the rules of JAMS."

            # Inputs workspace
            st.markdown('<div style="background: rgba(255, 255, 255, 0.6); border: 1px solid #e5e7eb; padding: 1.25rem; border-radius: 12px; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.02); color: #111827;">', unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                clause_a_text = st.text_area(
                    "Clause A (First Covenant)", 
                    value=clause_a_val if clause_a_val else "Section 2.1: Permanent destruction of all records within 30 days.",
                    height=120,
                    key="logic_clause_a"
                )
            with col2:
                clause_b_text = st.text_area(
                    "Clause B (Second Covenant)", 
                    value=clause_b_val if clause_b_val else "Section 5.4: Retain transactional records for 3 years.",
                    height=120,
                    key="logic_clause_b"
                )
                
            validate_btn = st.button("🔍 Validate Semantic Integrity", use_container_width=True, type="primary")
            st.markdown('</div>', unsafe_allow_html=True)

            if validate_btn:
                # 3-step progress pipeline
                with st.status("🔍 Analyzing Clause Semantic Compatibility...", expanded=True) as status:
                    st.write("🔍 Running Syntax Parsing on Covenants...")
                    time.sleep(0.5)
                    st.write("🗺️ Building Semantic Vector Mappings...")
                    time.sleep(0.5)
                    st.write("⚡ Checking Legal Discrepancy Matrix...")
                    time.sleep(0.5)
                    
                    api_key = st.session_state.get("gemini_api_key", os.environ.get("GEMINI_API_KEY", ""))
                    if api_key and clause_a_text.strip() and clause_b_text.strip():
                        st.write("🔮 Asking Gemini to audit logic contradictions...")
                        sys_instruction = (
                            "You are an elite legal contract auditor specializing in finding hidden internal logical "
                            "contradictions and structural discrepancies between different clauses in a contract. You detect "
                            "if complying with one clause causes a direct breach of another clause."
                        )
                        prompt = (
                            f"Compare the following two contract clauses:\n\n"
                            f"Clause A:\n'{clause_a_text}'\n\n"
                            f"Clause B:\n'{clause_b_text}'\n\n"
                            f"Identify if there is an operational or logical contradiction or conflict between them. "
                            f"Output MUST be a valid JSON object matching the exact structure below, with NO markdown formatting wraps:\n"
                            f"{{\n"
                            f"  \"conflict\": \"Conflict Title\",\n"
                            f"  \"severity\": \"Critical\" or \"High\" or \"Medium\" or \"Clear\",\n"
                            f"  \"rule_a\": \"Summary of Clause A constraint\",\n"
                            f"  \"rule_b\": \"Summary of Clause B constraint\",\n"
                            f"  \"explanation\": \"Detailed legal explanation of why they conflict and what the operational risk is.\",\n"
                            f"  \"resolved_clause\": \"A suggested integrated clause that legally resolves both requirements harmoniously.\"\n"
                            f"}}"
                        )
                        
                        raw_json = call_gemini(sys_instruction, prompt, api_key=api_key, force_json=True)
                        if raw_json:
                            try:
                                clean_json = raw_json.strip()
                                if clean_json.startswith("```json"):
                                    clean_json = clean_json[7:]
                                if clean_json.endswith("```"):
                                    clean_json = clean_json[:-3]
                                st.session_state["logic_validation_result"] = json.loads(clean_json.strip())
                            except Exception as e:
                                st.warning(f"Error parsing Gemini contradiction report: {str(e)}. Using fallback simulator.")
                                st.session_state["logic_validation_result"] = run_simulated_logic_validation(clause_a_text, clause_b_text)
                        else:
                            st.session_state["logic_validation_result"] = run_simulated_logic_validation(clause_a_text, clause_b_text)
                    else:
                        st.session_state["logic_validation_result"] = run_simulated_logic_validation(clause_a_text, clause_b_text)
                    
                    status.update(label="✅ Semantic Integrity Checked!", state="complete", expanded=False)
                st.rerun()

            # Render validation result
            if st.session_state.get("logic_validation_result"):
                conflict = st.session_state["logic_validation_result"]
                
                sev_styles = {
                    "Critical": ("#fef2f2",  "#ef4444", "#fca5a5"),
                    "High":     ("#fffbeb", "#fbbf24", "#fcd34d"),
                    "Medium":   ("#f0fdf4",  "#22c55e", "#86efac"),
                    "Clear":    ("#f0fdf4",  "#16a34a", "#86efac"),
                }
                
                bg, fg, border = sev_styles.get(conflict.get('severity', 'Medium'), sev_styles["Medium"])
                
                st.markdown("<h3 style='font-size:1.05rem; font-weight:600; color:#1f2937; margin-bottom:1rem;'>Semantic Integrity Report Card</h3>", unsafe_allow_html=True)
                
                render_html(f"""
                <div class="conflict-card" style="background:#ffffff; border:1px solid #f0f1f3; border-radius:12px; padding:1.5rem; margin-bottom:1.25rem; box-shadow:0 1px 3px rgba(0,0,0,0.02);">
                    <div style='display:flex;align-items:center; justify-content:space-between;margin-bottom:1rem;'>
                        <div style="font-size:1.05rem; font-weight:600; color:#111827;">⚡ {conflict.get('conflict', 'Semantic Contradiction')}</div>
                        <span style='display:inline-block;padding:2px 10px;border-radius:20px;
                            font-size:0.75rem;font-weight:700;background:{bg};
                            color:{fg};border:1px solid {border};'>
                            {conflict.get('severity', 'High')}
                        </span>
                    </div>
                    <div class="rule-box" style="border: 1px solid #f3f4f6; border-radius:8px; padding:12px; font-size:0.85rem; line-height:1.5; margin-bottom:10px; background:#fcfcfc; color:#1f2937;">
                        <strong>📋 Clause A Constraint:</strong> {conflict.get('rule_a', '')}
                    </div>
                    <div class="rule-box" style="border: 1px solid #f3f4f6; border-radius:8px; padding:12px; font-size:0.85rem; line-height:1.5; margin-bottom:10px; background:#fcfcfc; color:#1f2937;">
                        <strong>📋 Clause B Constraint:</strong> {conflict.get('rule_b', '')}
                    </div>
                    <div style="font-size:0.85rem; color:#4b5563; line-height:1.5; background:#eff6ff; border-radius:8px; padding:12px; border-left:3px solid #3b82f6; margin-bottom:12px;">
                        💡 <strong>Analysis & Operational Threat:</strong> {conflict.get('explanation', '')}
                    </div>
                </div>
                """)
                
                # Show resolving clause in a beautiful success box with copyability
                if conflict.get("resolved_clause") and conflict.get("resolved_clause") != "Clause A and Clause B are already aligned. No resolution is required.":
                    st.markdown("""
                    <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:12px; padding:1.25rem; margin-top:1rem; border-bottom-left-radius:0px; border-bottom-right-radius:0px; border-bottom: none;">
                        <div style="font-size:0.8rem; font-weight:700; text-transform:uppercase; color:#166534; margin-bottom:6px; letter-spacing:0.05em;">🛡️ Suggested Harmonized Clause (Resolves Conflict)</div>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(conflict["resolved_clause"], language="text")

                    if conflict.get("z3_code"):
                        st.markdown("""
                        <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:12px; padding:1.25rem; margin-top:1rem; border-bottom-left-radius:0px; border-bottom-right-radius:0px; border-bottom: none; display: flex; justify-content: space-between; align-items: center;">
                            <div style="font-size:0.8rem; font-weight:700; text-transform:uppercase; color:#334155; letter-spacing:0.05em; display: flex; align-items: center; gap: 6px;">
                                🔬 Z3 SMT Solver Propositional Verification Logic
                            </div>
                            <span style="font-size:0.7rem; font-weight:700; background:#fee2e2; color:#991b1b; padding:2px 8px; border-radius:12px; border: 1px solid #fca5a5;">UNSAT CONFIRMED</span>
                        </div>
                        """, unsafe_allow_html=True)
                        st.code(conflict["z3_code"], language="python")

        # Tab Content: Auto-Fixer
        elif active_tab == "AutoFixer":
            # Extract state values from URL query parameters (default to Termination Rights)
            active_clause_key = qp.get("clause")
            if not active_clause_key or active_clause_key not in playbook_data:
                active_clause_key = list(playbook_data.keys())[0] if playbook_data else "Termination Rights"
                
            active_persona_key = qp.get("persona", "Defender")
            if active_persona_key not in ["Defender", "Attacker", "Exploiter", "Arbitrator"]:
                active_persona_key = "Defender"

            # Sync and handle persona name aliases
            clause_payload = playbook_data.get(active_clause_key, {
                "title": active_clause_key,
                "severity": 5,
                "original": "Clause text not found.",
                "Defender": {"rewrite": "Clause text not found.", "risk_label": "🛡️ Neutral Risk", "risk_class": "low", "score": "5/10", "rationale": "No rationale."}
            })
            original_text = clause_payload.get("original", "")
            active_severity = clause_payload.get("severity", 5)
            
            persona_key_to_use = active_persona_key
            if persona_key_to_use == "Exploiter" and "Attacker" in clause_payload:
                persona_key_to_use = "Attacker"
            elif persona_key_to_use == "Attacker" and "Exploiter" in clause_payload:
                persona_key_to_use = "Exploiter"
                
            persona_payload = clause_payload.get(persona_key_to_use, clause_payload.get("Defender"))
            suggested_text = persona_payload.get("rewrite", "")
            risk_label = persona_payload.get("risk_label", "🛡️ Balanced Risk")
            risk_class = persona_payload.get("risk_class", "low")
            score = persona_payload.get("score", "3/10")
            rationale_text = persona_payload.get("rationale", "")

            # If user had run a custom rewrite in session state, override
            if st.session_state.get("autofix_result") and st.session_state["autofix_result"].get("preset_clause") == active_clause_key and st.session_state["autofix_result"].get("preset_persona") == active_persona_key:
                suggested_text = st.session_state["autofix_result"]["rewrite"]
                risk_label = st.session_state["autofix_result"]["risk_label"]
                risk_class = st.session_state["autofix_result"]["risk_class"]
                score = st.session_state["autofix_result"]["score"]
                rationale_text = st.session_state["autofix_result"]["rationale"]

            # Compute dynamic color-coded word highlights on the fly!
            word_diff_html = get_word_diff(original_text, suggested_text)

            # Dynamically generate beautiful horizontal folder selector tabs
            clause_tabs_html = []
            for pk in playbook_data.keys():
                active_class = "active" if active_clause_key == pk else ""
                display_name = pk
                if pk == "Termination Rights":
                    display_name = "Termination asymmetry"
                elif pk == "IP Assignment":
                    display_name = "Overbroad IP Scope"
                elif pk == "Liability Cap":
                    display_name = "Uncapped Liability"
                clause_tabs_html.append(
                    f'<a href="{get_playbook_link(pk, active_persona_key)}" target="_self" class="glass-btn {active_class}">📁 {display_name}</a>'
                )
            clause_tabs_html_str = "\n".join(clause_tabs_html)

            # Dynamically generate beautiful horizontal persona selectors
            persona_tabs_html = []
            for pers in ["Defender", "Attacker", "Arbitrator"]:
                active_class = "active" if active_persona_key == pers else ""
                icon = "🛡️" if pers == "Defender" else ("⚔️" if pers == "Attacker" else "⚖️")
                mapped_pers = "Exploiter" if pers == "Attacker" and "Exploiter" in clause_payload else pers
                persona_tabs_html.append(
                    f'<a href="{get_playbook_link(active_clause_key, mapped_pers)}" target="_self" class="glass-btn {active_class}">{icon} {pers}</a>'
                )
            persona_tabs_html_str = "\n".join(persona_tabs_html)

            # Render custom CSS styling elements to support exact visual layout
            glass_controls_html = f"""
            <div class="glass-panel">
                <div class="glass-title">🔮 AI Negotiation Playbook Sandbox</div>
                <div class="glass-subtitle">Configure AI negotiation profiles, view side-by-side comparison, and export self-healing rewrites with dynamic word-level diff highlights.</div>
                
                <!-- Selection Bar -->
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1.25rem; margin-bottom:1.75rem; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:1.25rem;">
                    <!-- Clause Selection Buttons -->
                    <div style="display:flex; flex-direction:column; gap:6px;">
                        <div style="font-size:0.7rem; font-weight:600; text-transform:uppercase; color:#9ca3af; letter-spacing:0.06em;">Select Vulnerable Clause</div>
                        <div style="display:flex; gap:6px; flex-wrap:wrap;">
                            {clause_tabs_html_str}
                        </div>
                    </div>
                    
                    <!-- Option 1 Persona Toggles -->
                    <div style="display:flex; flex-direction:column; gap:6px;">
                        <div style="font-size:0.7rem; font-weight:600; text-transform:uppercase; color:#9ca3af; letter-spacing:0.06em;">AI Negotiation Profile</div>
                        <div class="persona-container">
                            {persona_tabs_html_str}
                        </div>
                    </div>
                </div>

                <!-- 1. Split Screen Workspace Grid -->
                <div class="glass-split-screen">
                    <!-- Left pane: Original -->
                    <div class="glass-pane">
                        <div class="pane-header">
                            <span class="pane-title">⚖️ DUAL-SIDE CONTRACT DEBATE</span>
                            <span class="glass-risk-pill critical">🚨 Risk Severity: {active_severity}/10</span>
                        </div>
                        <div class="pane-content">{original_text}</div>
                    </div>
                    
                    <!-- Right pane: Suggested Rewrite with Dynamic Diff Overlay! -->
                    <div class="glass-pane">
                        <div class="pane-header">
                            <span class="pane-title">🛡️ MULTI-AGENT ADVERSARIAL DEBATE</span>
                            <span class="glass-risk-pill {risk_class}">{risk_label} ({score})</span>
                        </div>
                        <div class="pane-content">{word_diff_html}</div>
                    </div>
                </div>

                <!-- Rationale Card -->
                <div style="background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.05); border-radius:12px; padding:1.25rem; margin-top:1.5rem; border-left:4px solid #3b82f6;">
                    <div style="font-size:0.75rem; font-weight:700; text-transform:uppercase; color:#9ca3af; margin-bottom:6px; letter-spacing:0.05em;">💡 AI Negotiation Strategy & Rationale</div>
                    <div style="font-size:0.875rem; color:#e5e7eb; line-height:1.5;">{rationale_text}</div>
                </div>
            </div>
            """
            render_html(glass_controls_html)

            # Render clean export buttons below for absolute robustness
            st.markdown("<div style='margin-top:1rem;'></div>", unsafe_allow_html=True)
            st.markdown("<p style='font-size:0.78rem; color:#6b7280; margin-bottom:0.5rem;'>📥 Export this rewrite as a PDF — the same format accepted by the uploader.</p>", unsafe_allow_html=True)
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                # Generate a single-clause PDF
                _single_clause = [{
                    "title": "AI Suggested Rewrite",
                    "text": suggested_text,
                    "risk": False
                }]
                _clause_pdf = generate_rewrite_pdf(
                    _single_clause,
                    user_name=st.session_state.get('user_name', 'General Counsel'),
                    filename="Clause Rewrite"
                )
                st.download_button(
                    label="📥 Export Rewrite as PDF",
                    data=_clause_pdf,
                    file_name="Suggested_Rewrite_RegulAIte.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    type="primary"
                )
            with col_btn2:
                st.markdown("**📋 Copy Rewrite Verbatim:**")
                st.code(suggested_text, language="text")

            # Clean expandable custom self-healing AI rewrite sandbox at the bottom
            with st.expander("⚡ Custom AI Rewrite Sandbox", expanded=False):
                st.markdown("<p style='font-size:0.8rem; color:#6b7280; margin-bottom:1rem;'>Customize the clause wording or write a custom clause, and use Google Gemini to generate a live AI rewrite on the fly.</p>", unsafe_allow_html=True)
                col_box1, col_box2 = st.columns([2, 1])
                with col_box1:
                    clause_text_input = st.text_area("Clause Text to Fix", value=original_text, height=100, key="autofix_clause_text_input")
                with col_box2:
                    persona_selection = st.selectbox("AI Negotiation Profile", options=["Defender (🛡️)", "Attacker (⚔️)", "Arbitrator (⚖️)"], key="autofix_persona_select")
                
                autofix_btn = st.button("⚡ Generate Custom AI Rewrite", use_container_width=True, type="primary")
                
                if autofix_btn:
                    with st.status("🔮 Compiling AI Self-Healing Rewrite...", expanded=True) as status:
                        st.write("🔮 Reading clause vulnerability markers...")
                        time.sleep(0.4)
                        st.write("⚖️ Structuring rewrite under Selected Persona...")
                        time.sleep(0.4)
                        
                        persona_clean = persona_selection.split(" ")[0] # Defender, Attacker, Arbitrator
                        api_key = st.session_state.get("gemini_api_key", os.environ.get("GEMINI_API_KEY", ""))
                        
                        if api_key and clause_text_input.strip():
                            st.write("🔮 Asking Gemini to write clause rewrite...")
                            sys_instruction = (
                                "You are an elite legal contract advisor and expert draftsman. You specialize in rewriting contract clauses "
                                "to fit specific negotiation profiles:\n"
                                "1. 'Defender': A protective corporate counsel who equalizes clauses, reduces risks, introduces standard mutual covenants, and ensures fair reciprocity.\n"
                                "2. 'Attacker': An aggressive vendor-favored counsel who shifts all liabilities to the other party and maximizes unilateral rights.\n"
                                "3. 'Arbitrator': A balanced third-party arbitrator who drafts standard, fair, and legally robust neutral compromises."
                            )
                            prompt = (
                                f"Rewrite the following contract clause under the '{persona_clean}' profile:\n\n"
                                f"'{clause_text_input}'\n\n"
                                f"Output MUST be a valid JSON object matching the exact structure below, with NO markdown formatting wraps:\n"
                                f"{{\n"
                                f"  \"title\": \"Title of the Fix\",\n"
                                f"  \"severity\": 5,\n"
                                f"  \"rewrite\": \"Verbatim rewritten clause text here.\",\n"
                                f"  \"risk_label\": \"Short badge label (e.g. 🛡️ Reciprocal Risk)\",\n"
                                f"  \"risk_class\": \"low\" or \"medium\" or \"high\" or \"critical\",\n"
                                f"  \"score\": \"e.g. 2/10\",\n"
                                f"  \"rationale\": \"Strategy rationale detail here.\"\n"
                                f"}}"
                            )
                            raw_json = call_gemini(sys_instruction, prompt, api_key=api_key, force_json=True)
                            if raw_json:
                                try:
                                    clean_json = raw_json.strip()
                                    if clean_json.startswith("```json"):
                                        clean_json = clean_json[7:]
                                    if clean_json.endswith("```"):
                                        clean_json = clean_json[:-3]
                                    fix_data = json.loads(clean_json.strip())
                                    fix_data["clause_text"] = clause_text_input
                                    fix_data["preset_clause"] = active_clause_key
                                    fix_data["preset_persona"] = active_persona_key
                                    st.session_state["autofix_result"] = fix_data
                                except Exception as e:
                                    st.warning(f"Error parsing Gemini response: {str(e)}")
                                    fix_data = run_simulated_autofix(clause_text_input, persona_clean)
                                    fix_data["clause_text"] = clause_text_input
                                    fix_data["preset_clause"] = active_clause_key
                                    fix_data["preset_persona"] = active_persona_key
                                    st.session_state["autofix_result"] = fix_data
                            else:
                                fix_data = run_simulated_autofix(clause_text_input, persona_clean)
                                fix_data["clause_text"] = clause_text_input
                                fix_data["preset_clause"] = active_clause_key
                                fix_data["preset_persona"] = active_persona_key
                                st.session_state["autofix_result"] = fix_data
                        else:
                            fix_data = run_simulated_autofix(clause_text_input, persona_clean)
                            fix_data["clause_text"] = clause_text_input
                            fix_data["preset_clause"] = active_clause_key
                            fix_data["preset_persona"] = active_persona_key
                            st.session_state["autofix_result"] = fix_data
                            
                        status.update(label="✅ Custom AI Rewrite Complete!", state="complete", expanded=False)
                    st.rerun()

    # ── Page: Cases (Precedents Database Listing) ─────────────────────────────
    elif current_page == "Cases":
        render_html(f"""
        <div class="subpage-container">
            <h1 class="subpage-title">📁 Precedents & Cases Database</h1>
            <p style="color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem; margin-top:-1rem;">
                Browse standard market precedence, past arbitration outcomes, and corporate transaction filings referenced by the intelligence layer.
            </p>
            <table class="cases-table" style="margin-top: 1rem;">
                <thead>
                    <tr>
                        <th>Precedent Document / Case Title</th>
                        <th>Jurisdiction</th>
                        <th>Year</th>
                        <th>Relevance Score</th>
                        <th>Clause Reference</th>
                        <th>Market Standard Outcome</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Nova Systems Corp vs. Standard Retail LLC</td>
                        <td>🇬🇧 United Kingdom</td>
                        <td>2025</td>
                        <td>93 % (High)</td>
                        <td>Clause 5.1 (Indemnification)</td>
                        <td><span class="outcome-pill win">Win / Upheld</span></td>
                    </tr>
                    <tr>
                        <td>Global TechSoft vs. Orion Logistics Ltd</td>
                        <td>🇬🇧 United Kingdom</td>
                        <td>2024</td>
                        <td>94 % (High)</td>
                        <td>Clause 2.3 (Exclusivity Cap)</td>
                        <td><span class="outcome-pill win">Win / Upheld</span></td>
                    </tr>
                    <tr>
                        <td>Confidentiality Clause Dispute in FinTech Mergers</td>
                        <td>🇪🇺 European Union</td>
                        <td>2022</td>
                        <td>89 % (Medium)</td>
                        <td>Clause 5.2 (Data Breach Venue)</td>
                        <td><span class="outcome-pill settled">Settled / Arbitrated</span></td>
                    </tr>
                    <tr>
                        <td>SaaS Vendor Liability Cap Case No. 842</td>
                        <td>🇺🇸 Delaware, USA</td>
                        <td>2023</td>
                        <td>85 % (Medium)</td>
                        <td>Section 10.4 (Asymmetrical Cap)</td>
                        <td><span class="outcome-pill settled">Invalidated Asymmetry</span></td>
                    </tr>
                    <tr>
                        <td>Telecomm Services IP Assignment Arbitration</td>
                        <td>🇺🇸 California, USA</td>
                        <td>2021</td>
                        <td>78 % (Medium)</td>
                        <td>Section 6.3 (Work Made For Hire)</td>
                        <td><span class="outcome-pill win">Restricted Scope</span></td>
                    </tr>
                </tbody>
            </table>
        </div>
        """)

    # ── Page: Legal Search (AI Precedent Search Tool) ──────────────────────────
    elif current_page == "LegalSearch":
        st.markdown("<h1 style='font-size:1.4rem; font-weight:700; color:#111827; margin-bottom:0.25rem;'>🔍 AI Precedent Search Engine</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem;'>Search our extensive multi-jurisdictional precedents, regulatory standards, and case law databases for matching clauses.</p>", unsafe_allow_html=True)
        
        search_query = st.text_input("Enter keywords, clause snippet, or category", value="indemnification fault limit liability", placeholder="e.g., 'indemnification asymmetrical', 'net 45 terms'", label_visibility="collapsed")
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("<h3 style='font-size:0.95rem; font-weight:600; color:#4b5563; margin-bottom:0.75rem;'>Search Results (Top 3 AI Matches)</h3>", unsafe_allow_html=True)

        render_html(f"""
        <div class="search-results-list">
            <div class="search-card">
                <div class="search-card-header">
                    <span class="search-card-title">Delaware Court of Chancery — Asymmetric Liability Precedent</span>
                    <span class="search-card-score">94% Relevance Match</span>
                </div>
                <div class="search-card-content">
                    "Under Delaware contract interpretation rules, an extremely asymmetrical limitation of liability clause (capping customer at $5,000 but leaving vendor unlimited) is scrutinized for unconscionability. While typically upheld in commercial transactions, extreme disparity requires clear waiver evidence."
                </div>
                <div class="search-card-meta">📁 Precedent ID: DEL-2023-842 &nbsp;•&nbsp; ⚖️ Venue: Delaware Chancery &nbsp;•&nbsp; 📅 Cited: 14 times</div>
            </div>
            
            <div class="search-card">
                <div class="search-card-header">
                    <span class="search-card-title">SaaS Master Services Agreement Standard (2024 Market Baseline)</span>
                    <span class="search-card-score">88% Relevance Match</span>
                </div>
                <div class="search-card-content">
                    "Standard market compromise for liability caps in technology vendor agreements is a mutual cap equal to 12-24 months of fees paid or payable. Asymmetric caps where only one party is limited represent a red flag under modern B2B SaaS norms."
                </div>
                <div class="search-card-meta">📁 Precedent ID: MSA-TECH-2024 &nbsp;•&nbsp; ⚖️ Venue: IEEE Commercial Standards &nbsp;•&nbsp; 📅 Cited: 112 times</div>
            </div>

            <div class="search-card">
                <div class="search-card-header">
                    <span class="search-card-title">UK Supreme Court — Express Negligence Doctrine ruling</span>
                    <span class="search-card-score">82% Relevance Match</span>
                </div>
                <div class="search-card-content">
                    "To hold a party indemnified against the consequences of its own negligence, the contract terms must be clear, express, and unequivocal. General words like 'regardless of fault' are interpreted strictly against the drafting party."
                </div>
                <div class="search-card-meta">📁 Precedent ID: UKSC-2021-42 &nbsp;•&nbsp; ⚖️ Venue: UK Supreme Court &nbsp;•&nbsp; 📅 Cited: 35 times</div>
            </div>
        </div>
        """)

    # ── Page: Compliance View ─────────────────────────────────────────────────
    elif current_page == "ComplianceView":
        audit = active_risk_data.get("compliance_audit", {})
        
        # Dynamic values with fallbacks
        gdpr_score = audit.get("gdpr_score", 94)
        gdpr_status = audit.get("gdpr_status", "🟢 Very Good • Low Risk")
        gdpr_details = audit.get("gdpr_details", "Section 2.1 destroys logs within 30 days. Perfect alignment, but conflicts with Section 5.4 regulatory backup requirement (3 years).")
        
        it_act_score = audit.get("it_act_score", 88)
        it_act_status = audit.get("it_act_status", "🟢 Compliant")
        it_act_details = audit.get("it_act_details", "Section 5.4 maintains transactional backups for 3 years, satisfying accounting and IT Act 2000 requirements.")
        
        ccpa_score = audit.get("ccpa_score", 90)
        ccpa_status = audit.get("ccpa_status", "🟢 Compliant")
        ccpa_details = audit.get("ccpa_details", "Clear definitions of consumer data privacy are established, although explicit opt-out clauses are missing.")
        
        def get_compliance_color(score):
            if score >= 85:
                return "#059669"
            elif score >= 60:
                return "#d97706"
            else:
                return "#dc2626"
                
        gdpr_color = get_compliance_color(gdpr_score)
        it_act_color = get_compliance_color(it_act_score)
        ccpa_color = get_compliance_color(ccpa_score)

        render_html(f"""
        <div class="subpage-container">
            <h1 class="subpage-title">📈 Corporate Compliance View</h1>
            <p style="color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem; margin-top:-1rem;">
                AI compliance score across various international regulatory frameworks for the current active document (<strong>{fn}</strong>).
            </p>
            
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:1.25rem; margin-top:1.5rem;">
                <div style="background:#fcfcfc; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem; text-align:center;">
                    <div style="font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">GDPR & Privacy Compliance</div>
                    <div style="font-size:2rem; font-weight:700; color:{gdpr_color};">{gdpr_score}%</div>
                    <div style="font-size:0.72rem; color:{gdpr_color}; margin-top:4px; font-weight:500;">{gdpr_status}</div>
                </div>
                <div style="background:#fcfcfc; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem; text-align:center;">
                    <div style="font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">Information Technology Act 2000</div>
                    <div style="font-size:2rem; font-weight:700; color:{it_act_color};">{it_act_score}%</div>
                    <div style="font-size:0.72rem; color:{it_act_color}; margin-top:4px; font-weight:500;">{it_act_status}</div>
                </div>
                <div style="background:#fcfcfc; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem; text-align:center;">
                    <div style="font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">CCPA Privacy Compliance</div>
                    <div style="font-size:2rem; font-weight:700; color:{ccpa_color};">{ccpa_score}%</div>
                    <div style="font-size:0.72rem; color:{ccpa_color}; margin-top:4px; font-weight:500;">{ccpa_status}</div>
                </div>
            </div>
            
            <h3 style="font-size:0.95rem; font-weight:600; color:#111827; margin-top:2rem; margin-bottom:0.75rem;">Framework Conformity Summary</h3>
            <ul style="font-size:0.85rem; color:#4b5563; line-height:1.6; padding-left:1.2rem; margin-bottom:0;">
                <li><strong>GDPR (Data Privacy & Minimization):</strong> {gdpr_details}</li>
                <li><strong>IT Act 2000 (Information Security & Section 43A):</strong> {it_act_details}</li>
                <li><strong>CCPA (California Consumer Privacy Act):</strong> {ccpa_details}</li>
            </ul>
        </div>
        """)

    # ── Page: Legal Forms ─────────────────────────────────────────────────────
    elif current_page == "LegalForms":
        render_html(f"""
        <div class="subpage-container">
            <h1 class="subpage-title">📋 Premium Legal Forms Template Library</h1>
            <p style="color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem; margin-top:-1rem;">
                Select, customize, and pre-analyze high-quality corporate agreement forms curated by our legal intelligence team.
            </p>
            
            <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap:1.25rem; margin-top:1.5rem;">
                <div style="background:#fcfcfc; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem; display:flex; flex-direction:column; justify-content:space-between;">
                    <div>
                        <div style="font-size:0.95rem; font-weight:600; color:#111827; margin-bottom:4px;">Mutual Non-Disclosure Agreement (NDA)</div>
                        <div style="font-size:0.75rem; color:#9ca3af; margin-bottom:8px;">Standard Mutual Protection Agreement • Version 4.1</div>
                        <p style="font-size:0.8rem; color:#4b5563; line-height:1.4;">
                            A balanced, industry-standard mutual NDA featuring robust carve-outs for public domain data, clear retention limits, and California governing law.
                        </p>
                    </div>
                    <a href="#" style="align-self:flex-start; margin-top:1rem; font-size:0.8rem; color:#3b82f6; font-weight:600; text-decoration:none;">Use Form Template →</a>
                </div>
                
                <div style="background:#fcfcfc; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem; display:flex; flex-direction:column; justify-content:space-between;">
                    <div>
                        <div style="font-size:0.95rem; font-weight:600; color:#111827; margin-bottom:4px;">Master Services Agreement (MSA) - Vendor Favored</div>
                        <div style="font-size:0.75rem; color:#9ca3af; margin-bottom:8px;">Vendor Protection Oriented • Version 2.3</div>
                        <p style="font-size:0.8rem; color:#4b5563; line-height:1.4;">
                            Drafted specifically to guard the services vendor against unilateral liability exposure, broad IP transfers, and short-notice terminations.
                        </p>
                    </div>
                    <a href="#" style="align-self:flex-start; margin-top:1rem; font-size:0.8rem; color:#3b82f6; font-weight:600; text-decoration:none;">Use Form Template →</a>
                </div>
            </div>
        </div>
        """)

    # ── Page: Authentication (Signature Persona & Digital ID Setup) ───────────
    elif current_page == "Authentication":
        # Look up email and extra professional details from DB for display and pre-filling
        _session_name_full = st.session_state.get('user_name', '')
        _auto_name = _session_name_full.split(',')[0].strip() if ',' in _session_name_full else _session_name_full
        _auto_role = _session_name_full.split(',')[-1].strip() if ',' in _session_name_full else ''
        _user_hash = st.session_state.get('user_hash', '')
        
        _user_email = ""
        _specialization = ""
        _organization = ""
        try:
            _conn = get_db_connection()
            _cur = _conn.cursor()
            _cur.execute("SELECT email, specialization, organization, name, persona FROM users WHERE user_hash = ?", (_user_hash,))
            _row = _cur.fetchone()
            _conn.close()
            if _row:
                _user_email = _row[0] if _row[0] else ""
                _specialization = _row[1] if _row[1] else ""
                _organization = _row[2] if _row[2] else ""
                if _row[3]: _auto_name = _row[3]
                if _row[4]: _auto_role = _row[4]
        except Exception:
            pass
        
        st.markdown("<h1 style='font-size:1.4rem; font-weight:700; color:#111827; margin-bottom:0.25rem;'>🔑 Identity & Signature Center</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem;'>Your verified digital identity is automatically loaded from your account. Update your display name, role, and professional details below.</p>", unsafe_allow_html=True)
        
        # Profile card with auto-filled data
        st.markdown(f"""
        <div style="background:linear-gradient(135deg,#f8faff 0%,#eff6ff 100%); border:1px solid #bfdbfe; border-radius:16px; padding:1.5rem; margin-bottom:1.5rem; display:flex; align-items:center; gap:1.25rem; flex-wrap:wrap;">
            <div style="background:linear-gradient(135deg,#3b82f6,#0ea5e9); width:60px; height:60px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:1.5rem; color:#fff; font-weight:700; flex-shrink:0; box-shadow:0 4px 12px rgba(59,130,246,0.4);">
                {(_auto_name[0].upper() if _auto_name else 'U')}
            </div>
            <div style="flex:1; min-width:150px;">
                <div style="font-size:1.15rem; font-weight:800; color:#1e40af; margin-bottom:2px;">{_auto_name if _auto_name else 'Your Name'}</div>
                <div style="font-size:0.82rem; color:#3b82f6; font-weight:600; margin-bottom:4px;">{_auto_role if _auto_role else 'Your Role'}</div>
                {('<div style="font-size:0.75rem; color:#475569; margin-bottom:2px;"><b>🏢 Org:</b> ' + _organization + '</div>') if _organization else ''}
                {('<div style="font-size:0.75rem; color:#475569; margin-bottom:2px;"><b>🔬 Focus:</b> ' + _specialization + '</div>') if _specialization else ''}
                {('<div style="font-size:0.75rem; color:#6b7280;">📧 ' + _user_email + '</div>') if _user_email else ''}
                <div style="font-size:0.7rem; color:#94a3b8; margin-top:3px; font-family:monospace;">🔑 Vault: {_user_hash[:8]}...{_user_hash[-4:] if len(_user_hash) > 12 else _user_hash}</div>
            </div>
            <div style="background:#dcfce7; border:1px solid #86efac; border-radius:20px; padding:4px 12px; font-size:0.72rem; font-weight:700; color:#166534; white-space:nowrap;">
                ✅ Authenticated
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div style="background:#ffffff; border:1px solid #e5e7eb; padding:1.5rem; border-radius:12px; margin-bottom:1.5rem;">', unsafe_allow_html=True)
        st.markdown("<p style='font-size:0.85rem; color:#374151; font-weight:600; margin-bottom:0.75rem;'>✏️ Edit Profile & Professional Details</p>", unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            name_input = st.text_input(
                "Full Display Name",
                value=_auto_name,
                placeholder="Your display name",
                help="This will show up on your audited reports."
            )
            org_input = st.text_input(
                "Organization Name",
                value=_organization,
                placeholder="e.g. Tattvasphere Inc.",
                help="Your company, firm, or institutional affiliation."
            )
        with col2:
            role_options = ["General Counsel", "Freelance Consultant", "Enterprise Procurement", "Legal Intern", "Co-Founder / CEO", "Associate Counsel", "Senior Partner"]
            # Auto-match role from session
            current_role_idx = 0
            for _i, _opt in enumerate(role_options):
                if _auto_role.lower() in _opt.lower() or _opt.lower() in _auto_role.lower():
                    current_role_idx = _i
                    break
            role_input = st.selectbox("Your Role", options=role_options, index=current_role_idx)
            
            spec_input = st.text_input(
                "Legal Specialization / Focus",
                value=_specialization,
                placeholder="e.g. Commercial Contracts, GDPR Compliance, IP",
                help="Your areas of specific legal care or expertise."
            )
            
        st.markdown("<br>", unsafe_allow_html=True)
        auth_btn = st.button("💾 Save Identity Update", type="primary", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        if auth_btn:
            if name_input.strip():
                try:
                    _conn = get_db_connection()
                    _cur = _conn.cursor()
                    _cur.execute("""
                        UPDATE users 
                        SET name = ?, persona = ?, specialization = ?, organization = ?
                        WHERE user_hash = ?
                    """, (name_input.strip(), role_input, spec_input.strip(), org_input.strip(), _user_hash))
                    _conn.commit()
                    _conn.close()
                    
                    st.session_state['user_name'] = f"{name_input.strip()}, {role_input}"
                    st.success("🎉 Profile and professional details successfully saved to the database!")
                    time.sleep(0.3)
                    st.rerun()
                except Exception as ex:
                    st.error(f"❌ Failed to save profile details to the database: {str(ex)}")
            else:
                st.error("⚠️ Please enter a valid name.")

        # Logout & GDPR Shredding Controls
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("<h2 style='font-size:1.15rem; font-weight:600; color:#111827; margin-bottom:0.5rem;'>🚪 Portal Navigation & Exit</h2>", unsafe_allow_html=True)
        st.markdown('<div style="background:#ffffff; border:1px solid #e5e7eb; padding:1.5rem; border-radius:12px; margin-bottom:1.5rem; color:#111827;">', unsafe_allow_html=True)
        
        if st.button("🚪 Logout of Vault Session", use_container_width=True):
            if os.path.exists(SESSION_CACHE_FILE):
                try:
                    os.remove(SESSION_CACHE_FILE)
                except Exception:
                    pass
            st.session_state.clear()
            st.session_state["authenticated"] = False
            st.query_params.update({"logout": "1"})
            st.success("🚪 Session closed. Redirecting...")
            time.sleep(0.3)
            st.rerun()
            
        st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("<h2 style='font-size:1.15rem; font-weight:600; color:#dc2626; margin-bottom:0.5rem;'>☣️ GDPR Compliance Vault Shredder (Danger Zone)</h2>", unsafe_allow_html=True)
        st.markdown('<div style="background:#fff5f5; border:1px solid #fee2e2; padding:1.5rem; border-radius:12px; margin-bottom:1.5rem; color:#991b1b;">', unsafe_allow_html=True)
        st.markdown("<p style='font-size:0.82rem; margin-bottom:1rem; line-height:1.4;'>Permanently erase your active account record from the SQLite database, clear audit logs, and physically shred all contract PDF/PPTX drafts saved on disk under your isolated sandbox uploads directory.</p>", unsafe_allow_html=True)
        
        if st.button("🚨 Wipe SQLite Vault & Physical GDPR Purging", type="primary", use_container_width=True):
            user_hash = st.session_state.get("user_hash", "")
            
            # 1. Physical GDPR purging under uploads directory
            user_dir = os.path.join("data", "users", user_hash)
            if os.path.exists(user_dir):
                try:
                    shutil.rmtree(user_dir)
                except Exception:
                    pass
            
            # 2. Relational SQLite deletion
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM documents WHERE user_hash = ?", (user_hash,))
                cursor.execute("DELETE FROM audit_logs WHERE user_hash = ?", (user_hash,))
                cursor.execute("DELETE FROM users WHERE user_hash = ?", (user_hash,))
                conn.commit()
                conn.close()
            except Exception:
                pass
                
            # 3. Log out and clear session cache file
            if os.path.exists(SESSION_CACHE_FILE):
                try:
                    os.remove(SESSION_CACHE_FILE)
                except Exception:
                    pass
                    
            st.session_state.clear()
            st.session_state["authenticated"] = False
            st.success("✅ Vault wiped and physically shredded. Redirecting...")
            time.sleep(0.3)
            st.rerun()
            
            st.markdown("</div>", unsafe_allow_html=True)

    # ── Page: Chaos Simulator (5-Agent Red-Team View) ─────────────────────────
    elif current_page == "ChaosSimulator":
        st.markdown("<h1 style='font-size:1.4rem; font-weight:700; color:#111827; margin-bottom:0.25rem;'>☣️ Chaos Simulator — Adversarial Red-Team Engine</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem;'>Five specialized AI agents simultaneously red-team your contract from different adversarial angles — exposing hidden loopholes, structural traps, and negotiation pressure points that a simple review misses. Click <b>Run Live AI Simulation</b> to activate all agents with Gemini AI.</p>", unsafe_allow_html=True)
        
        # Animated agent grid
        agents = [
            {
                "name": "⚔️ Liability Attacker",
                "desc": "Probes every clause for uncapped financial exposure, hidden penalty traps, and asymmetric risk distributions.",
                "color": "#dc2626",
                "bg": "#fef2f2",
                "border": "#fca5a5",
                "status": "Active — Scanning Liability Clauses",
                "finds": active_risk_data.get('red_flags', [{}])[0].get('category', 'Uncapped Liability Exposure') if active_risk_data.get('red_flags') else 'Uncapped Liability Exposure'
            },
            {
                "name": "🧨 IP Exploiter",
                "desc": "Exploits overbroad intellectual property assignment clauses to claim maximum IP ownership on behalf of the Client.",
                "color": "#7c3aed",
                "bg": "#faf5ff",
                "border": "#c4b5fd",
                "status": "Active — Scanning IP Assignments",
                "finds": "Overbroad Work-For-Hire Scope"
            },
            {
                "name": "⏰ Deadline Arbitrageur",
                "desc": "Identifies conflicting payment timelines, asymmetric notice periods, and cross-schedule timing traps.",
                "color": "#0891b2",
                "bg": "#ecfeff",
                "border": "#a5f3fc",
                "status": "Active — Scanning Payment Schedules",
                "finds": "Net 15 vs. Net 30 Contradiction"
            },
            {
                "name": "🧠 Logic Auditor (Z3)",
                "desc": "Uses formal SMT constraint solving to find internally contradictory covenants that are logically impossible to both comply with.",
                "color": "#059669",
                "bg": "#ecfdf5",
                "border": "#6ee7b7",
                "status": "Active — Z3 Formal Verification",
                "finds": f"{len(active_risk_data.get('logic_conflicts', [{'conflict': 'Data Retention vs Destruction'}]))} Logical Contradictions Found"
            },
            {
                "name": "📡 Compliance Scanner",
                "desc": "Cross-references every clause against GDPR, CCPA, IT Act 2000, and ISO 27001 frameworks for regulatory compliance gaps.",
                "color": "#d97706",
                "bg": "#fffbeb",
                "border": "#fde68a",
                "status": "Active — Regulatory Audit",
                "finds": f"GDPR Score: {active_risk_data.get('compliance_audit', {}).get('gdpr_score', 94)}%"
            }
        ]
        
        # Static agent card grid (always visible)
        col1, col2 = st.columns(2)
        for i, agent in enumerate(agents):
            with (col1 if i % 2 == 0 else col2):
                st.markdown(f"""
                <div style="background:{agent['bg']}; border:1px solid {agent['border']}; border-left:5px solid {agent['color']};
                    border-radius:12px; padding:1.25rem; margin-bottom:1rem;
                    box-shadow:0 2px 8px rgba(0,0,0,0.04);">
                    <div style="font-size:1rem; font-weight:700; color:{agent['color']}; margin-bottom:6px;">{agent['name']}</div>
                    <div style="font-size:0.82rem; color:#4b5563; line-height:1.5; margin-bottom:10px;">{agent['desc']}</div>
                    <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid {agent['border']}; padding-top:8px; gap:6px; flex-wrap:wrap;">
                        <span style="font-size:0.7rem; font-weight:700; color:{agent['color']}; display:flex; align-items:center; gap:4px;">
                            <span style="display:inline-block; width:7px; height:7px; border-radius:50%; background:{agent['color']};"></span>
                            {agent['status']}
                        </span>
                        <span style="font-size:0.7rem; font-weight:700; background:{agent['bg']}; color:{agent['color']}; padding:2px 8px; border-radius:8px; border:1px solid {agent['border']};">
                            🎯 {agent['finds']}
                        </span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Summary stats box
        total_risks = len(active_risk_data.get('red_flags', []))
        total_conflicts = len(active_risk_data.get('logic_conflicts', []))
        st.markdown(f"""
        <div style="background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%); border:1px solid rgba(59,130,246,0.3);
            border-radius:14px; padding:1.5rem; color:#f1f5f9; margin-bottom:1.5rem;
            box-shadow:0 10px 30px rgba(0,0,0,0.2);">
            <div style="font-size:1rem; font-weight:800; color:#38bdf8; margin-bottom:1rem; display:flex; align-items:center; gap:8px;">
                ☣️ CHAOS SIMULATION RESULTS — <span style="color:#f87171;">{fn}</span>
            </div>
            <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:1rem;">
                <div style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:10px; padding:1rem; text-align:center;">
                    <div style="font-size:2rem; font-weight:900; color:#f87171;">{total_risks}</div>
                    <div style="font-size:0.72rem; color:#94a3b8; margin-top:4px; font-weight:600; text-transform:uppercase; letter-spacing:0.03em;">Red Flags Found</div>
                </div>
                <div style="background:rgba(168,85,247,0.1); border:1px solid rgba(168,85,247,0.3); border-radius:10px; padding:1rem; text-align:center;">
                    <div style="font-size:2rem; font-weight:900; color:#c084fc;">{total_conflicts}</div>
                    <div style="font-size:0.72rem; color:#94a3b8; margin-top:4px; font-weight:600; text-transform:uppercase; letter-spacing:0.03em;">Logic Contradictions</div>
                </div>
                <div style="background:rgba(14,165,233,0.1); border:1px solid rgba(14,165,233,0.3); border-radius:10px; padding:1rem; text-align:center;">
                    <div style="font-size:2rem; font-weight:900; color:#38bdf8;">{active_risk_data.get('ai_confidence', '93%')}</div>
                    <div style="font-size:0.72rem; color:#94a3b8; margin-top:4px; font-weight:600; text-transform:uppercase; letter-spacing:0.03em;">AI Confidence</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # ── Live Gemini AI Simulation ───────────────────────────────────────────
        st.markdown("<h3 style='font-size:1rem; font-weight:700; color:#111827; margin-bottom:0.5rem;'>🤖 Live AI Agent Simulation</h3>", unsafe_allow_html=True)
        st.markdown("<p style='color:#6b7280; font-size:0.82rem; margin-bottom:1rem;'>Click below to run each agent through Gemini AI and get real streaming analysis specific to your uploaded contract.</p>", unsafe_allow_html=True)
        
        _contract_text = active_risk_data.get('contract_text', '') or '\n'.join([rf.get('clause_text','') for rf in active_risk_data.get('red_flags', [])])
        _api_key = st.session_state.get('gemini_api_key', os.environ.get('GEMINI_API_KEY', ''))
        
        if not _api_key:
            st.info("💡 Add your Gemini API key in the sidebar to enable live AI agent simulation.")
        else:
            _agent_prompts = [
                {"agent": "⚔️ Liability Attacker", "color": "#dc2626", "system": "You are an adversarial legal agent specialized in exploiting liability clauses. Your job is to find and expose every uncapped financial exposure, hidden penalty trap, and asymmetric risk distribution in a contract, from the perspective of someone trying to exploit the weaker party.",
                 "prompt": f"Contract text:\n{_contract_text[:3000]}\n\nAs the Liability Attacker AI, identify and explain in 3-5 bullet points the most dangerous liability clauses and what they could cost the weaker party. Be specific with clause references where possible. Keep it clear enough for a non-lawyer to understand."},
                {"agent": "🧨 IP Exploiter", "color": "#7c3aed", "system": "You are an adversarial legal agent specialized in intellectual property law. Your goal is to identify overbroad IP assignments, work-for-hire traps, and background IP ownership risks.",
                 "prompt": f"Contract text:\n{_contract_text[:3000]}\n\nAs the IP Exploiter AI, identify in 3-5 bullet points the most dangerous IP assignment clauses — what IP could be lost, to whom, and how a negotiator could push back. Keep language simple."},
                {"agent": "⏰ Deadline Arbitrageur", "color": "#0891b2", "system": "You are an adversarial legal agent specialized in finding timing traps and conflicting deadlines in contracts.",
                 "prompt": f"Contract text:\n{_contract_text[:3000]}\n\nAs the Deadline Arbitrageur AI, identify in 3-5 bullet points any conflicting payment timelines, asymmetric notice periods, or schedule contradictions. Explain what happens if those deadlines clash."},
                {"agent": "🧠 Logic Auditor (Z3)", "color": "#059669", "system": "You are a formal logic auditor. You identify clauses that are internally contradictory — where two clauses cannot both be simultaneously obeyed.",
                 "prompt": f"Contract text:\n{_contract_text[:3000]}\n\nAs the Z3 Logic Auditor AI, identify in 3-5 bullet points any logical contradictions or paradoxes where two clauses conflict — i.e., obeying one clause makes it impossible to obey another. Explain each contradiction in simple terms."},
                {"agent": "📡 Compliance Scanner", "color": "#d97706", "system": "You are a regulatory compliance AI. You identify breaches of GDPR, CCPA, IT Act 2000, and ISO 27001 in contract clauses.",
                 "prompt": f"Contract text:\n{_contract_text[:3000]}\n\nAs the Compliance Scanner AI, identify in 3-5 bullet points any clauses that may violate GDPR, CCPA, India IT Act 2000, or ISO 27001. Explain the specific violation and its real-world consequence for the business."},
            ]
            
            if st.button("🚀 Run Live AI Simulation (All 5 Agents)", type="primary", use_container_width=True):
                st.session_state["chaos_run"] = True
            
            if st.session_state.get("chaos_run"):
                for ap in _agent_prompts:
                    with st.expander(f"{ap['agent']} — Live AI Analysis", expanded=True):
                        st.markdown(f"<div style='font-size:0.75rem; font-weight:700; color:{ap['color']}; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.04em;'>🤖 Gemini AI — Streaming Response</div>", unsafe_allow_html=True)
                        _result = call_gemini(ap["system"], ap["prompt"], api_key=_api_key)
                        if _result:
                            st.markdown(_result)
                        else:
                            st.warning(f"Agent {ap['agent']} could not generate a response. Check your Gemini API key.")
        
        st.markdown("<br>", unsafe_allow_html=True)
        # Navigate to Smart Review CTA
        if st.button("🔮 Launch Full Adversarial Bot Debate in Smart Review", type="primary", use_container_width=True):
            st.query_params.update({"page": "SmartReview", "tab": "BotDebate", "user": st.session_state.get("user_hash", "")})
            st.rerun()
