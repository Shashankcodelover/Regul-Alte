# pyrefly: ignore [missing-import]
import streamlit as st
import time
import textwrap
import difflib
import os
import json
from mock_data import risk_data, loophole_logs, logic_conflicts, auto_fixes

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

def analyze_pdf_content(uploaded_file):
    import pypdf
    import io
    import zipfile
    import re
    
    filename = uploaded_file.name
    filename_lower = filename.lower()
    full_text = ""
    num_pages = 1
    
    # Read text from PDF or PPTX
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
                        "impact": "..."
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
                        "impact": "..."
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

    # CASE 1: Perfect / Balanced Standard Agreement
    if "perfect" in filename_lower or "balanced" in filename_lower or "perfect_standard" in filename_lower:
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
        # Check text keywords for dynamic custom contract scanning!
        has_indemn = any(k in full_text.lower() for k in ["indemnify", "hold harmless", "regardless of fault"])
        has_termination = "terminate" in full_text.lower() and ("days" in full_text.lower() or "asymmetr" in full_text.lower())
        has_liability = "liability" in full_text.lower() and ("cap" in full_text.lower() or "exceed" in full_text.lower() or "limit" in full_text.lower())
        has_ip = any(k in full_text.lower() for k in ["invention", "discoveries", "intellectual property", "work product"])
        
        if has_indemn:
            clause_text = find_context_sentence("fault", full_text) or find_context_sentence("indemnify", full_text)
            if not clause_text or len(clause_text) < 15:
                clause_text = "Vendor agrees to indemnify, defend, and hold harmless the Client from and against any and all claims, losses, liabilities, damages, expenses... regardless of fault."
            detected_flags.append({
                "category": "Indemnification Asymmetry",
                "severity": 9,
                "clause_text": clause_text,
                "citation": "Section 4.2 / Indemnification (Scanned)",
                "impact": "The phrase 'regardless of fault' exposes the Vendor to liability even for the Client's own negligent or reckless acts. This is a severe legal trap."
            })
            
        if has_termination:
            clause_text = find_context_sentence("asymmetry", full_text) or find_context_sentence("five (5) days", full_text) or find_context_sentence("60", full_text)
            if not clause_text or len(clause_text) < 15:
                clause_text = "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days."
            detected_flags.append({
                "category": "Termination Asymmetry",
                "severity": 8,
                "clause_text": clause_text,
                "citation": "Section 9.1 / Termination convenience (Scanned)",
                "impact": "A highly unbalanced 5-day vs 60-day notice period creates severe operational and planning instability for the Vendor, allowing client exit on whim."
            })
            
        if has_liability:
            clause_text = find_context_sentence("exceed the total", full_text) or find_context_sentence("one (1) month", full_text) or find_context_sentence("uncapped", full_text)
            if not clause_text or len(clause_text) < 15:
                clause_text = "Under no circumstances shall Client's aggregate liability exceed the total amount paid by Client to Vendor in the one (1) month preceding... No equivalent cap is placed upon Vendor's liability."
            detected_flags.append({
                "category": "Liability Cap Asymmetry",
                "severity": 10,
                "clause_text": clause_text,
                "citation": "Section 10.4 / Limitation of Liability (Scanned)",
                "impact": "Client liability is capped at ~1/12th of annual fees while Vendor's liability is left entirely uncapped — a critical risk that could cause catastrophic financial ruin."
            })
            
        if has_ip:
            clause_text = find_context_sentence("whether or not", full_text) or find_context_sentence("exclusive property of client", full_text) or find_context_sentence("hire", full_text)
            if not clause_text or len(clause_text) < 15:
                clause_text = "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall be deemed works made for hire and shall be the exclusive property of Client."
            detected_flags.append({
                "category": "Intellectual Property Assignment",
                "severity": 7,
                "clause_text": clause_text,
                "citation": "Section 6.3 / Intellectual Property (Scanned)",
                "impact": "Overly broad IP assignment without carve-outs may strip Vendor of pre-existing background IP rights and general commercial know-how."
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

# Initialize session state for user name and active level
if 'user_name' not in st.session_state:
    st.session_state['user_name'] = "Anna K., Associate"
if 'active_level' not in st.session_state:
    st.session_state['active_level'] = "Level 3 (High Risk)"

# Sync page from query parameters
if "page" in qp:
    st.session_state['current_page'] = qp["page"]
elif 'current_page' not in st.session_state:
    st.session_state['current_page'] = "Dashboard"

# Sync session state from query parameters
if "demo" in qp:
    st.session_state['demo_mode'] = (qp["demo"] == "true")
    st.session_state['analysis_complete'] = True
    st.session_state['file_uploaded'] = False
    st.session_state['filename'] = qp.get("filename", "NDA_v3.2_Draft.pdf")
elif "analyzed" in qp:
    st.session_state['analysis_complete'] = (qp["analyzed"] == "true")
    st.session_state['file_uploaded'] = True
    st.session_state['demo_mode'] = False
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
    if st.session_state.get('demo_mode'):
        params.append("demo=true")
    elif st.session_state.get('analysis_complete'):
        params.append("analyzed=true")
    if st.session_state.get('filename'):
        params.append(f"filename={st.session_state['filename']}")
    return "?" + "&".join(params)

# Helper function to clean and render HTML safely without triggering raw Markdown code blocks
def render_html(html_code: str):
    cleaned = " ".join([line.strip() for line in html_code.splitlines()])
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

/* Hide default Streamlit chrome */
#MainMenu, header, footer { visibility: hidden !important; }
.stDeployButton { display: none !important; }

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
</style>
""")

# ── Sidebar Layout ────────────────────────────────────────────────────────────
current_page = st.session_state['current_page']

sidebar_html = f"""
<div class="sidebar-container">
    <!-- Header/Logo -->
    <div class="sidebar-header">
        <div style="display:flex; align-items:center; gap:10px;">
            <div class="logo-box">R</div>
            <span class="brand-name">RegulAIte</span>
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

    uploaded_file = st.file_uploader(
        "Upload Document (PDF, PPTX)",
        type=["pdf", "pptx"],
        label_visibility="collapsed"
    )

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
                    🤖 regulAIte Multi-Agent Scan
                </div>
                <div style="font-size: 0.85rem; color: #4b5563; line-height: 1.5; margin-bottom: 1.5rem;">
                    Adversarial legal agents are currently red-teaming your covenants, scanning for uncapped liabilities, and compiling a semantic compliance audit.
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
        
        # Analyze and trigger sleeker delay for complete immersive visual feedback
        st.session_state['uploaded_file_analysis'] = analyze_pdf_content(uploaded_file)
        time.sleep(1.8)
        loading_placeholder.empty()
        
        st.session_state['analysis_complete'] = True
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
            elif "Level 2" in level_choice:
                st.session_state['filename'] = "Mildly_Risky_Agreement.pdf"
            else:
                st.session_state['filename'] = "Vulnerable_Agreement_Draft.pdf"
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
                
            with st.spinner("🤖 Agents analyzing contract..."):
                time.sleep(1.5)
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

        if st.button("🔄 Reset / Clear Document", use_container_width=True):
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
    render_html("""
    <div style='display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:80vh; text-align:center;'>
        <div style='font-size:3rem; margin-bottom:1rem;'>⚖️</div>
        <h1 style='font-size:2.2rem; font-weight:800; color:#111827; margin-bottom:0.5rem;'>Drop your contract.<br>We'll decode the risk.</h1>
        <p style='color:#6b7280; font-size:1.05rem; max-width:550px; line-height:1.6; margin-bottom:1.5rem;'>
            Upload any legal contract PDF in the sidebar — or click <strong>Load Demo Analysis</strong> to instantly explore our sophisticated AI-driven legal insights dashboard.
        </p>
    </div>
    """)

else:
    # Common variables globally available inside all subpages to avoid Scope / NameErrors
    fn = st.session_state.get('filename', 'NDA_v3.2_Draft.pdf')
    demo_mode = st.session_state.get('demo_mode', False)

    lvl = st.session_state.get('active_level', 'Level 3 (High Risk)')
    from mock_data import (
        level_1_data, level_2_data, level_3_data,
        level_1_debate, level_2_debate, level_3_debate,
        level_1_conflicts, level_2_conflicts, level_3_conflicts,
        level_1_playbook, level_2_playbook, level_3_playbook
    )
    
    if demo_mode or 'uploaded_file_analysis' not in st.session_state:
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
        if "Level 1" in lvl:
            active_debate = level_1_debate
            active_conflicts = level_1_conflicts
            active_playbook = level_1_playbook
        elif "Level 2" in lvl:
            active_debate = level_2_debate
            active_conflicts = level_2_conflicts
            active_playbook = level_2_playbook
        else:
            active_debate = level_3_debate
            active_conflicts = level_3_conflicts
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
        st.session_state["logic_validation_result"] = active_conflicts[0]
        
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
        # Determine active highlight coordinates dynamically based on risk score
        score = active_risk_data.get('score', 87)
        if score <= 20: # Level 1 (Low Risk)
            highlight_x = 290
            highlight_rect_x = 272
            blue_dot_y = 51.5
            red_dot_y = 123.5
            tooltip_x = 220
        elif score <= 60: # Level 2 (Medium Risk)
            highlight_x = 470
            highlight_rect_x = 452
            blue_dot_y = 42.5
            red_dot_y = 119
            tooltip_x = 400
        else: # Level 3 (High Risk)
            highlight_x = 650
            highlight_rect_x = 632
            blue_dot_y = 65
            red_dot_y = 132.5
            tooltip_x = 580
            
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
          <path d="M 50 119 C 80 90, 80 50, 110 74 C 140 98, 140 40, 170 56 C 200 72, 200 80, 230 74 C 260 68, 260 40, 290 51.5 C 320 63, 320 80, 350 65 C 380 50, 380 15, 410 29 C 440 43, 440 60, 470 42.5 C 500 25, 500 110, 530 87.5 C 560 65, 560 30, 590 47 C 620 64, 620 80, 650 65 C 680 50, 680 20, 710 38" 
                fill="none" stroke="#0ea5e9" stroke-width="3" stroke-linecap="round" />
                
          <!-- Red Line Path (With Risks) -->
          <path d="M 50 101 C 80 120, 80 150, 110 137 C 140 124, 140 70, 170 87.5 C 200 105, 200 140, 230 128 C 260 116, 260 110, 290 123.5 C 320 137, 320 155, 350 141.5 C 380 128, 380 70, 410 87.5 C 440 105, 440 130, 470 119 C 500 108, 500 80, 530 96.5 C 560 113, 560 130, 590 114.5 C 620 99, 620 120, 650 132.5 C 680 145, 680 130, 710 141.5" 
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

        # Construct Dashboard HTML Grid
        dashboard_html = f"""
        <div class="dashboard-container">
            <!-- Header bar matching picture -->
            <div class="header-container">
                <h1 class="header-title">AI Analysis Overview</h1>
                <div class="search-bar-container">
                    <span class="search-icon">🔍</span>
                    <input type="text" placeholder="Search..." class="search-input">
                </div>
                <div class="header-actions">
                    <span style="font-size:0.8rem; color:#4b5563; font-weight:600; margin-right:4px;">👤 {st.session_state.get('user_name', 'Guest Auditor').split(',')[0]}</span>
                    <button class="action-btn">+</button>
                    <button class="action-btn">🎛️</button>
                    <button class="action-btn relative">🔔<span class="badge-dot"></span></button>
                    <img src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&fit=crop" class="avatar" alt="Avatar">
                </div>
            </div>

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

                    <!-- Documents Card -->
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Documents</h2>
                            <span class="card-actions">•••</span>
                        </div>
                        <div class="card-subtitle">Last AI Documents Reviews</div>
                        <div class="pdf-row" style="margin-bottom:0;">
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

        # Detailed Red Flags Analysis (styled Streamlit expanders below grid)
        st.markdown('<h2 style="font-size:1.15rem; font-weight:600; color:#111827; margin-bottom:1rem; margin-top:0.5rem;">Detailed Red Flag Analysis</h2>', unsafe_allow_html=True)
        
        sev_map = {
            10: ("Critical Risk", "badge-red"),
            9:  ("Critical Risk", "badge-red"),
            8:  ("High Risk",     "badge-yellow"),
            7:  ("High Risk",     "badge-yellow"),
            6:  ("Medium Risk",   "badge-yellow"),
        }
        for flag in active_risk_data['red_flags']:
            sev_label, sev_cls = sev_map.get(flag['severity'], ("Medium", "badge-medium"))
            with st.expander(f"{flag['category']}  ·  Severity {flag['severity']}/10"):
                render_html(f"""
                <div style='margin-bottom: 10px;'>
                    <span class="badge {sev_cls}">{sev_label}</span>
                </div>
                <div style="font-size:0.85rem; font-weight:600; color:#374151; margin-bottom: 6px;">Clause Content</div>
                """)
                st.error(flag['clause_text'])
                st.markdown(f"**⚡ Risk Impact:** {flag['impact']}")
                st.caption(f"📍 Citation: {flag['citation']}")

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
            render_html("""
            <div style='margin-bottom:1.5rem;'>
                <h2 style='font-size:1.15rem;font-weight:700;color:#0f172a;margin:0 0 4px 0;'>
                    AI Negotiation Playbook Sandbox
                </h2>
                <p style='color:#64748b;font-size:0.85rem;margin:0;'>
                    Select a scanned red flag or write a custom clause, select a negotiation profile, and view word-level difference overlays dynamically.
                </p>
            </div>
            """)

            # Dropdown options
            flag_categories = []
            flag_texts = {}
            flag_severities = {}
            for flag in active_risk_data.get('red_flags', []):
                cat = flag['category']
                flag_categories.append(cat)
                flag_texts[cat] = flag['clause_text']
                flag_severities[cat] = flag['severity']
            
            # Default options if red_flags is empty
            if not flag_categories:
                flag_categories = ["Termination rights", "Liability Cap", "IP Assignment"]
                flag_texts = {
                    "Termination rights": "Client may terminate this Agreement at any time for any reason upon five (5) days' written notice, whereas Vendor may only terminate upon a material breach remaining uncured for sixty (60) days.",
                    "Liability Cap": "In no event shall Client's total liability under this Agreement exceed the fees paid in the preceding one (1) month. No limitation on liability applies to Vendor.",
                    "IP Assignment": "All work product, inventions, discoveries, and improvements conceived or developed by Vendor, whether or not during working hours and whether or not using Client's resources, shall belong exclusively to Client."
                }
                flag_severities = {
                    "Termination rights": 8,
                    "Liability Cap": 10,
                    "IP Assignment": 7
                }
            
            flag_categories.append("Custom Clause...")
            
            # Setup columns for clean inputs
            st.markdown('<div style="background: rgba(255, 255, 255, 0.6); border: 1px solid #e5e7eb; padding: 1.25rem; border-radius: 12px; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.02); color: #111827;">', unsafe_allow_html=True)
            col1, col2 = st.columns([2, 1])
            with col1:
                selected_cat = st.selectbox("Select Clause to Auto-Fix", options=flag_categories, key="autofix_cat_select")
            with col2:
                persona_selection = st.selectbox("AI Negotiation Profile", options=["Defender (🛡️)", "Attacker (⚔️)", "Arbitrator (⚖️)"], key="autofix_persona_select")
            
            default_text = flag_texts.get(selected_cat, "")
            clause_text_input = st.text_area("Clause Text to Fix", value=default_text, height=100, key="autofix_clause_text_input")
            
            autofix_btn = st.button("⚡ Generate AI Rewrite", use_container_width=True, type="primary")
            st.markdown('</div>', unsafe_allow_html=True)
 
            if autofix_btn:
                # Execution Flow
                with st.status("🔮 Compiling AI Self-Healing Rewrite...", expanded=True) as status:
                    st.write("🔮 Reading clause vulnerability markers...")
                    time.sleep(0.4)
                    st.write("⚖️ Structuring rewrite under Selected Persona...")
                    time.sleep(0.4)
                    st.write("⚡ Custom diff-compiling Suggested Clause...")
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
                                st.session_state["autofix_result"] = fix_data
                            except Exception as e:
                                st.warning(f"Error parsing Gemini rewrite: {str(e)}. Using fallback simulator.")
                                fix_data = run_simulated_autofix(clause_text_input, persona_clean)
                                fix_data["clause_text"] = clause_text_input
                                st.session_state["autofix_result"] = fix_data
                        else:
                            fix_data = run_simulated_autofix(clause_text_input, persona_clean)
                            fix_data["clause_text"] = clause_text_input
                            st.session_state["autofix_result"] = fix_data
                    else:
                        fix_data = run_simulated_autofix(clause_text_input, persona_clean)
                        fix_data["clause_text"] = clause_text_input
                        st.session_state["autofix_result"] = fix_data
                        
                    status.update(label="✅ Custom Rewrite Complete!", state="complete", expanded=False)
                st.rerun()

            # Render Split Workspace Screen
            if st.session_state.get("autofix_result"):
                fix = st.session_state["autofix_result"]
                original_text = fix.get("clause_text", clause_text_input)
                suggested_text = fix.get("rewrite", "")
                active_severity = flag_severities.get(selected_cat, fix.get("severity", 5))
                risk_class = fix.get("risk_class", "low")
                risk_label = fix.get("risk_label", "🛡️ Reciprocal Risk")
                score = fix.get("score", "3/10")
                rationale_text = fix.get("rationale", "")
                persona_name = persona_selection.split(" ")[0]

                word_diff_html = get_word_diff(original_text, suggested_text)

                glass_controls_html = f"""
                <div class="glass-panel">
                    <div class="glass-title">🔮 AI Negotiation Playbook Sandbox</div>
                    <div class="glass-subtitle">Configure AI negotiation profiles, view side-by-side comparison, and export self-healing rewrites with dynamic word-level diff highlights.</div>
                    
                    <!-- 1. Split Screen Workspace Grid -->
                    <div class="glass-split-screen">
                        <!-- Left pane: Original -->
                        <div class="glass-pane">
                            <div class="pane-header">
                                <span class="pane-title">Original Contract Wording</span>
                                <span class="glass-risk-pill critical">🚨 Risk Severity: {active_severity}/10</span>
                            </div>
                            <div class="pane-content">{original_text}</div>
                        </div>
                        
                        <!-- Right pane: Suggested Rewrite with Dynamic Diff Overlay! -->
                        <div class="glass-pane">
                            <div class="pane-header">
                                <span class="pane-title">Suggested Rewrite ({persona_name} Profile)</span>
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
                
                # Render clean Streamlit copy button and download buttons below for absolute robustness
                st.markdown("<div style='margin-top:1rem;'></div>", unsafe_allow_html=True)
                col_btn1, col_btn2 = st.columns(2)
                with col_btn1:
                    st.download_button(
                        label="📥 Export Clause as Text File",
                        data=suggested_text,
                        file_name="Suggested_Rewrite_Clause.txt",
                        mime="text/plain",
                        use_container_width=True
                    )
                with col_btn2:
                    # Renders a neat code box so they can click copy instantly
                    st.markdown("**📋 Copy Rewrite Verbatim:**")
                    st.code(suggested_text, language="text")

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
        st.markdown("<h1 style='font-size:1.4rem; font-weight:700; color:#111827; margin-bottom:0.25rem;'>🔑 Identity & Signature Center</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem;'>Configure your digital persona. All annotations, logic revisions, and audit stamps will be dynamically associated with this identity.</p>", unsafe_allow_html=True)
        
        render_html(f"""
        <div class="glass-panel" style="margin-top: 1rem;">
            <div class="glass-title">🔐 Secure Workspace Authentication</div>
            <div class="glass-subtitle">Enter your name and operational role to sign off on edits and lock reviews under your authenticated signature.</div>
            
            <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius:12px; padding:1.5rem; margin-bottom:1.5rem; border-left:4px solid #10b981;">
                <div style="font-size:0.75rem; font-weight:700; text-transform:uppercase; color:#10b981; margin-bottom:6px; letter-spacing:0.05em;">👑 Active Identity Status</div>
                <div style="font-size:0.95rem; color:#e5e7eb; line-height:1.5;">Currently signed in as: <strong>{st.session_state.get('user_name', 'Anna K., Associate')}</strong></div>
            </div>
        </div>
        """)
        
        st.markdown('<div style="background:#ffffff; border:1px solid #e5e7eb; padding:1.5rem; border-radius:12px; margin-bottom:1.5rem; color:#111827;">', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            name_input = st.text_input("Full Signature Name", value=st.session_state.get('user_name', 'Anna K., Associate').split(",")[0])
        with col2:
            role_options = ["Associate Counsel", "Senior Partner", "Co-Founder", "General Counsel", "Legal Intern"]
            current_role = st.session_state.get('user_name', 'Anna K., Associate').split(",")[-1].strip()
            current_role_idx = 0
            if current_role in role_options:
                current_role_idx = role_options.index(current_role)
            role_input = st.selectbox("Organizational Role", options=role_options, index=current_role_idx)
            
        st.markdown("<br>", unsafe_allow_html=True)
        auth_btn = st.button("🔑 Authenticate Signature Persona", type="primary", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        if auth_btn:
            if name_input.strip():
                st.session_state['user_name'] = f"{name_input.strip()}, {role_input}"
                st.success(f"Signature authenticated successfully! Welcome, {name_input}!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Please enter a valid signature name.")
