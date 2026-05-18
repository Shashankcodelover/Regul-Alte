# pyrefly: ignore [missing-import]
import streamlit as st
import time
import textwrap
import difflib
from mock_data import risk_data, loophole_logs, logic_conflicts, auto_fixes

# ── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LegalInspect | AI Legal Simplifier",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Navigation & Query Parameter State Sync ────────────────────────────────────
qp = st.query_params

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
        "Exploiter": {
            "rewrite": "Vendor may terminate this Agreement at any time for convenience upon five (5) days' notice. Client shall have no right to terminate for convenience and may only terminate for uncured material breach after ninety (90) days.",
            "risk_label": "😈 Extremely Vendor-Favored",
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
        "Exploiter": {
            "rewrite": "Vendor's aggregate liability for all claims shall be strictly capped at five thousand dollars ($5,000). Client's liability under this Agreement shall remain entirely uncapped and unlimited.",
            "risk_label": "😈 Extremely Vendor-Favored",
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
        "Exploiter": {
            "rewrite": "Vendor retains exclusive sole ownership of all intellectual property, work product, and deliverables developed under this Agreement. Client is granted a non-exclusive, revocable license to use the deliverables solely for its internal operations.",
            "risk_label": "😈 Extremely Vendor-Favored",
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
    
</div>
"""

with st.sidebar:
    render_html(sidebar_html)
    st.markdown("<div class='sidebar-divider'></div>", unsafe_allow_html=True)
    st.markdown("<div class='sidebar-section-title'>Document Upload</div>", unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        "Upload Contract (PDF)",
        type=["pdf"],
        label_visibility="collapsed"
    )

    if uploaded_file is not None and not st.session_state['file_uploaded']:
        st.session_state['file_uploaded'] = True
        st.session_state['demo_mode'] = False
        st.session_state['filename'] = uploaded_file.name
        with st.spinner("🤖 Agents analyzing contract..."):
            time.sleep(3)
        st.session_state['analysis_complete'] = True
        # Set query parameters to preserve upload state
        st.query_params.update({
            "page": "Dashboard",
            "analyzed": "true",
            "filename": uploaded_file.name
        })
        st.rerun()

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
                "filename": "NDA_v3.2_Draft.pdf"
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
            st.rerun()

    st.markdown("""
    <div style='margin-top:2rem;font-size:0.72rem;color:#94a3b8;text-align:center;'>
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

    # ── Page: Dashboard ───────────────────────────────────────────────────────
    if current_page == "Dashboard":
        # Determine active highlight coordinates dynamically based on demo or upload mode
        if st.session_state.get('demo_mode', False):
            highlight_x = 410
            highlight_rect_x = 392
            blue_dot_y = 29
            red_dot_y = 87.5
            tooltip_x = 340
            tooltip_text = "Risk exposure: 25%"
        else:
            highlight_x = 650
            highlight_rect_x = 632
            blue_dot_y = 65
            red_dot_y = 45
            tooltip_x = 580
            tooltip_text = f"Risk exposure: {risk_data.get('score', 0)}%"

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
        pages = risk_data['pages_analyzed']
        pages_t = risk_data['pages_trend']
        prec = risk_data['relevant_precedents']
        prec_t = risk_data['precedents_trend']
        risks = risk_data['identified_risks']
        risks_t = risk_data['risks_trend']
        conf = risk_data['ai_confidence']
        conf_t = risk_data['confidence_trend']
        risk_z = risk_data['risk_zone']
        an_date = risk_data['analyzed_date']
        ed_author = risk_data['last_edited']

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
                    <button class="action-btn">+</button>
                    <button class="action-btn">🎛️</button>
                    <button class="action-btn relative">🔔<span class="badge-dot"></span></button>
                    <img src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&fit=crop" class="avatar" alt="Avatar">
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
        for flag in risk_data['red_flags']:
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
                    Adversarial AI Agent Debate
                </h2>
                <p style='color:#64748b;font-size:0.85rem;margin:0;'>
                    The <span style='color:#dc2626;font-weight:600;'>Exploiter</span> probes for
                    vulnerabilities. The <span style='color:#16a34a;font-weight:600;'>Defender</span>
                    evaluates enforceability and legal risk.
                </p>
            </div>
            """)

            for i, log in enumerate(loophole_logs):
                turn = i // 2 + 1
                if log["role"] == "Exploiter":
                    with st.chat_message("Exploiter", avatar="😈"):
                        st.markdown(
                            f"**Exploiter Agent** &nbsp;"
                            f"<span style='font-size:0.75rem;color:#991b1b;background:#fef2f2;"
                            f"padding:2px 8px;border-radius:12px;border:1px solid #fca5a5;'>Turn {turn}</span>",
                            unsafe_allow_html=True
                        )
                        st.write(log['content'])
                else:
                    with st.chat_message("Defender", avatar="🛡️"):
                        st.markdown(
                            f"**Defender Agent** &nbsp;"
                            f"<span style='font-size:0.75rem;color:#166534;background:#f0fdf4;"
                            f"padding:2px 8px;border-radius:12px;border:1px solid #86efac;'>Turn {turn}</span>",
                            unsafe_allow_html=True
                        )
                        st.write(log['content'])

        # Tab Content: Logic Validator
        elif active_tab == "LogicValidator":
            render_html("""
            <div style='margin-bottom:1.5rem;'>
                <h2 style='font-size:1.15rem;font-weight:700;color:#0f172a;margin:0 0 4px 0;'>
                    Logical Contradiction Map
                </h2>
                <p style='color:#64748b;font-size:0.85rem;margin:0;'>
                    Clauses that directly conflict — complying with one may legally violate the other.
                </p>
            </div>
            """)

            sev_styles = {
                "Critical": ("#fef2f2",  "#ef4444", "#fca5a5"),
                "High":     ("#fffbeb", "#fbbf24", "#fcd34d"),
                "Medium":   ("#f0fdf4",  "#22c55e", "#86efac"),
            }

            for conflict in logic_conflicts:
                bg, fg, border = sev_styles.get(conflict['severity'], sev_styles["Medium"])
                render_html(f"""
                <div class="conflict-card" style="background:#ffffff; border:1px solid #f0f1f3; border-radius:12px; padding:1.5rem; margin-bottom:1.25rem; box-shadow:0 1px 3px rgba(0,0,0,0.02);">
                    <div style='display:flex;align-items:center; justify-content:space-between;margin-bottom:1rem;'>
                        <div style="font-size:1.05rem; font-weight:600; color:#111827;">⚡ {conflict['conflict']}</div>
                        <span style='display:inline-block;padding:2px 10px;border-radius:20px;
                            font-size:0.75rem;font-weight:700;background:{bg};
                            color:{fg};border:1px solid {border};'>
                            {conflict['severity']}
                        </span>
                    </div>
                    <div class="rule-box" style="border: 1px solid #f3f4f6; border-radius:8px; padding:12px; font-size:0.85rem; line-height:1.5; margin-bottom:10px; background:#fcfcfc;">
                        <strong>📋 Rule A:</strong> {conflict['rule_a']}
                    </div>
                    <div class="rule-box" style="border: 1px solid #f3f4f6; border-radius:8px; padding:12px; font-size:0.85rem; line-height:1.5; margin-bottom:10px; background:#fcfcfc;">
                        <strong>📋 Rule B:</strong> {conflict['rule_b']}
                    </div>
                    <div style="font-size:0.85rem; color:#4b5563; line-height:1.5; background:#eff6ff; border-radius:8px; padding:12px; border-left:3px solid #3b82f6;">
                        💡 <strong>Analysis:</strong> {conflict['explanation']}
                    </div>
                </div>
                """)

        # Tab Content: Auto-Fixer (Futuristic Dark Glassmorphism Split Screen Negotiation Playbook!)
        elif active_tab == "AutoFixer":
            # Extract state values from URL query parameters
            active_clause_key = qp.get("clause", "Termination Rights")
            active_persona_key = qp.get("persona", "Defender")
            
            # Bounds checking
            if active_clause_key not in playbook_data:
                active_clause_key = "Termination Rights"
            if active_persona_key not in ["Defender", "Exploiter", "Arbitrator"]:
                active_persona_key = "Defender"

            clause_payload = playbook_data[active_clause_key]
            original_text = clause_payload["original"]
            active_severity = clause_payload["severity"]
            
            persona_payload = clause_payload[active_persona_key]
            suggested_text = persona_payload["rewrite"]
            risk_label = persona_payload["risk_label"]
            risk_class = persona_payload["risk_class"]
            score = persona_payload["score"]
            rationale_text = persona_payload["rationale"]

            # Compute dynamic color-coded word highlights on the fly!
            word_diff_html = get_word_diff(original_text, suggested_text)

            # Build Option 1 Persona Toggles and Clause Selectors inside glass header
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
                            <a href="{get_playbook_link('Termination Rights', active_persona_key)}" target="_self" class="glass-btn {'active' if active_clause_key == 'Termination Rights' else ''}">📂 Termination asymmetry</a>
                            <a href="{get_playbook_link('Liability Cap', active_persona_key)}" target="_self" class="glass-btn {'active' if active_clause_key == 'Liability Cap' else ''}">📂 Uncapped Liability</a>
                            <a href="{get_playbook_link('IP Assignment', active_persona_key)}" target="_self" class="glass-btn {'active' if active_clause_key == 'IP Assignment' else ''}">📂 Overbroad IP Scope</a>
                        </div>
                    </div>
                    
                    <!-- Option 1 Persona Toggles -->
                    <div style="display:flex; flex-direction:column; gap:6px;">
                        <div style="font-size:0.7rem; font-weight:600; text-transform:uppercase; color:#9ca3af; letter-spacing:0.06em;">AI Negotiation Profile</div>
                        <div class="persona-container">
                            <a href="{get_playbook_link(active_clause_key, 'Defender')}" target="_self" class="glass-btn {'active' if active_persona_key == 'Defender' else ''}">🛡️ Defender</a>
                            <a href="{get_playbook_link(active_clause_key, 'Exploiter')}" target="_self" class="glass-btn {'active' if active_persona_key == 'Exploiter' else ''}">😈 Exploiter</a>
                            <a href="{get_playbook_link(active_clause_key, 'Arbitrator')}" target="_self" class="glass-btn {'active' if active_persona_key == 'Arbitrator' else ''}">⚖️ Arbitrator</a>
                        </div>
                    </div>
                </div>

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
                            <span class="pane-title">Suggested Rewrite ({active_persona_key} Profile)</span>
                            <span class="glass-risk-pill {risk_class}">{risk_label} ({score})</span>
                        </div>
                        <div class="pane-content">{word_diff_html}</div>
                    </div>
                </div>

                <!-- Rationale Card and Actions -->
                <div style="background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.05); border-radius:12px; padding:1.25rem; margin-top:1.5rem; border-left:4px solid #3b82f6;">
                    <div style="font-size:0.75rem; font-weight:700; text-transform:uppercase; color:#9ca3af; margin-bottom:6px; letter-spacing:0.05em;">💡 AI Negotiation Strategy & Rationale</div>
                    <div style="font-size:0.875rem; color:#e5e7eb; line-height:1.5;">{rationale_text}</div>
                </div>

                <div class="glass-actions-row">
                    <a href="#" class="glass-btn" onclick="alert('Exported Playbook Clause as PDF successfully!')">📥 Export Clause</a>
                    <a href="#" class="glass-btn primary" onclick="navigator.clipboard.writeText(`{suggested_text}`).then(() => alert('Copied Suggested Rewrite to clipboard!'))">📋 Copy Rewrite</a>
                </div>
            </div>
            """
            render_html(glass_controls_html)

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
        render_html(f"""
        <div class="subpage-container">
            <h1 class="subpage-title">📈 Corporate Compliance View</h1>
            <p style="color:#6b7280; font-size:0.85rem; margin-bottom:1.5rem; margin-top:-1rem;">
                AI compliance score across various international regulatory frameworks for the current active document (<strong>{fn}</strong>).
            </p>
            
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:1.25rem; margin-top:1.5rem;">
                <div style="background:#fcfcfc; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem; text-align:center;">
                    <div style="font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">GDPR & Privacy Compliance</div>
                    <div style="font-size:2rem; font-weight:700; color:#059669;">94%</div>
                    <div style="font-size:0.72rem; color:#059669; margin-top:4px; font-weight:500;">🟢 Very Good • Low Risk</div>
                </div>
                <div style="background:#fcfcfc; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem; text-align:center;">
                    <div style="font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">Liability Asymmetry Risk</div>
                    <div style="font-size:2rem; font-weight:700; color:#dc2626;">24%</div>
                    <div style="font-size:0.72rem; color:#dc2626; margin-top:4px; font-weight:500;">🔴 Highly Asymmetrical</div>
                </div>
                <div style="background:#fcfcfc; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem; text-align:center;">
                    <div style="font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">Operational SLA Feasibility</div>
                    <div style="font-size:2rem; font-weight:700; color:#d97706;">81%</div>
                    <div style="font-size:0.72rem; color:#d97706; margin-top:4px; font-weight:500;">🟡 Moderate Risk • Net 45 Terms</div>
                </div>
            </div>
            
            <h3 style="font-size:0.95rem; font-weight:600; color:#111827; margin-top:2rem; margin-bottom:0.75rem;">Framework Conformity Summary</h3>
            <ul style="font-size:0.85rem; color:#4b5563; line-height:1.6; padding-left:1.2rem; margin-bottom:0;">
                <li><strong>GDPR (Data Retention):</strong> Section 2.1 destroys logs within 30 days. Perfect alignment, but conflicts with Section 5.4 regulatory backup requirement (3 years).</li>
                <li><strong>Securities & Exchange Commission (SEC) Audit:</strong> Section 5.4 maintains transactional backups for 3 years, satisfying accounting regulations.</li>
                <li><strong>Commercial Law:</strong> Indemnification wording 'regardless of fault' presents a severe threat under common law indemnification doctrines.</li>
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
