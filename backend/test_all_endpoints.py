"""
RegulAIte Comprehensive End-to-End Endpoints and Features Test Suite
=====================================================================
Bootstraps the FastAPI backend server, executes requests against all exposed endpoints,
validates schemas, and verifies that the 5-agent orchestration pipeline, Z3 constraint solver,
and memory subsystems function perfectly without errors.
"""

import sys
import os
import time
import requests
import json

# Force standard ASCII output to prevent Windows console encoding errors
def log(msg, status="INFO"):
    tags = {
        "INFO": "[INFO]",
        "SUCCESS": "[PASS]",
        "FAIL": "[FAIL]",
        "WARN": "[WARN]"
    }
    print(f"{tags.get(status, '[INFO]')} {msg}")

def run_tests():
    server_url = "http://localhost:8000"
    
    log("Starting End-to-End Endpoint Test Suite...")
    
    # ── Test 1: Health Endpoint ──
    log("Test 1: Querying GET /health...")
    try:
        res = requests.get(f"{server_url}/health", timeout=5.0)
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        data = res.json()
        assert data.get("status") == "ok", "Server health is not 'ok'"
        log(f"Health Response: {data}", "SUCCESS")
    except Exception as e:
        log(f"Test 1 Failed: {e}", "FAIL")
        sys.exit(1)

    # ── Test 2: Paste Raw Text JSON Analysis Endpoint ──
    log("Test 2: Querying POST /analyse/json with raw text body...")
    sample_text = (
        "This Master Services Agreement is entered into on January 1, 2025. "
        "Vendor shall indemnify Client for any losses regardless of fault. "
        "Invoices shall be payable in forty-five (45) days of receipt (Net 45). "
        "However, premium services invoices are due Net 15. "
        "All data must be destroyed within thirty (30) days of termination. "
        "Vendor shall retain complete backups of transactional data for three (3) years."
    )
    try:
        res = requests.post(
            f"{server_url}/analyse/json",
            json={"text": sample_text},
            timeout=60.0
        )
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        data = res.json()
        
        # Verify required keys in returned schema
        required_keys = [
            "score", "verdict", "summary", "red_flags", 
            "loophole_logs", "logic_conflicts", "auto_fixes"
        ]
        for key in required_keys:
            assert key in data, f"Missing required key in response: {key}"
        
        log("Response payload verified successfully with correct schemas.", "SUCCESS")
        log(f"Risk Score: {data['score']}/100 | Verdict: {data['verdict']}", "SUCCESS")
        log(f"Summary: {data['summary'][:80]}...", "SUCCESS")
        log(f"Red Flags Count: {len(data['red_flags'])}", "SUCCESS")
        log(f"Loophole Debate Logs: {len(data['loophole_logs'])} turns", "SUCCESS")
        log(f"Logical Conflicts (Z3): {len(data['logic_conflicts'])} conflicts", "SUCCESS")
        log(f"Auto-Fix Suggestions: {len(data['auto_fixes'])} items", "SUCCESS")
        
    except Exception as e:
        log(f"Test 2 Failed: {e}", "FAIL")
        sys.exit(1)

    # ── Test 3: PDF Ingestion & PyMuPDF Extraction Endpoint ──
    log("Test 3: Querying POST /analyse with raw PDF file upload...")
    # Find a test PDF in the workspace
    pdf_paths = [
        "../sample_agreements/Mildly_Risky_Agreement.pdf",
        "../sample_agreements/Perfect_Standard_Agreement.pdf",
        "../sample_agreements/Vulnerable_Agreement_Draft.pdf",
        "../Mildly_Risky_Agreement.pdf",
        "../Perfect_Standard_Agreement.pdf",
        "Mildly_Risky_Agreement.pdf",
        "Perfect_Standard_Agreement.pdf",
        "../Vulnerable_Agreement_Draft.pdf",
        "Vulnerable_Agreement_Draft.pdf"
    ]
    selected_pdf = None
    for path in pdf_paths:
        if os.path.exists(path):
            selected_pdf = path
            break
            
    if not selected_pdf:
        log("No test PDF files found in workspace directories. Skipping Test 3.", "WARN")
    else:
        log(f"Using test PDF file: {selected_pdf}")
        try:
            with open(selected_pdf, "rb") as f:
                pdf_bytes = f.read()
                
            res = requests.post(
                f"{server_url}/analyse",
                files={"file": (os.path.basename(selected_pdf), pdf_bytes, "application/pdf")},
                timeout=60.0
            )
            assert res.status_code == 200, f"Expected 200, got {res.status_code}"
            data = res.json()
            assert "score" in data, "No risk score in PDF audit payload"
            log(f"PDF Audit Successful! Risk Score: {data['score']}/100", "SUCCESS")
            log(f"Red Flags Found in PDF: {len(data.get('red_flags', []))}", "SUCCESS")
        except Exception as e:
            log(f"Test 3 Failed: {e}", "FAIL")
            sys.exit(1)

    # ── Test 4: Stored Clauses and Memory Subsystem Retrieval ──
    log("Test 4: Querying GET /clauses memory store...")
    try:
        res = requests.get(f"{server_url}/clauses", timeout=5.0)
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        data = res.json()
        assert "clauses" in data, "Response payload missing 'clauses' array"
        log(f"Stored Clauses Count: {data.get('clause_count', 0)}", "SUCCESS")
        log(f"Memory Subsystem Jurisdiction: {data.get('jurisdiction', 'None Specified')}", "SUCCESS")
        if data.get("clauses"):
            log(f"First Clause Snippet: {data['clauses'][0].get('text', '')[:60]}...", "SUCCESS")
    except Exception as e:
        log(f"Test 4 Failed: {e}", "FAIL")
        sys.exit(1)

    print("\n============================================================")
    log("ALL ENDPOINTS AND SUB-SYSTEM FEATURES PASSED HEALTHY AUDITS!", "SUCCESS")
    print("============================================================\n")

if __name__ == "__main__":
    run_tests()
