# ⚖️ RegulAIte: Comprehensive Step-by-Step Production Deployment Guide

This guide provides a detailed, step-by-step description of how to deploy the **RegulAIte** corporate document auditor to the cloud, utilizing your GitHub repository at [https://github.com/Shashankcodelover/Regul-Alte.git](https://github.com/Shashankcodelover/Regul-Alte.git).

---

## 🚀 Pathway 1: Streamlit Community Cloud (Frontend - 100% Free & Easiest)

Streamlit Community Cloud is the native hosting platform for Streamlit applications. It compiles requirements automatically, manages server restarts, and links directly to GitHub. 

Because we have built a robust "Graceful Offline Fallback" inside [app.py](file:///d:/users/Shashank%20J/Desktop/my%20stufs/regulaite-ai/app.py) that works directly with your Gemini API Key and rule-based dynamic scanner, the frontend can be deployed completely independently and securely!

### Step 1: Sign Up for Streamlit Share
1. Open your browser and go to [share.streamlit.io](https://share.streamlit.io/).
2. Click **"Connect GitHub account"** (or Sign In with GitHub).
3. Authorize Streamlit to access your GitHub repositories.

### Step 2: Deploy your Repository
1. In your Streamlit Share Workspace, click the prominent **"New app"** button in the top right.
2. In the deployment configuration page, fill in the details:
   - **Repository:** `Shashankcodelover/Regul-Alte` (it should appear in your dropdown list automatically).
   - **Branch:** `main`
   - **Main file path:** `app.py`
3. Click the **"Deploy"** button.
4. *Streamlit will spin up a secure container, pull your code from GitHub, install all Python libraries from `requirements.txt`, and deploy your app.*

### Step 3: Configure Advanced Secrets & API Keys
To protect your Gemini API Key and configure the platform:
1. While your app is compiling (or after it boots), look at the bottom-right corner of the Streamlit dashboard and click the **"Settings"** gear icon (or select the app from your dashboard and click "Settings" -> "Secrets").
2. In the **"Secrets"** text box, paste your environment variables in standard TOML format:
   ```toml
   GEMINI_API_KEY = "your_actual_gemini_api_key_here"
   SERVER_PORT = "8000"
   ```
3. Click **"Save"**. Streamlit will automatically hot-reload the app to consume these secure credentials without exposing them in your public code!

---

## ⚙️ Pathway 2: Deploying the FastAPI Multi-Agent Backend on Render.com

If you want the advanced **5-Agent AI Orchestration pipeline** (Claude-powered Multi-Agent Debates and Z3 formal verification) active in the cloud, you can deploy the FastAPI server to **Render.com** (which offers a free tier for Python web services).

### Step 1: Sign Up for Render
1. Open your browser and go to [Render.com](https://render.com/).
2. Click **"Sign Up"** and authenticate using your **GitHub account**.

### Step 2: Create a New Web Service
1. On your Render dashboard, click the blue **"New +"** button in the top right, and select **"Web Service"**.
2. Connect your GitHub repository:
   - Locate and select the **`Regul-Alte`** repository from your connected GitHub account list.
3. Configure the web service settings:
   - **Name:** `regulaite-backend` (or similar)
   - **Region:** Choose the region closest to you (e.g., `Singapore` or `Oregon`)
   - **Branch:** `main`
   - **Runtime:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn backend.server:app --host 0.0.0.0 --port $PORT`
     *(Render automatically maps the dynamic port via the `$PORT` environment variable)*
   - **Instance Type:** Select **"Free"**

### Step 3: Add Backend Environment Variables
1. Scroll down to the **"Environment Variables"** section (or go to the "Environment" tab in the sidebar after creation).
2. Click **"Add Environment Variable"** and define:
   - Key: `ANTHROPIC_API_KEY` | Value: `your_claude_api_key_here`
   - Key: `SERVER_PORT` | Value: `8000`
3. Click **"Create Web Service"**. Render will build the virtual environment, install the Z3 solver, and deploy your asynchronous API.
4. Copy the generated public URL of your service (e.g., `https://regulaite-backend.onrender.com`).

### Step 4: Link Frontend to the Render Backend
Now that your backend has a public URL, tell your Streamlit frontend to connect to it!
1. Open your **Streamlit Share** dashboard.
2. Go to **Settings** -> **Secrets**.
3. Add or update the backend URL secret so the frontend routes the audits to Render:
   ```toml
   # Inside Streamlit Secrets
   SERVER_URL = "https://regulaite-backend.onrender.com"
   ```
4. Save the secrets. The entire unified stack is now connected and running in the cloud!

---

## 📈 Post-Deployment Verification Checklist

Once deployed, visit your live Streamlit site and run this quick validation checklist:
- [x] **Secure Landing Portal:** The website should prompt you to register or log in (or enter demo mode), securing all dashboard pages.
- [x] **Personalized Greetings:** Once logged in or using the demo, the premium welcome card displays your name and the autoplaying walkthrough video (`docs/Screen Recording 2026-05-23 195222.mp4`) flawlessly.
- [x] **Dynamic Analysis Coordination:**
  - Paste an asymmetric contract (e.g., Unilateral Vendor Indemnity or Uncapped Vendor Liability).
  - Verify that the risk score rises to a high value.
  - Verify that the **Reciprocity Speedometer** needle skews heavily to the right/left to reflect the asymmetry instead of staying balanced at `0°`.
  - Verify that the **SVG Trend Line Graph**'s red risk dot moves up dynamically in sync with the calculated score.
