@echo off
echo ============================================
echo  RegulAIte Backend + Frontend Launcher
echo ============================================
echo.

REM Check if .env exists, if not copy from example
if not exist ".env" (
    echo [INFO] No .env found. Copying from .env.example...
    copy .env.example .env
    echo [WARN] Please edit .env and add your ANTHROPIC_API_KEY before running.
    echo        Without it, the backend runs in stub mode with demo data.
    echo.
)

REM Install dependencies
echo [INFO] Installing Python dependencies...
pip install -r requirements.txt --quiet

echo.
echo [INFO] Starting FastAPI backend on http://localhost:8000 ...
start "RegulAIte Backend" cmd /k "cd /d %~dp0 && python backend/server.py"

echo [INFO] Waiting 3 seconds for backend to start...
timeout /t 3 /nobreak >nul

echo [INFO] Starting Streamlit frontend...
start "RegulAIte Frontend" cmd /k "cd /d %~dp0 && streamlit run app.py --server.port 8501"

echo.
echo ============================================
echo  Backend:  http://localhost:8000
echo  Frontend: http://localhost:8501
echo  Health:   http://localhost:8000/health
echo ============================================
echo.
echo Both windows are now open. Press any key to exit this launcher.
pause >nul
