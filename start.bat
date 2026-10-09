@echo off
title Bug Bounty AI - Baslaniyor...
cd /d "%~dp0"

echo.
echo ============================================
echo   Bug Bounty Micro-SaaS - Sistem Baslatma
echo ============================================
echo.

:: Python launcher sec: once "py", yoksa "python"
set "PY=py"
where py >nul 2>nul || set "PY=python"

:: .env dosyasindan token'lari oku (trim ile)
if not exist ".env" (
    echo [HATA] .env dosyasi bulunamadi.
    pause
    exit /b 1
)

for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
    set "%%a=%%b"
)

:: Trailing space temizle
for /f "tokens=*" %%a in ("%BUGBOUNTY_TG_TOKEN%") do set "BUGBOUNTY_TG_TOKEN=%%a"
for /f "tokens=*" %%a in ("%BUGBOUNTY_TG_CHAT_ID%") do set "BUGBOUNTY_TG_CHAT_ID=%%a"
for /f "tokens=*" %%a in ("%ANTHROPIC_API_KEY%") do set "ANTHROPIC_API_KEY=%%a"

:: venv yok -> global Python kullaniliyor.
:: Bagimliliklar global'e kurulu (pip install -r requirements.txt).

echo [1/4] FastAPI + Dashboard baslatiliyor (port 8000)...
echo        Panel: http://127.0.0.1:8000/dashboard
start "FastAPI - Merkezi Omurga + Dashboard" cmd /k "cd /d "%~dp0" && %PY% -m uvicorn main:app --port 8000"

timeout /t 3 /nobreak > nul

echo [2/4] Telegram Bot baslatiliyor...
start "Telegram Bot" cmd /k "cd /d "%~dp0" && set "BUGBOUNTY_TG_TOKEN=%BUGBOUNTY_TG_TOKEN%" && set "BUGBOUNTY_TG_CHAT_ID=%BUGBOUNTY_TG_CHAT_ID%" && %PY% telegram_bot.py"

timeout /t 3 /nobreak > nul

echo [3/4] Triyaj Daemon baslatiliyor (her 60 saniyede bir)...
start "Triyaj Daemon - Ollama" cmd /k "cd /d "%~dp0" && %PY% triage_worker.py --daemon --interval 60"

timeout /t 3 /nobreak > nul

echo [4/4] Claude Analyzer baslatiliyor (her 120 saniyede bir)...
start "Claude Analyzer - Katman 4" cmd /k "cd /d "%~dp0" && set "BUGBOUNTY_TG_TOKEN=%BUGBOUNTY_TG_TOKEN%" && set "BUGBOUNTY_TG_CHAT_ID=%BUGBOUNTY_TG_CHAT_ID%" && set "ANTHROPIC_API_KEY=%ANTHROPIC_API_KEY%" && %PY% claude_analyzer.py --daemon --interval 120"

echo.
echo ============================================
echo   Sistem aktif! 4 pencere acildi.
echo   Panel: http://127.0.0.1:8000/dashboard
echo   Telegram'dan /stats yaz.
echo ============================================
echo.
pause
