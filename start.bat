@echo off
setlocal enabledelayedexpansion

:: ================================================================
:: The Open OSINT Board — Windows Startup Script
:: Compatible: Windows 10 (1803+), Windows 11
:: Requires: Python 3.8 or higher
:: ================================================================

title The Open OSINT Board

echo.
echo  +==================================================+
echo  ^|        The Open OSINT Board — OSINT Dashboard        ^|
echo  +==================================================+
echo.

set "SCRIPT_DIR=%~dp0"
set "BACKEND=%SCRIPT_DIR%backend"
set "FRONTEND=%SCRIPT_DIR%frontend\index.html"

:: ── Check frontend exists ───────────────────────────────────────
if not exist "%FRONTEND%" (
    echo [!] ERROR: frontend\index.html not found.
    echo     Make sure your folder structure is:
    echo       The_OSINT_Dashboard\
    echo         start.bat
    echo         backend\server.py
    echo         frontend\index.html
    echo.
    pause
    exit /b 1
)

:: ── Check backend exists ────────────────────────────────────────
if not exist "%BACKEND%\server.py" (
    echo [!] ERROR: backend\server.py not found.
    pause
    exit /b 1
)

:: ── Find Python ─────────────────────────────────────────────────
echo [*] Checking for Python 3.8+...
set PYTHON=

:: Try 'python' first
python --version >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
    set PYTHON=python
    goto :found_python
)

:: Try 'python3'
python3 --version >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=2" %%v in ('python3 --version 2^>^&1') do set PYVER=%%v
    set PYTHON=python3
    goto :found_python
)

:: Try 'py' launcher (Windows Store Python)
py --version >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=2" %%v in ('py --version 2^>^&1') do set PYVER=%%v
    set PYTHON=py
    goto :found_python
)

echo [!] Python not found. Please install Python 3.8+ from:
echo     https://www.python.org/downloads/
echo     IMPORTANT: Check "Add Python to PATH" during install.
echo.
pause
exit /b 1

:found_python
echo     Found: Python !PYVER! using '!PYTHON!'
echo.

:: ── Install/verify dependencies ─────────────────────────────────
echo [*] Installing/checking dependencies...
!PYTHON! -m pip install --upgrade pip --quiet 2>nul
!PYTHON! -m pip install -r "%BACKEND%\requirements.txt" --quiet 2>nul
if errorlevel 1 (
    echo     [!] pip install failed. Trying with --user flag...
    !PYTHON! -m pip install -r "%BACKEND%\requirements.txt" --quiet --user 2>nul
)
echo     [OK] Dependencies ready
echo.

:: ── Free up port 5000 if occupied ──────────────────────────────
echo [*] Checking port 5000...
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":5000 " ^| findstr "LISTENING"') do (
    echo     Freeing port 5000 ^(PID %%a^)...
    taskkill /PID %%a /F >nul 2>&1
)
echo     [OK] Port 5000 ready
echo.

:: ── Start backend ───────────────────────────────────────────────
echo [*] Starting The Open OSINT Board backend...
cd /d "%BACKEND%"
start "TOOB Backend" /min cmd /c "!PYTHON! server.py 2>&1 & echo. & echo Backend stopped. Press any key... & pause >nul"
echo     [OK] Backend process launched
echo.

:: ── Wait for backend to respond ─────────────────────────────────
echo [*] Waiting for backend to initialize...
set /a TRIES=0

:WAIT_LOOP
set /a TRIES+=1
if !TRIES! gtr 30 (
    echo.
    echo     [!] Backend slow to start. Opening dashboard anyway.
    echo         If feeds show errors, wait 30s and refresh the page.
    goto :OPEN
)
curl -s --max-time 1 http://localhost:5000/api/status >nul 2>&1
if not errorlevel 1 (
    echo     [OK] Backend responding ^(!TRIES! sec^)
    goto :OPEN
)
<nul set /p "=."
timeout /t 1 /nobreak >nul
goto :WAIT_LOOP

:OPEN
echo.
echo  +==================================================+
echo  ^|  The Open OSINT Board is running!                  ^|
echo  ^|                                                  ^|
echo  ^|  Backend:   http://localhost:5000                ^|
echo  ^|  Status:    http://localhost:5000/api/status     ^|
echo  ^|                                                  ^|
echo  ^|  Opening dashboard in your browser...            ^|
echo  +==================================================+
echo.

:: Open dashboard — cmd /c start is the most reliable method
:: across Windows 10 and 11 for opening HTML files
cmd /c start "" /b "%FRONTEND%"

echo  Feeds will populate within 15-30 seconds.
echo  Keep this window open — closing it stops the backend.
echo.
echo  Press any key to STOP and exit.
echo.
pause >nul

:: ── Cleanup ─────────────────────────────────────────────────────
echo.
echo [*] Stopping backend...
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":5000 " ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)
echo     [OK] Stopped. Goodbye.
timeout /t 2 /nobreak >nul
endlocal
