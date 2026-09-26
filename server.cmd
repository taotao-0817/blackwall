@echo off
rem ============================================================
rem  BlackWall - HTTP Gateway launcher (Windows)
rem  Picks a Python 3.10+ interpreter via the py launcher,
rem  installs fastapi + uvicorn on first run, then starts
rem  the gateway at http://127.0.0.1:8765
rem ============================================================
chcp 65001 >nul
cd /d "%~dp0"

set "PYCMD=py -3.12"
py -3.12 -c "pass" >nul 2>&1 || set "PYCMD=py -3"

%PYCMD% -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
  echo [BlackWall] First run: installing gateway dependencies ...
  %PYCMD% -m pip install -r requirements.txt
  %PYCMD% -c "import fastapi, uvicorn" >nul 2>&1
  if errorlevel 1 (
    echo [BlackWall] Install failed. Run manually: %PYCMD% -m pip install fastapi uvicorn
    pause
    exit /b 1
  )
)

echo [BlackWall] Gateway starting at http://127.0.0.1:8765   [Ctrl+C to stop]
%PYCMD% server.py
pause
