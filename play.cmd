@echo off
rem ============================================================
rem  BlackWall - Interactive Console launcher (Windows)
rem  Picks a Python 3.10+ interpreter via the py launcher.
rem  A running gateway is required in another window:
rem      server.cmd   (or:  py -3.12 server.py)
rem ============================================================
chcp 65001 >nul
cd /d "%~dp0"

set "PYCMD=py -3.12"
py -3.12 -c "pass" >nul 2>&1 || set "PYCMD=py -3"

%PYCMD% play.py
echo.
pause
