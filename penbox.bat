@echo off
setlocal
set "SCRIPT_DIR=%~dp0"

if not exist "%SCRIPT_DIR%.venv-penbox\Scripts\python.exe" (
    echo [PenBox] Environnement introuvable. Lancez setup.bat d'abord.
    pause
    exit /b 1
)

"%SCRIPT_DIR%.venv-penbox\Scripts\python.exe" "%SCRIPT_DIR%penbox_app.py"

if errorlevel 1 (
    echo.
    echo [PenBox] L'application s'est terminee avec une erreur.
    pause
)
