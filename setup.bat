@echo off
setlocal

where uv >nul 2>&1
if errorlevel 1 (
    echo [PenBox] "uv" est introuvable dans le PATH.
    echo Installez-le depuis https://docs.astral.sh/uv/ puis relancez ce script.
    exit /b 1
)

echo [PenBox] Creation du venv 64 bits (.venv-penbox, Python 3.12)...
uv venv --python 3.12 --clear .venv-penbox
if errorlevel 1 (
    echo [PenBox] Echec de creation du venv.
    exit /b 1
)

echo [PenBox] Installation des dependances...
uv pip install --python .venv-penbox -r requirements.txt
if errorlevel 1 (
    echo [PenBox] Echec de l'installation des dependances.
    exit /b 1
)

echo [PenBox] OK. Verification de PySide6/PyYAML...
.venv-penbox\Scripts\python.exe -c "import PySide6, yaml; print('PySide6', PySide6.__version__, '/ PyYAML OK')"
if errorlevel 1 (
    echo [PenBox] PySide6 ou PyYAML indisponible dans le venv.
    exit /b 1
)

echo.
echo [PenBox] Environnement pret. Lancer avec :
echo   .venv-penbox\Scripts\python.exe penbox_app.py
