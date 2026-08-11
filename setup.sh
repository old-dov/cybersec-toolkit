#!/usr/bin/env bash
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
    echo "[PenBox] \"uv\" est introuvable dans le PATH."
    echo "Installez-le depuis https://docs.astral.sh/uv/ puis relancez ce script."
    exit 1
fi

echo "[PenBox] Creation du venv 64 bits (.venv-penbox, Python 3.12)..."
uv venv --python 3.12 --clear .venv-penbox

echo "[PenBox] Installation des dependances..."
uv pip install --python .venv-penbox -r requirements.txt

echo "[PenBox] Verification de PySide6/PyYAML..."
.venv-penbox/bin/python -c "import PySide6, yaml; print('PySide6', PySide6.__version__, '/ PyYAML OK')"

echo
echo "[PenBox] Environnement pret. Lancer avec :"
echo "  .venv-penbox/bin/python penbox_app.py"
