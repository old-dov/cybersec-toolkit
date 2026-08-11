"""Bootstrap sans console pour PenBox.

Le pythonw.exe genere dans .venv-penbox par uv est en subsystem CONSOLE
(bug/limitation de uv), donc le lancer directement ouvre un terminal.
On lance ici le vrai pythonw.exe (subsystem GUI) de l'installation Python
de base, et on injecte manuellement le site-packages du venv.
"""

import runpy
import site
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Les scripts du catalogue sont relancés en sous-processus via sys.executable
# (voir runner.py/ui/jobs.py) : sans cette réaffectation, ils héritent du
# pythonw.exe "nu" d'uv ci-dessus (pas celui du venv), donc sans ses paquets
# (dnspython, python-whois...) — l'UI elle-même reste sur l'interpréteur déjà
# chargé, seule cette variable change pour les futurs sous-processus.
sys.executable = str(ROOT / ".venv-penbox" / "Scripts" / "python.exe")
site.addsitedir(str(ROOT / ".venv-penbox" / "Lib" / "site-packages"))
sys.path.insert(0, str(ROOT))

runpy.run_path(str(ROOT / "penbox_app.py"), run_name="__main__")

