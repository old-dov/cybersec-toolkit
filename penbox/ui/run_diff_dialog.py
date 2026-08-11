"""Comparateur de scans — identifie les findings apparus ou disparus entre
deux runs (même outil, exécutions à des dates différentes). L'identité d'un
finding pour la comparaison est (nom, catégorie, détail) : le run_id et le
risque/faux-positif (modifiables après coup) ne doivent pas faire croire à
tort qu'un finding est "nouveau"."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from penbox.store import Store

STATUS_LABEL = {"new": "🆕 Nouveau", "resolved": "✅ Disparu"}


def _finding_key(row) -> tuple:
    return (row["name"], row["category"], row["detail"])


class RunDiffDialog(QDialog):
    def __init__(self, store: Store, project_id: int, parent=None):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Comparer deux scans")
        self.setMinimumSize(640, 420)

        runs = store.list_runs(project_id)  # plus récent en premier
        self.run_a_combo = QComboBox()
        self.run_b_combo = QComboBox()
        for combo in (self.run_a_combo, self.run_b_combo):
            for run in runs:
                combo.addItem(f"#{run['id']} — {run['tool_id']} — {run['started_at']}", run["id"])
        # Par défaut : A = run le plus ancien des deux derniers, B = le plus récent.
        if len(runs) >= 2:
            self.run_a_combo.setCurrentIndex(1)
            self.run_b_combo.setCurrentIndex(0)

        form = QFormLayout()
        form.addRow("Run de référence (ancien) :", self.run_a_combo)
        form.addRow("Run à comparer (nouveau) :", self.run_b_combo)

        self.compare_btn = QPushButton("Comparer")
        self.compare_btn.clicked.connect(self._compare)

        self.summary_label = QLabel("")

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Statut", "Nom", "Catégorie", "Risque"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.compare_btn)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table)
        layout.addWidget(buttons)

        if len(runs) < 2:
            self.compare_btn.setEnabled(False)
            self.summary_label.setText("Il faut au moins deux runs dans ce projet pour comparer.")

    def _compare(self) -> None:
        run_a = self.run_a_combo.currentData()
        run_b = self.run_b_combo.currentData()
        if run_a is None or run_b is None:
            return
        if run_a == run_b:
            self.summary_label.setText("Choisissez deux runs différents.")
            self.table.setRowCount(0)
            return

        findings_a = {_finding_key(f): f for f in self.store.get_findings_for_run(run_a)}
        findings_b = {_finding_key(f): f for f in self.store.get_findings_for_run(run_b)}

        new_findings = [f for k, f in findings_b.items() if k not in findings_a]
        resolved_findings = [f for k, f in findings_a.items() if k not in findings_b]
        unchanged_count = len(findings_a) - len(resolved_findings)  # = len(findings_b) - len(new_findings)

        self.summary_label.setText(
            f"{len(new_findings)} nouveau(x) · {len(resolved_findings)} disparu(s) "
            f"· {unchanged_count} inchangé(s) sur les deux runs"
        )

        rows = [("new", f) for f in new_findings] + [("resolved", f) for f in resolved_findings]
        self.table.setRowCount(len(rows))
        for i, (status, f) in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(STATUS_LABEL[status]))
            self.table.setItem(i, 1, QTableWidgetItem(f["name"]))
            self.table.setItem(i, 2, QTableWidgetItem(f["category"]))
            self.table.setItem(i, 3, QTableWidgetItem(f["risk"]))
