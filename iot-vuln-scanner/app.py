"""Desktop interface for the IoT vulnerability scanner."""

import os
import json
import sys
from pathlib import Path

from PySide6.QtCore import QProcess, QUrl, Qt
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


class ScannerWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.project_dir = Path(__file__).parent
        self.output_dir = (
            Path.home() / "IoTScannerReports"
            if getattr(sys, "frozen", False)
            else self.project_dir
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.markdown_report = self.output_dir / "scan_report.md"
        self.html_report = self.output_dir / "scan_report.html"
        self.csv_report = self.output_dir / "scan_results.csv"
        self.json_report = self.output_dir / "scan_results.json"
        self.cancel_requested = False
        self.process = QProcess(self)
        self.process.setWorkingDirectory(str(self.project_dir))
        self.process.readyReadStandardOutput.connect(self.read_process_output)
        self.process.readyReadStandardError.connect(self.read_process_output)
        self.process.finished.connect(self.scan_finished)
        self.process.errorOccurred.connect(self.process_error)

        self.setWindowTitle("IoT Vulnerability Scanner")
        self.resize(900, 650)
        self.build_ui()

    def build_ui(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background: #f4f6f8; }
            QGroupBox { font-weight: bold; margin-top: 12px; padding: 12px; }
            QLineEdit, QComboBox, QSpinBox { padding: 6px; }
            QPushButton { padding: 8px 14px; }
            QPushButton#scanButton { background: #176b4d; color: white; font-weight: bold; }
            QPlainTextEdit { background: #17202a; color: #d9f7e8; font-family: Consolas; }
            """
        )

        central = QWidget()
        layout = QVBoxLayout(central)

        title = QLabel("IoT Vulnerability Scanner")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #173b57;")
        subtitle = QLabel("Scan only networks you own or are authorized to test.")
        subtitle.setStyleSheet("color: #52616b;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        settings = QGroupBox("Scan settings")
        form = QFormLayout(settings)
        self.network_input = QLineEdit("192.168.1.0/24")
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Example: 22,80,443,554")
        self.mode_input = QComboBox()
        self.mode_input.addItems(["quick", "full"])
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 30)
        self.timeout_input.setValue(2)
        self.offline_input = QCheckBox("Do not use Internet services")
        self.nvd_input = QCheckBox("Query NVD for CVEs")
        form.addRow("Network", self.network_input)
        form.addRow("Ports", self.ports_input)
        form.addRow("Mode", self.mode_input)
        form.addRow("ARP timeout", self.timeout_input)
        form.addRow("Options", self.offline_input)
        form.addRow("", self.nvd_input)
        layout.addWidget(settings)

        actions = QHBoxLayout()
        self.scan_button = QPushButton("Start scan")
        self.scan_button.setObjectName("scanButton")
        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setEnabled(False)
        self.open_button = QPushButton("Open HTML")
        self.open_button.clicked.connect(lambda: self.open_report(self.html_report))
        self.open_button.setEnabled(False)
        self.open_csv_button = QPushButton("Open CSV")
        self.open_csv_button.clicked.connect(lambda: self.open_report(self.csv_report))
        self.open_csv_button.setEnabled(False)
        actions.addWidget(self.scan_button)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.open_button)
        actions.addWidget(self.open_csv_button)
        actions.addStretch()
        layout.addLayout(actions)

        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(
            ["IP", "Hostname", "Type", "Vendor", "Model", "Risk"]
        )
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.results_table, 1)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        layout.addWidget(self.log_output, 1)
        self.setCentralWidget(central)

    def start_scan(self) -> None:
        if self.process.state() != QProcess.NotRunning:
            return
        self.log_output.clear()
        self.results_table.setRowCount(0)
        self.cancel_requested = False
        self.open_button.setEnabled(False)
        self.open_csv_button.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status_label.setText("Scanning...")

        scan_arguments = [
            "--network",
            self.network_input.text().strip(),
            "--timeout",
            str(self.timeout_input.value()),
            "--mode",
            self.mode_input.currentText(),
            "--output",
            str(self.markdown_report),
            "--html-output",
            str(self.html_report),
            "--csv-output",
            str(self.csv_report),
            "--json-output",
            str(self.json_report),
        ]
        if self.ports_input.text().strip():
            scan_arguments.extend(["--ports", self.ports_input.text().strip()])
        if self.offline_input.isChecked():
            scan_arguments.append("--offline")
        if self.nvd_input.isChecked():
            scan_arguments.append("--nvd")

        if getattr(sys, "frozen", False):
            program = sys.executable
            arguments = ["--scan-cli", *scan_arguments]
        else:
            program = sys.executable
            arguments = ["main.py", *scan_arguments]
        self.process.start(program, arguments)

    def read_process_output(self) -> None:
        output = bytes(self.process.readAllStandardOutput()).decode(errors="replace")
        errors = bytes(self.process.readAllStandardError()).decode(errors="replace")
        text = output + errors
        if text:
            self.log_output.appendPlainText(text.rstrip())

    def scan_finished(self, exit_code: int, _exit_status: QProcess.ExitStatus) -> None:
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        if self.cancel_requested:
            self.status_label.setText("Scan cancelled.")
            return
        if exit_code == 0:
            self.load_results()
            self.status_label.setText("Scan finished. Reports are ready.")
            self.open_button.setEnabled(True)
            self.open_csv_button.setEnabled(True)
        else:
            self.status_label.setText("Scan failed. Check the log.")
            QMessageBox.warning(self, "Scan failed", "The scanner returned an error.")

    def cancel_scan(self) -> None:
        if self.process.state() != QProcess.NotRunning:
            self.cancel_requested = True
            self.process.kill()
            self.status_label.setText("Scan cancelled.")

    def load_results(self) -> None:
        try:
            data = json.loads(self.json_report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.status_label.setText("Scan finished, but results could not be loaded.")
            return

        devices = data.get("devices", [])
        self.results_table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            identity = device.get("identity", {})
            values = [
                device.get("ip", ""),
                device.get("hostname", "Unknown hostname"),
                identity.get("type", "Unknown device"),
                identity.get("vendor", device.get("vendor", "Unknown vendor")),
                identity.get("model", "Unknown model"),
                device.get("risk", "low").upper(),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 5:
                    colors = {"HIGH": "#b42318", "MEDIUM": "#b54708", "LOW": "#176b4d"}
                    item.setForeground(QColor(colors.get(str(value), "#222222")))
                self.results_table.setItem(row, column, item)
        self.results_table.resizeColumnsToContents()

    def process_error(self, _error: QProcess.ProcessError) -> None:
        self.scan_button.setEnabled(True)
        self.status_label.setText("Could not start the scanner.")
        self.log_output.appendPlainText(self.process.errorString())

    def open_report(self, requested_path: Path | None = None) -> None:
        report_path = requested_path or self.html_report
        if not report_path.exists() and requested_path is not None:
            report_path = self.markdown_report
        if not report_path.exists():
            QMessageBox.information(self, "Report not found", "Run a scan first.")
            return
        if sys.platform == "win32":
            os.startfile(str(report_path))
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(report_path)))


def main() -> None:
    app = QApplication(sys.argv)
    window = ScannerWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    if "--scan-cli" in sys.argv:
        sys.argv.remove("--scan-cli")
        from main import main as run_cli

        run_cli()
    else:
        main()