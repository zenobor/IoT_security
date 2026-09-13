"""Desktop interface for the IoT vulnerability scanner."""

import sys
from pathlib import Path

from PySide6.QtCore import QProcess, Qt
from PySide6.QtGui import QDesktopServices
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
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


class ScannerWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.project_dir = Path(__file__).parent
        self.process = QProcess(self)
        self.process.setWorkingDirectory(str(self.project_dir))
        self.process.readyReadStandardOutput.connect(self.read_process_output)
        self.process.readyReadStandardError.connect(self.read_process_output)
        self.process.finished.connect(self.scan_finished)

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
        self.open_button = QPushButton("Open Markdown report")
        self.open_button.clicked.connect(self.open_report)
        self.open_button.setEnabled(False)
        actions.addWidget(self.scan_button)
        actions.addWidget(self.open_button)
        actions.addStretch()
        layout.addLayout(actions)

        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output, 1)
        self.setCentralWidget(central)

    def start_scan(self) -> None:
        if self.process.state() != QProcess.NotRunning:
            return
        self.log_output.clear()
        self.open_button.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.status_label.setText("Scanning...")

        arguments = [
            "main.py",
            "--network",
            self.network_input.text().strip(),
            "--timeout",
            str(self.timeout_input.value()),
            "--mode",
            self.mode_input.currentText(),
            "--output",
            "scan_report.md",
            "--html-output",
            "scan_report.html",
            "--csv-output",
            "scan_results.csv",
            "--json-output",
            "scan_results.json",
        ]
        if self.ports_input.text().strip():
            arguments.extend(["--ports", self.ports_input.text().strip()])
        if self.offline_input.isChecked():
            arguments.append("--offline")
        if self.nvd_input.isChecked():
            arguments.append("--nvd")
        self.process.start(sys.executable, arguments)

    def read_process_output(self) -> None:
        output = bytes(self.process.readAllStandardOutput()).decode(errors="replace")
        errors = bytes(self.process.readAllStandardError()).decode(errors="replace")
        text = output + errors
        if text:
            self.log_output.appendPlainText(text.rstrip())

    def scan_finished(self, exit_code: int, _exit_status: QProcess.ExitStatus) -> None:
        self.scan_button.setEnabled(True)
        if exit_code == 0:
            self.status_label.setText("Scan finished. Reports are ready.")
            self.open_button.setEnabled(True)
        else:
            self.status_label.setText("Scan failed. Check the log.")
            QMessageBox.warning(self, "Scan failed", "The scanner returned an error.")

    def open_report(self) -> None:
        report_path = self.project_dir / "scan_report.md"
        QDesktopServices.openUrl(report_path.as_uri())


def main() -> None:
    app = QApplication(sys.argv)
    window = ScannerWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()