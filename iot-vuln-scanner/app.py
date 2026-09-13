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
    QProgressBar,
    QStyleFactory,
    QTableWidget,
    QTableWidgetItem,
    QSpinBox,
    QTabWidget,
    QTextBrowser,
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
        self.resize(980, 700)
        self.setMinimumSize(820, 560)
        self.build_ui()

    def build_ui(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background: #e9edf2; }
            QGroupBox { color: #173b57; font-weight: bold; margin-top: 10px; padding: 10px; border: 1px solid #aeb9c6; border-radius: 2px; background: #f7f8fa; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; background: #e9edf2; }
            QLineEdit, QComboBox, QSpinBox { min-height: 23px; padding: 2px 5px; border: 1px solid #8b98a8; border-radius: 2px; background: white; }
            QPushButton { min-height: 25px; padding: 3px 12px; border: 1px solid #7d8b99; border-radius: 2px; background: #f4f6f8; color: #1b2836; }
            QPushButton:hover { background: #e1ebf5; border-color: #4d78a8; }
            QPushButton:pressed { background: #c9d9e9; }
            QPushButton#scanButton { background: #2b6ca3; color: white; font-weight: bold; border-color: #1e4f7d; }
            QPushButton#scanButton:hover { background: #3c80bb; }
            QTabWidget::pane { border: 1px solid #aeb9c6; background: #ffffff; }
            QTabBar::tab { background: #d7dee7; border: 1px solid #aeb9c6; padding: 6px 18px; margin-right: 2px; }
            QTabBar::tab:selected { background: white; border-bottom-color: white; color: #173b57; font-weight: bold; }
            QTableWidget { alternate-background-color: #f0f4f8; gridline-color: #c7d0da; selection-background-color: #c9dff2; selection-color: #17202a; }
            QHeaderView::section { background: #d7dee7; color: #173b57; padding: 5px; border: 1px solid #b4c0cc; font-weight: bold; }
            QPlainTextEdit { background: #202a35; color: #dce8f2; font-family: Consolas; border: 1px solid #7e8b98; }
            QProgressBar { border: 1px solid #9ba8b5; background: #f7f8fa; text-align: center; min-height: 16px; }
            QProgressBar::chunk { background: #4d86b8; }
            """
        )

        central = QWidget()
        layout = QVBoxLayout(central)

        title = QLabel("IoT Vulnerability Scanner")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #173b57; padding: 3px 0;")
        subtitle = QLabel("Local network security assessment")
        subtitle.setStyleSheet("color: #52616b; padding-bottom: 2px;")
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
        self.mode_input.setToolTip("Quick checks common ports. Full also runs deeper checks.")
        self.timeout_input.setToolTip("Seconds to wait for ARP replies.")
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
        self.status_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.status_label.setStyleSheet("color: #3d4d5d; padding: 2px 4px;")
        layout.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)
        self.tabs = QTabWidget()
        devices_page = QWidget()
        devices_layout = QVBoxLayout(devices_page)
        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(
            ["IP", "Hostname", "Type", "Vendor", "Model", "Risk"]
        )
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        devices_layout.addWidget(self.results_table)
        self.tabs.addTab(devices_page, "Devices")

        report_page = QWidget()
        report_layout = QVBoxLayout(report_page)
        self.report_view = QTextBrowser()
        self.report_view.setOpenExternalLinks(False)
        self.report_view.setPlaceholderText("The report will appear here after a scan.")
        report_layout.addWidget(self.report_view)
        self.tabs.addTab(report_page, "Report")
        log_page = QWidget()
        log_layout = QVBoxLayout(log_page)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        self.tabs.addTab(log_page, "Log")
        layout.addWidget(self.tabs, 1)
        self.statusBar().showMessage("Ready")
        self.setCentralWidget(central)

    def start_scan(self) -> None:
        if self.process.state() != QProcess.NotRunning:
            return
        self.log_output.clear()
        self.results_table.setRowCount(0)
        self.report_view.clear()
        self.tabs.setCurrentIndex(0)
        self.cancel_requested = False
        self.open_button.setEnabled(False)
        self.open_csv_button.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status_label.setText("Scanning...")
        self.statusBar().showMessage("Scanning network...")
        self.progress_bar.setRange(0, 0)

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
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0 if exit_code else 1)
        if self.cancel_requested:
            self.status_label.setText("Scan cancelled.")
            self.statusBar().showMessage("Scan cancelled")
            return
        if exit_code == 0:
            self.load_results()
            self.load_report()
            self.status_label.setText("Scan finished. Reports are ready.")
            self.statusBar().showMessage("Scan complete")
            self.open_button.setEnabled(True)
            self.open_csv_button.setEnabled(True)
        else:
            self.status_label.setText("Scan failed. Check the log.")
            self.statusBar().showMessage("Scan failed")
            QMessageBox.warning(self, "Scan failed", "The scanner returned an error.")

    def cancel_scan(self) -> None:
        if self.process.state() != QProcess.NotRunning:
            self.cancel_requested = True
            self.process.kill()
            self.status_label.setText("Scan cancelled.")
            self.statusBar().showMessage("Cancelling scan...")

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

    def load_report(self) -> None:
        try:
            markdown = self.markdown_report.read_text(encoding="utf-8")
        except OSError as exc:
            self.report_view.setPlainText(f"Could not load report: {exc}")
            return
        self.report_view.setMarkdown(markdown)
        self.tabs.setCurrentIndex(1)

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
    if "WindowsVista" in QStyleFactory.keys():
        app.setStyle("WindowsVista")
    elif "Fusion" in QStyleFactory.keys():
        app.setStyle("Fusion")
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