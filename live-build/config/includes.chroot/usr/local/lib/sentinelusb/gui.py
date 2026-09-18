#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QMessageBox, QPushButton, QProgressBar, QVBoxLayout, QWidget
)

from scanner import flatten_devices, list_block_devices, scan
from storage import report_root, status

RULES = Path("/usr/local/share/sentinelusb/rules/sentinel.yar")


class ScanWorker(QThread):
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, device):
        super().__init__()
        self.device = device

    def run(self):
        try:
            reports = report_root()
            report = scan(self.device, RULES, reports, self.progress.emit)
            self.finished_ok.emit(report)
        except Exception as exc:
            self.failed.emit(str(exc))


class SentinelWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.devices = []
        self.setWindowTitle("SentinelUSB")
        self.resize(900, 620)
        self.build_ui()
        self.refresh()

    def build_ui(self):
        root = QVBoxLayout(self)

        title = QLabel("SENTINELUSB")
        title.setStyleSheet("font-size: 30px; font-weight: 800;")
        root.addWidget(title)

        subtitle = QLabel(
            "Booted outside the target OS. Select an OS volume and scan it read-only."
        )
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        self.storage = QLabel()
        root.addWidget(self.storage)

        self.list = QListWidget()
        root.addWidget(self.list, 1)

        buttons = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh drives")
        self.scan_button = QPushButton("Scan selected")
        self.report_button = QPushButton("Open latest report")
        buttons.addWidget(self.refresh_button)
        buttons.addWidget(self.scan_button)
        buttons.addWidget(self.report_button)
        root.addLayout(buttons)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        root.addWidget(self.progress)

        self.status = QLabel("Ready.")
        self.status.setWordWrap(True)
        root.addWidget(self.status)

        self.refresh_button.clicked.connect(self.refresh)
        self.scan_button.clicked.connect(self.start_scan)
        self.report_button.clicked.connect(self.open_latest_report)

    def refresh(self):
        self.list.clear()
        self.devices = []
        try:
            self.devices = flatten_devices(list_block_devices())
        except Exception as exc:
            self.status.setText(f"Drive enumeration failed: {exc}")
            return

        for device in self.devices:
            path = device.get("path") or ""
            if not path or device.get("type") not in {"part", "disk"}:
                continue
            label = device.get("label") or "-"
            fstype = device.get("fstype") or "-"
            size = device.get("size") or "-"
            item = QListWidgetItem(f"{path}    {fstype:<10} {size:<10} {label}")
            item.setData(32, path)
            self.list.addItem(item)

        s = status()
        if s["device"]:
            self.storage.setText(
                f"Report storage: {s['device']} → {s['mountpoint']} "
                f"({'mounted' if s['mounted'] else 'not mounted'})"
            )
        else:
            self.storage.setText(
                "Report storage: no SENTINELDATA partition detected. "
                "Scans will fall back to temporary live-environment storage."
            )

    def set_busy(self, busy):
        self.refresh_button.setEnabled(not busy)
        self.scan_button.setEnabled(not busy)
        self.list.setEnabled(not busy)
        if busy:
            self.progress.show()
        else:
            self.progress.hide()

    def start_scan(self):
        item = self.list.currentItem()
        if item is None:
            QMessageBox.warning(self, "Select a volume", "Choose a target volume first.")
            return

        device = item.data(32)
        if not device:
            return

        answer = QMessageBox.question(
            self,
            "Start read-only scan?",
            f"SentinelUSB will mount {device} read-only and scan it.

Continue?",
        )
        if answer != QMessageBox.Yes:
            return

        self.set_busy(True)
        self.status.setText("Starting scan...")
        self.worker = ScanWorker(device)
        self.worker.progress.connect(self.status.setText)
        self.worker.finished_ok.connect(self.scan_finished)
        self.worker.failed.connect(self.scan_failed)
        self.worker.start()

    def scan_finished(self, report):
        self.set_busy(False)
        self.status.setText(
            f"Scan complete: {report['finding_count']} finding(s). "
            f"Report: {report['report_directory']}"
        )
        QMessageBox.information(
            self,
            "Scan complete",
            f"Detected OS: {report['os']}\n"
            f"Findings: {report['finding_count']}\n\n"
            f"{report['report_directory']}/report.html",
        )

    def scan_failed(self, message):
        self.set_busy(False)
        self.status.setText(f"Scan failed: {message}")
        QMessageBox.critical(self, "Scan failed", message)

    def open_latest_report(self):
        root = report_root()
        reports = sorted(root.glob("Scan_*/report.html"), reverse=True)
        if not reports:
            QMessageBox.information(self, "No report", "No scan report has been created yet.")
            return
        subprocess.Popen(["xdg-open", str(reports[0])])


def main():
    if os.geteuid() != 0:
        print("SentinelUSB GUI requires root privileges.")
        return 1
    app = QApplication(sys.argv)
    window = SentinelWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
