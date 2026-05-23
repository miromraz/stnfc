#!/usr/bin/env python3
# stnfc GUI -- a PySide6 frontend that drives the stnfc CLI.
#
# Targets Plasma Mobile on the Pixel 4a (sunfish) running postmarketOS,
# but is plain Qt Widgets so it works on any Qt6 desktop too. Each button
# spawns the stnfc binary as a subprocess and streams its output.
#
# Permissions: stnfc needs root (it opens /dev/i2c-2 and /dev/gpiochip2).
# The GUI invokes it via `sudo -n` (non-interactive) by default. Either:
#   - configure passwordless sudo for stnfc:
#       echo '%wheel ALL=(root) NOPASSWD: /usr/local/bin/stnfc' \
#         | sudo tee /etc/sudoers.d/stnfc
#   - or install stnfc setuid root (less safe; OK on a test phone):
#       sudo chown root:root /usr/local/bin/stnfc && sudo chmod u+s /usr/local/bin/stnfc
#       export STNFC_SUDO=         # then unset the sudo wrapper
#
# Environment knobs:
#   STNFC       path to the stnfc binary    (default: stnfc on $PATH)
#   STNFC_SUDO  command to escalate with    (default: sudo; empty = none)

import os
import subprocess
import sys

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QApplication, QInputDialog, QLabel, QMainWindow, QPlainTextEdit,
    QPushButton, QVBoxLayout, QWidget,
)

STNFC = os.environ.get("STNFC", "stnfc")
SUDO = os.environ.get("STNFC_SUDO", "sudo")


class StnfcWorker(QThread):
    """Runs stnfc in a background thread, streaming stdout/stderr."""

    line = Signal(str)
    finished_with = Signal(int)

    def __init__(self, args, parent=None):
        super().__init__(parent)
        self.args = list(args)

    def run(self):
        cmd = ([SUDO, "-n", STNFC] if SUDO else [STNFC]) + self.args
        self.line.emit(f"\n$ {' '.join(cmd)}\n")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                self.line.emit(line)
            proc.wait()
            self.finished_with.emit(proc.returncode)
        except FileNotFoundError:
            self.line.emit(f"[error: {STNFC} not found in $PATH]\n")
            self.finished_with.emit(-1)
        except Exception as exc:
            self.line.emit(f"[error: {exc}]\n")
            self.finished_with.emit(-1)


class StnfcGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("stnfc")
        self.resize(420, 720)
        self.worker = None

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setSpacing(6)

        header = QLabel("<b>stnfc</b> — NFC toolkit for sunfish")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        buttons = [
            ("Read tag (poll)",        lambda: self.run(["poll"])),
            ("Read NDEF",              lambda: self.run(["ndef-read"])),
            ("Dump MIFARE 1K",         lambda: self.run(["dump"])),
            ("Clone tag → /tmp/clone.conf",
                                       lambda: self.run(["clone", "/tmp/clone.conf"])),
            ("Emulate /tmp/clone.conf (60 s)",
                                       lambda: self.run(["--timeout", "60000",
                                                         "emulate-apdu",
                                                         "/tmp/clone.conf"])),
            ("Emulate URL / text …",   self.prompt_url),
            ("MIFARE write block …",   self.prompt_write),
            ("MIFARE copy from dump …",self.prompt_mfc_copy),
            ("Stop running command",   self.stop),
        ]
        for label, slot in buttons:
            btn = QPushButton(label)
            btn.clicked.connect(slot)
            layout.addWidget(btn)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("font-family: monospace; font-size: 10pt;")
        layout.addWidget(self.output, 1)

        self.setCentralWidget(central)

    # ---- helpers ------------------------------------------------------

    def append(self, text):
        self.output.moveCursor(QTextCursor.End)
        self.output.insertPlainText(text)
        self.output.moveCursor(QTextCursor.End)

    def run(self, args):
        if self.worker and self.worker.isRunning():
            self.append("[busy — another stnfc invocation is still running]\n")
            return
        self.worker = StnfcWorker(args, self)
        self.worker.line.connect(self.append)
        self.worker.finished_with.connect(
            lambda rc: self.append(f"[stnfc exit {rc}]\n"))
        self.worker.start()

    def stop(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.append("[terminate signal sent]\n")
        else:
            self.append("[nothing running]\n")

    # ---- input prompts -----------------------------------------------

    def prompt_url(self):
        url, ok = QInputDialog.getText(
            self, "Emulate URL or text",
            "URL (https://…), tel:, mailto:, or plain text:",
        )
        if ok and url:
            self.run(["--timeout", "60000", "emulate-ndef", url])

    def prompt_write(self):
        blk, ok = QInputDialog.getInt(
            self, "MIFARE Classic — write block",
            "Block number (1–62; block 0 and sector trailers are guarded):",
            value=1, minValue=1, maxValue=62,
        )
        if not ok:
            return
        text, ok = QInputDialog.getText(
            self, "MIFARE Classic — write block",
            "Up to 16 characters (UTF-8) to write:",
        )
        if ok and text:
            data = text.encode("utf-8")[:16].ljust(16, b"\x00")
            hex_args = [f"{b:02X}" for b in data]
            self.run(["write", str(blk)] + hex_args)

    def prompt_mfc_copy(self):
        path, ok = QInputDialog.getText(
            self, "MIFARE Classic — copy from dump",
            "Path to dump file (created by Clone tag):",
            text="/tmp/clone.conf",
        )
        if ok and path:
            self.run(["mfc-copy", path])


def main():
    app = QApplication(sys.argv)
    win = StnfcGUI()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
