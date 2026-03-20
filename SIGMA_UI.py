import sys
import os
import time

_PROJECT_DIR = r"C:\Users\HP\Documents\work_space\Embedded_Secure_Encryp_Comp"
sys.path.insert(0, _PROJECT_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import serial
import serial.tools.list_ports

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QTextEdit, QLineEdit, QFileDialog,
    QFrame, QSizePolicy, QSpacerItem
)
from PyQt5.QtCore  import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui   import (
    QFont, QColor, QPainter, QPainterPath, QPixmap, QPen, QTextCursor
)

# ─── Crypto ───────────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives import hashes, serialization
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
LOGO_PATH     = r"C:\Users\HP\Documents\work_space\Embedded_Secure_Encryp_Comp\images\logo.jpg"
PRIV_KEY_FILE = "private_key.pem"
PUB_KEY_FILE  = "public_key.pem"
CHUNK_SIZE    = 128
ACK           = b'\x79'
ERR           = b'\x1F'
END           = 0xFFFF

AES_KEY = bytes([
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
])

# ─── Classic grey palette ─────────────────────────────────────────────────────
BG        = "#F0F0F0"
SURFACE   = "#FFFFFF"
BORDER    = "#ADADAD"
BTN_BG    = "#E1E1E1"
BTN_HOVER = "#C8E0F4"
BTN_PRESS = "#B0CCE4"
TEXT      = "#000000"
MUTED     = "#555555"
ACCENT    = "#2B83CB"
GREEN     = "#007700"
RED       = "#CC0000"
ORANGE    = "#AA6600"

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

class CircularLogo(QWidget):
    def __init__(self, path, size=50, parent=None):
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        self._pix = QPixmap(path) if os.path.exists(path) else QPixmap()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = self._size
        clip = QPainterPath()
        clip.addEllipse(2, 2, s-4, s-4)
        p.setClipPath(clip)
        if not self._pix.isNull():
            sc = self._pix.scaled(s-4, s-4, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
            ox = (sc.width()  - (s-4)) // 2
            oy = (sc.height() - (s-4)) // 2
            p.drawPixmap(2, 2, sc, ox, oy, s-4, s-4)
        else:
            p.fillRect(2, 2, s-4, s-4, QColor("#CCCCCC"))
        p.setClipping(False)
        p.setPen(QPen(QColor(BORDER), 1))
        p.drawEllipse(2, 2, s-4, s-4)
        p.end()


SS_BTN = f"""
    QPushButton {{
        background:{BTN_BG}; color:{TEXT};
        border:1px solid {BORDER}; border-radius:2px;
        padding:3px 6px;
        font-family:'Segoe UI',Arial,sans-serif; font-size:8pt;
    }}
    QPushButton:hover   {{ background:{BTN_HOVER}; border-color:{ACCENT}; }}
    QPushButton:pressed {{ background:{BTN_PRESS}; }}
    QPushButton:disabled {{ background:{BG}; color:#AAAAAA; border-color:#CCCCCC; }}
"""

SS_COMBO = f"""
    QComboBox {{
        background:{SURFACE}; color:{TEXT};
        border:1px solid {BORDER}; border-radius:2px;
        padding:1px 4px;
        font-family:'Segoe UI',Arial,sans-serif; font-size:8pt;
    }}
    QComboBox:hover {{ border-color:{ACCENT}; }}
    QComboBox::drop-down {{ border-left:1px solid {BORDER}; width:14px; }}
    QComboBox QAbstractItemView {{
        background:{SURFACE}; color:{TEXT};
        selection-background-color:{ACCENT}; selection-color:white;
        border:1px solid {BORDER};
    }}
"""

SS_EDIT = f"""
    QLineEdit {{
        background:{SURFACE}; color:{TEXT};
        border:1px solid {BORDER}; border-radius:2px;
        padding:1px 4px;
        font-family:'Segoe UI',Arial,sans-serif; font-size:8pt;
    }}
    QLineEdit:focus {{ border-color:{ACCENT}; }}
"""

def _btn(text):
    b = QPushButton(text)
    b.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    b.setFixedHeight(30)
    b.setStyleSheet(SS_BTN)
    b.setCursor(Qt.PointingHandCursor)
    return b

def _lbl(text, bold=False):
    l = QLabel(text)
    w = "bold" if bold else "normal"
    l.setStyleSheet(f"font-family:'Segoe UI',Arial,sans-serif; font-size:8pt; font-weight:{w}; color:{TEXT};")
    return l

def _hrule():
    f = QFrame(); f.setFrameShape(QFrame.HLine); f.setFrameShadow(QFrame.Sunken)
    f.setFixedHeight(2); return f


# ═══════════════════════════════════════════════════════════════════════════════
#  FLASH WORKER
# ═══════════════════════════════════════════════════════════════════════════════

class FlashWorker(QThread):
    log  = pyqtSignal(str, str)
    done = pyqtSignal(bool)

    def __init__(self, ser, bin_path, parent=None):
        super().__init__(parent)
        self.ser = ser; self.bin_path = bin_path; self._abort = False

    def abort(self): self._abort = True

    def _wait(self, expected, timeout=5):
        start = time.time()
        while True:
            if self._abort: return False
            if self.ser.in_waiting:
                b = self.ser.read(1)
                self.log.emit(f"RX <- {b.hex().upper()}", "muted")
                if b == expected: return True
                if b == ERR: self.log.emit("STM32 -> ERROR", "err"); return False
            if time.time() - start > timeout:
                self.log.emit("TIMEOUT", "err"); return False
            time.sleep(0.01)

    def _tx(self, data):
        self.ser.write(data); self.ser.flush()
        self.log.emit(f"TX -> {len(data)} B", "muted")

    def run(self):
        try: self._flash()
        except Exception as e: self.log.emit(f"Exception: {e}", "err"); self.done.emit(False)

    def _flash(self):
        try:
            from SIGMA_compress import lzss_compress
            from SIGMA_encrypt  import aes_gcm_encrypt
        except ImportError as e:
            self.log.emit(f"Import error: {e}", "err")
            self.log.emit(f"Dossier cherche: {os.path.dirname(os.path.abspath(__file__))}", "warn")
            self.done.emit(False); return

        if not CRYPTO_OK:
            self.log.emit("cryptography not installed", "err"); self.done.emit(False); return
        if not os.path.exists(PRIV_KEY_FILE):
            self.log.emit("private_key.pem not found", "err"); self.done.emit(False); return

        with open(PRIV_KEY_FILE, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        self.log.emit("Private key loaded", "info")

        with open(self.bin_path, "rb") as f: firmware = f.read()
        self.log.emit(f"Firmware: {len(firmware)} bytes", "info")

        compressed    = lzss_compress(firmware)
        original_size = len(firmware)
        self.log.emit(f"LZSS: {len(compressed)} B ({len(compressed)/original_size*100:.1f}%)", "ok")

        iv, encrypted, tag = aes_gcm_encrypt(compressed)
        self.log.emit(f"AES-GCM: {len(encrypted)} B", "ok")

        der = priv.sign(firmware, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw_sig = r.to_bytes(32,'big') + s.to_bytes(32,'big')
        self.log.emit("ECDSA P-256 signed", "ok")

        self.log.emit("Syncing bootloader...", "info")
        synced = False; start = time.time()
        while time.time() - start < 10 and not self._abort:
            self.ser.reset_input_buffer()
            self.ser.write(b'F'); self.ser.flush(); time.sleep(0.2)
            if self.ser.in_waiting:
                b = self.ser.read(1)
                if b == ACK: self.log.emit("Bootloader ACK", "ok"); synced = True; break
        if not synced: self.log.emit("No ACK — press RESET?", "err"); self.done.emit(False); return

        self.log.emit("Waiting erase...", "info")
        if not self._wait(ACK, 10): self.done.emit(False); return
        self.log.emit("Erase OK", "ok")

        self._tx(iv);
        if not self._wait(ACK): self.done.emit(False); return
        self._tx(tag)
        if not self._wait(ACK): self.done.emit(False); return
        self._tx(original_size.to_bytes(4,'little'))
        if not self._wait(ACK): self.done.emit(False); return

        offset = 0; total = len(encrypted); cid = 0
        while offset < total and not self._abort:
            chunk = encrypted[offset:offset+CHUNK_SIZE]
            self._tx(len(chunk).to_bytes(2,'little'))
            if not self._wait(ACK): self.done.emit(False); return
            self._tx(chunk)
            if not self._wait(ACK): self.done.emit(False); return
            offset += len(chunk); cid += 1
            self.log.emit(f"Chunk {cid:03d}  {offset}/{total} ({offset/total*100:.0f}%)", "info")

        self._tx(END.to_bytes(2,'little'))
        if not self._wait(ACK): self.done.emit(False); return
        self._tx(raw_sig)
        self.log.emit("Signature sent — verifying...", "info")
        if not self._wait(ACK, 10):
            self.log.emit("Signature INVALID — flash erased!", "err"); self.done.emit(False); return
        self.log.emit("Signature VALID — jumping to app!", "ok")
        self.done.emit(True)  
# ═══════════════════════════════════════════════════════════════════════════════
#  Read from STM
# ═══════════════════════════════════════════════════════════════════════════════      
class SerialReader(QThread):
    received = pyqtSignal(str)
    def __init__(self, ser):
        super().__init__()
        self.ser = ser
        self._running = True
    def stop(self):
        self._running = False
    def run(self):
        while self._running:
            try:
                if self.ser and self.ser.is_open and self.ser.in_waiting:
                    data = self.ser.read(self.ser.in_waiting)
                    text = data.decode('utf-8', errors='ignore')
                    if text.strip():
                        self.received.emit(text)
            except:
                break
            time.sleep(0.05)
# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════════

class SigmaWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIGMA Embedded — Secure Flash Interface")
        self.setMinimumSize(580, 400)
        self.resize(780, 530)
        self.ser    = None
        self.worker = None

        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background:{BG}; color:{TEXT};
                font-family:'Segoe UI',Arial,sans-serif; font-size:8pt;
            }}
        """)
        self._build_ui()
        self._refresh_ports()
        self._port_timer = QTimer()
        self._port_timer.timeout.connect(self._refresh_ports)
        self._port_timer.start(3000)

    # ─── ROOT ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        v.addWidget(self._build_topbar())    # single top bar: logo + path+Add + COM + Port + Connect
        v.addWidget(_hrule())
        v.addWidget(self._build_body(), 1)   # sidebar | console

    # ─── TOP BAR (one single row) ─────────────────────────────────────────────
    def _build_topbar(self):
        bar = QFrame()
        bar.setFixedHeight(56)
        bar.setStyleSheet(f"background:{BG}; border:none;")
        h = QHBoxLayout(bar)
        h.setContentsMargins(6, 4, 6, 4)
        h.setSpacing(6)

        # Logo + title
        logo = CircularLogo(LOGO_PATH, size=50)
        h.addWidget(logo)

        title = QLabel("SIGMA Embedded")
        title.setStyleSheet(f"color:{ACCENT}; font-size:14pt; font-weight:bold; font-family:'Segoe UI',Arial,sans-serif;")
        h.addWidget(title)

        # stretchy spacer to push controls right
        h.addStretch(1)
        # separator
        sep = QFrame(); sep.setFrameShape(QFrame.VLine); sep.setFrameShadow(QFrame.Sunken); sep.setFixedWidth(8)
        h.addWidget(sep)

        # ── COM ──────────────────────────────────────────────────────
        h.addWidget(_lbl("Port"))
        self.port_combo = QComboBox()
        self.port_combo.setFixedSize(72, 30)
        self.port_combo.setStyleSheet(SS_COMBO)
        h.addWidget(self.port_combo)

        # ── Port (baud) ───────────────────────────────────────────────
        h.addWidget(_lbl("Baud Rate"))
        self.baud_combo = QComboBox()
        self.baud_combo.setFixedSize(80, 30)
        self.baud_combo.setStyleSheet(SS_COMBO)
        for b in ["9600","19200","38400","57600","115200","230400","921600"]:
            self.baud_combo.addItem(b)
        self.baud_combo.setCurrentText("115200")
        h.addWidget(self.baud_combo)

        # ── status dot ───────────────────────────────────────────────
        self.dot = QLabel("●")
        self.dot.setFixedWidth(12)
        self.dot.setStyleSheet(f"color:{BORDER}; font-size:9pt;")
        h.addWidget(self.dot)

        # ── Connect ───────────────────────────────────────────────────
        self.btn_connect = QPushButton("Connect")
        self.btn_connect.setFixedSize(100, 30)
        self.btn_connect.setStyleSheet(f"""
            QPushButton {{
                background:{BTN_BG}; color:{TEXT};
                border:1px solid {BORDER}; border-radius:2px;
                font-family:'Segoe UI',Arial,sans-serif; font-size:8pt; font-weight:bold;
            }}
            QPushButton:hover   {{ background:{BTN_HOVER}; border-color:{ACCENT}; color:{ACCENT}; }}
            QPushButton:pressed {{ background:{BTN_PRESS}; }}
        """)
        self.btn_connect.setCursor(Qt.PointingHandCursor)
        self.btn_connect.clicked.connect(self._toggle_connect)
        h.addWidget(self.btn_connect)
        return bar

    # ─── BODY ─────────────────────────────────────────────────────────────────
    def _build_body(self):
        body = QWidget()
        body.setStyleSheet(f"background:{BG};")
        h = QHBoxLayout(body)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self._build_sidebar(), 0)
        sep = QFrame(); sep.setFrameShape(QFrame.VLine); sep.setFrameShadow(QFrame.Sunken)
        h.addWidget(sep)
        h.addWidget(self._build_console(), 1)
        return body

    # ─── SIDEBAR ──────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = QFrame()
        sb.setObjectName("sb")
        sb.setStyleSheet(f"QFrame#sb {{ background:{BG}; border:none; }}")
        sb.setFixedWidth(130)

        v = QVBoxLayout(sb)
        v.setContentsMargins(6, 6, 6, 6)
        v.setSpacing(3)

        # ── BOOTLOADER ────────────────────────────────────────────────
        lbl_b = _lbl("Bootloader", bold=True)
        v.addWidget(lbl_b)
        v.addWidget(_hrule())

        self.btn_flash = _btn("Flash FW")
        self.btn_flash.setEnabled(False)
        self.btn_flash.clicked.connect(self._start_flash)
        v.addWidget(self.btn_flash)

        self.btn_jump = _btn("Jump To App")
        self.btn_jump.setEnabled(False)
        self.btn_jump.clicked.connect(self._jump)
        v.addWidget(self.btn_jump)

        self.btn_aes = _btn("AES key")
        self.btn_aes.clicked.connect(self._show_aes_key)
        v.addWidget(self.btn_aes)

        self.btn_ecdsa = _btn("ECDSA key")
        self.btn_ecdsa.clicked.connect(self._show_pub_key)
        v.addWidget(self.btn_ecdsa)

        v.addSpacing(8)

        # ── APPLICATION ───────────────────────────────────────────────
        lbl_a = _lbl("Application", bold=True)
        v.addWidget(lbl_a)
        v.addWidget(_hrule())

        self.btn_led = _btn("Toggle LED")
        self.btn_led.setEnabled(False)
        self.btn_led.clicked.connect(lambda: self._send_cmd("T"))
        v.addWidget(self.btn_led)

        self.btn_rst = _btn("Reset")
        self.btn_rst.setEnabled(False)
        self.btn_rst.clicked.connect(lambda: self._send_cmd("R"))
        v.addWidget(self.btn_rst)

        v.addStretch()
        return sb

    # ─── CONSOLE ──────────────────────────────────────────────────────────────
    def _build_console(self):
        frame = QFrame()
        frame.setStyleSheet(f"background:{BG}; border:none;")
        v = QVBoxLayout(frame)
        v.setContentsMargins(4, 4, 4, 4)
        v.setSpacing(1)
        # ── .bin path + Add ──────────────────────────────────────────
        bin_row = QHBoxLayout()
        bin_row.setSpacing(4)
        self.bin_edit = QLineEdit()
        self.bin_edit.setPlaceholderText("firmware .bin ...")
        self.bin_edit.setReadOnly(True)
        self.bin_edit.setFixedHeight(25)
        self.bin_edit.setStyleSheet(SS_EDIT)
        self.btn_add = QPushButton("Add")
        self.btn_add.setFixedSize(40, 25)
        self.btn_add.setStyleSheet(SS_BTN)
        self.btn_add.setCursor(Qt.PointingHandCursor)
        self.btn_add.clicked.connect(self._browse_bin)
        bin_row.addWidget(self.bin_edit, 1)   # ← 1 = stretch twila
        bin_row.addWidget(self.btn_add)
        v.addLayout(bin_row)
        v.setContentsMargins(8, 8, 8, 8) 
        v.setSpacing(8)        
# console label + copy/clear
        top = QHBoxLayout()
        top.addWidget(_lbl("Consol", bold=True))
        top.addStretch()
        for txt, fn in [("Copy", self._copy_log), ("Clear", self._clear_log)]:
            b = QPushButton(txt)
            b.setFixedSize(50, 30)
            b.setStyleSheet(SS_BTN)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(fn)
            top.addWidget(b)
        v.addLayout(top)

        # output area — smaller font, white bg, sunken border
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(f"""
            QTextEdit {{
                background:{SURFACE}; color:{TEXT};
                border:1px solid {BORDER}; border-radius:2px;
                font-family:'Consolas','Courier New',monospace;
                font-size:7pt;
                padding:3px;
                selection-background-color:{ACCENT}; selection-color:white;
            }}
            QScrollBar:vertical {{
                background:{BG}; width:12px; border:1px solid {BORDER};
            }}
            QScrollBar::handle:vertical {{
                background:#C0C0C0; border:1px solid {BORDER}; min-height:16px;
            }}
        """)
        v.addWidget(self.console, 1)

        # input row
        inp = QHBoxLayout(); inp.setSpacing(4)
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Type command + Enter  (T, R or J)")
        self.cmd_input.returnPressed.connect(self._send_manual)
        self.cmd_input.setFixedHeight(25)
        self.cmd_input.setStyleSheet(SS_EDIT)

        btn_send = QPushButton("Send")
        btn_send.setFixedSize(50, 25)
        btn_send.setStyleSheet(SS_BTN)
        btn_send.setCursor(Qt.PointingHandCursor)
        btn_send.clicked.connect(self._send_manual)
        inp.addWidget(self.cmd_input, 1)
        inp.addWidget(btn_send)
        v.addLayout(inp)
        inp.spacing()
        return frame

    # ─── RESIZE ───────────────────────────────────────────────────────────────
    def resizeEvent(self, e):
        super().resizeEvent(e)
        w  = self.width()
        pt = max(6, int(8 * min(1.0, 780 / max(w, 500))))
        # shrink console font on larger windows
        if hasattr(self, 'console'):
            self.console.setStyleSheet(f"""
                QTextEdit {{
                    background:{SURFACE}; color:{TEXT};
                    border:1px solid {BORDER}; border-radius:2px;
                    font-family:'Consolas','Courier New',monospace;
                    font-size:{pt}pt; padding:2px;
                    selection-background-color:{ACCENT}; selection-color:white;
                }}
                QScrollBar:vertical {{
                    background:{BG}; width:12px; border:1px solid {BORDER};
                }}
                QScrollBar::handle:vertical {{
                    background:#C0C0C0; border:1px solid {BORDER}; min-height:16px;
                }}
            """)

    # ═══════════════════════════════════════════════════════════════════════════
    #  LOGIC
    # ═══════════════════════════════════════════════════════════════════════════

    def _refresh_ports(self):
        cur   = self.port_combo.currentText()
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo.blockSignals(True)
        self.port_combo.clear()
        self.port_combo.addItems(ports)
        if cur in ports: self.port_combo.setCurrentText(cur)
        self.port_combo.blockSignals(False)

    def _toggle_connect(self):
        if self.ser and self.ser.is_open: self._disconnect()
        else:                             self._connect()

    def _connect(self):
        port = self.port_combo.currentText().strip()
        if not port: self._log("No COM port selected", "err"); return
        try:
            baud = int(self.baud_combo.currentText())
        except ValueError:
            self._log("Invalid baud rate", "err"); return
        try:
            self.ser = serial.Serial(port, baud, timeout=5)
            self.dot.setStyleSheet("color:green; font-size:9pt;")
            self.btn_connect.setText("Disconnect")
            for b in (self.btn_flash, self.btn_jump, self.btn_led, self.btn_rst):
                b.setEnabled(True)
            self._log(f"Connected  {port} @ {baud} baud", "ok")
            self._reader = SerialReader(self.ser)
            self._reader.received.connect(lambda t: self._log(t.strip(), "ok"))
            self._reader.start()
        except serial.SerialException as e:
            self.dot.setStyleSheet("color:red; font-size:9pt;")
            self._log(f"Connection failed: {e}", "err")

    def _disconnect(self):
        if self.ser:
            if hasattr(self, '_reader'):
                self._reader.stop()
                self._reader.wait()
            try: self.ser.close()
            except: pass
            self.ser = None
        self.dot.setStyleSheet(f"color:{BORDER}; font-size:9pt;")
        self.btn_connect.setText("Connect")
        for b in (self.btn_flash, self.btn_jump, self.btn_led, self.btn_rst):
            b.setEnabled(False)
        self._log("Disconnected", "warn")

    def _browse_bin(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Firmware Binary", "", "Binary Files (*.bin);;All Files (*)")
        if p:
            self.bin_edit.setText(p)
            self._log(f"Firmware: {os.path.basename(p)}", "info")

    def _start_flash(self):
        p = self.bin_edit.text().strip()
        if not p or not os.path.exists(p): self._log("Select a valid .bin file first", "err"); return
        if not self.ser or not self.ser.is_open: self._log("Not connected", "err"); return
        self.btn_flash.setEnabled(False)
        self.dot.setStyleSheet("color:orange; font-size:9pt;")
        self._log("-" * 48, "muted")
        if hasattr(self, '_reader'): self._reader.stop()
        self._log("Flash sequence started...", "info")
        self.worker = FlashWorker(self.ser, p)
        self.worker.log.connect(lambda m, l: self._log(m, l))
        self.worker.done.connect(self._on_done)
        self.worker.start()

    def _on_done(self, ok):
        self.btn_flash.setEnabled(True)
        self.dot.setStyleSheet(f"color:{'green' if ok else 'red'}; font-size:9pt;")
        self._log("Flash COMPLETE" if ok else "Flash FAILED", "ok" if ok else "err")
        self._log("-" * 48, "muted")
        if ok and self.ser and self.ser.is_open:
            self._reader = SerialReader(self.ser)
            self._reader.received.connect(lambda t: self._log(t.strip(), "ok"))
            self._reader.start()

    def _jump(self):
        if not self.ser or not self.ser.is_open: self._log("Not connected", "err"); return
        self._send_cmd("J"); self._log("Jump-to-app sent", "info")

    def _send_manual(self):
        t = self.cmd_input.text().strip()
        if not t: return
        self.cmd_input.clear()
        self._log(f"> {t}", "input")
        self._send_cmd(t)

    def _send_cmd(self, cmd):
        if not self.ser or not self.ser.is_open: self._log("Not connected", "err"); return
        try: self.ser.write(cmd.encode()); self.ser.flush()
        except Exception as e: self._log(f"Send error: {e}", "err")

    def _show_pub_key(self):
        if not os.path.exists(PUB_KEY_FILE): self._log("No public key — run Gen Keys first", "err"); return
        if not CRYPTO_OK: self._log("cryptography not installed", "err"); return
        with open(PUB_KEY_FILE, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        n   = pub.public_numbers()
        raw = n.x.to_bytes(32,'big') + n.y.to_bytes(32,'big')
        ha  = [f"0x{b:02X}" for b in raw]
        self._log("-" * 48, "muted")
        self._log("ECDSA P-256 Public Key — paste into flash_if.h:", "info")
        self._log("static const uint8_t PUBLIC_KEY[64] = {", "info")
        for i in range(0, 64, 8):
            self._log("    " + ", ".join(ha[i:i+8]) + ",", "ok")
        self._log("};", "info")
        self._log("-" * 48, "muted")

    def _show_aes_key(self):
        ha = [f"0x{b:02X}" for b in AES_KEY]
        self._log("-" * 48, "muted")
        self._log("AES-256-GCM Key — paste into bootloader:", "info")
        self._log("static const uint8_t AES_KEY[32] = {", "info")
        for i in range(0, 32, 8):
            self._log("    " + ", ".join(ha[i:i+8]) + ",", "ok")
        self._log("};", "info")
        self._log("-" * 48, "muted")

    def _gen_keys(self):
        if not CRYPTO_OK: self._log("cryptography not installed", "err"); return
        self._log("Generating ECDSA P-256 keypair...", "info")
        priv = ec.generate_private_key(ec.SECP256R1())
        pub  = priv.public_key()
        with open(PRIV_KEY_FILE,"wb") as f:
            f.write(priv.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with open(PUB_KEY_FILE,"wb") as f:
            f.write(pub.public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
        self._log("Keys saved: private_key.pem + public_key.pem", "ok")
        self._log("!! REFLASH BOOTLOADER WITH NEW PUBLIC KEY !!", "warn")

    _CLR = {"info": TEXT, "ok": GREEN, "err": RED, "warn": ORANGE,
            "muted": "#888888", "input": ACCENT}

    def _log(self, msg, level="info"):
        col = self._CLR.get(level, TEXT)
        ts  = time.strftime("%H:%M:%S")
        self.console.moveCursor(QTextCursor.End)
        self.console.insertHtml(
            f'<span style="color:#888888;">[{ts}]</span>&nbsp;'
            f'<span style="color:{col};">{msg}</span><br>'
        )
        self.console.moveCursor(QTextCursor.End)

    def _copy_log(self):
        QApplication.clipboard().setText(self.console.toPlainText())

    def _clear_log(self): self.console.clear()

    def closeEvent(self, e):
        self._disconnect(); super().closeEvent(e)


# ═══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setStyle("WindowsVista")
    app.setFont(QFont("Segoe UI", 8))
    win = SigmaWindow()
    win.setGeometry(200,100,850,750)
    win.show()
    win._log("SIGMA Secure Flash Interface ready", "ok")
    win._log("ADD firmware .bin  |  set COM/Port  |  Connect  |  Flash FW", "muted")
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
