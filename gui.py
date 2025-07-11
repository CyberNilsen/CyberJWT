from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTabWidget,
    QLabel, QTextEdit, QPushButton, QLineEdit, QFileDialog, QMessageBox
)
import sys

class CyberJWTGui(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberJWT GUI")
        self.setMinimumSize(600, 500)

        layout = QVBoxLayout()
        tabs = QTabWidget()

        tabs.addTab(self.parse_tab(), "Parse")
        tabs.addTab(self.encode_tab(), "Encode")
        tabs.addTab(self.decode_tab(), "Decode")
        tabs.addTab(self.brute_tab(), "Brute-force")

        layout.addWidget(tabs)
        self.setLayout(layout)

    def parse_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.jwt_input = QLineEdit()
        self.jwt_input.setPlaceholderText("Paste JWT here...")
        parse_btn = QPushButton("Parse JWT")
        self.parse_output = QTextEdit()
        self.parse_output.setReadOnly(True)

        parse_btn.clicked.connect(self.parse_jwt_placeholder)

        layout.addWidget(QLabel("JWT Token:"))
        layout.addWidget(self.jwt_input)
        layout.addWidget(parse_btn)
        layout.addWidget(self.parse_output)

        tab.setLayout(layout)
        return tab

    def parse_jwt_placeholder(self):
        token = self.jwt_input.text()
        if token:
            self.parse_output.setPlainText("🛠️ Parsing JWT...\n\n(Header + Payload will show here)")
        else:
            QMessageBox.warning(self, "Error", "Please enter a JWT first.")

    def encode_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("🚧 Encode functionality coming soon..."))
        tab.setLayout(layout)
        return tab

    def decode_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("🚧 Decode functionality coming soon..."))
        tab.setLayout(layout)
        return tab

    def brute_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("🚧 Brute-force functionality coming soon..."))
        tab.setLayout(layout)
        return tab


def run_gui():
    app = QApplication(sys.argv)
    window = CyberJWTGui()
    window.show()
    sys.exit(app.exec_())
