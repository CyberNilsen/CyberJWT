from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTabWidget, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QLineEdit, QFileDialog, QMessageBox,
    QComboBox, QGroupBox, QGridLayout, QCheckBox
)
import sys
import json
from encode import encode_jwt, create_default_payload, SUPPORTED_ALGORITHMS
from decode import decode_jwt, format_decode_output


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

        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("Algorithm:"))
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(SUPPORTED_ALGORITHMS)
        algo_layout.addWidget(self.algorithm_combo)
        algo_layout.addStretch()
        layout.addLayout(algo_layout)

        secret_layout = QHBoxLayout()
        secret_layout.addWidget(QLabel("Secret Key:"))
        self.secret_input = QLineEdit()
        self.secret_input.setPlaceholderText("Enter secret key (leave empty for 'none' algorithm)")
        secret_layout.addWidget(self.secret_input)
        layout.addLayout(secret_layout)

        payload_group = QGroupBox("JWT Payload")
        payload_layout = QVBoxLayout()
        
        quick_btn_layout = QHBoxLayout()
        default_payload_btn = QPushButton("Load Default Payload")
        clear_payload_btn = QPushButton("Clear Payload")
        default_payload_btn.clicked.connect(self.load_default_payload)
        clear_payload_btn.clicked.connect(self.clear_payload)
        quick_btn_layout.addWidget(default_payload_btn)
        quick_btn_layout.addWidget(clear_payload_btn)
        quick_btn_layout.addStretch()
        payload_layout.addLayout(quick_btn_layout)

        self.payload_input = QTextEdit()
        self.payload_input.setPlaceholderText('Enter JSON payload, e.g.:\n{\n  "sub": "user123",\n  "name": "John Doe",\n  "admin": true\n}')
        self.payload_input.setMaximumHeight(150)
        payload_layout.addWidget(self.payload_input)
        
        payload_group.setLayout(payload_layout)
        layout.addWidget(payload_group)

        encode_btn = QPushButton("🔐 Encode JWT")
        encode_btn.clicked.connect(self.encode_jwt_token)
        layout.addWidget(encode_btn)

        layout.addWidget(QLabel("Generated JWT:"))
        self.jwt_output = QTextEdit()
        self.jwt_output.setReadOnly(True)
        self.jwt_output.setMaximumHeight(100)
        layout.addWidget(self.jwt_output)

        copy_btn = QPushButton("📋 Copy JWT")
        copy_btn.clicked.connect(self.copy_jwt)
        layout.addWidget(copy_btn)

        tab.setLayout(layout)
        return tab

    def load_default_payload(self):
        """Load a default JWT payload"""
        default_payload = create_default_payload()
        self.payload_input.setPlainText(json.dumps(default_payload, indent=2))

    def clear_payload(self):
        """Clear the payload input"""
        self.payload_input.clear()

    def encode_jwt_token(self):
        """Encode JWT token using the current inputs"""
        try:
            payload_text = self.payload_input.toPlainText().strip()
            if not payload_text:
                QMessageBox.warning(self, "Error", "Please enter a payload.")
                return

            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError as e:
                QMessageBox.warning(self, "JSON Error", f"Invalid JSON payload:\n{str(e)}")
                return

            algorithm = self.algorithm_combo.currentText()
            secret = self.secret_input.text()

            if algorithm != 'none' and not secret:
                reply = QMessageBox.question(
                    self, "No Secret", 
                    "No secret key provided. This will create an unsigned token. Continue?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            jwt_token = encode_jwt(payload, secret, algorithm)
            
            self.jwt_output.setPlainText(jwt_token)
            
            QMessageBox.information(self, "Success", "JWT token generated successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to encode JWT:\n{str(e)}")

    def copy_jwt(self):
        """Copy JWT to clipboard"""
        jwt_text = self.jwt_output.toPlainText()
        if jwt_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(jwt_text)
            QMessageBox.information(self, "Copied", "JWT copied to clipboard!")
        else:
            QMessageBox.warning(self, "No JWT", "No JWT token to copy.")

    def decode_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("JWT Token:"))
        self.decode_jwt_input = QLineEdit()
        self.decode_jwt_input.setPlaceholderText("Paste JWT token here...")
        layout.addWidget(self.decode_jwt_input)

        secret_layout = QHBoxLayout()
        secret_layout.addWidget(QLabel("Secret Key (optional):"))
        self.decode_secret_input = QLineEdit()
        self.decode_secret_input.setPlaceholderText("Enter secret key for signature verification")
        self.decode_secret_input.setEchoMode(QLineEdit.Password)  
        secret_layout.addWidget(self.decode_secret_input)
        
        self.show_secret_btn = QPushButton("👁")
        self.show_secret_btn.setMaximumWidth(30)
        self.show_secret_btn.clicked.connect(self.toggle_secret_visibility)
        secret_layout.addWidget(self.show_secret_btn)
        
        layout.addLayout(secret_layout)

        options_group = QGroupBox("Verification Options")
        options_layout = QGridLayout()
        
        self.verify_signature_cb = QCheckBox("Verify Signature")
        self.verify_signature_cb.setChecked(True)
        self.verify_expiration_cb = QCheckBox("Check Expiration")
        self.verify_expiration_cb.setChecked(True)
        
        options_layout.addWidget(self.verify_signature_cb, 0, 0)
        options_layout.addWidget(self.verify_expiration_cb, 0, 1)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        decode_btn = QPushButton("🔓 Decode JWT")
        decode_btn.clicked.connect(self.decode_jwt_token)
        layout.addWidget(decode_btn)

        layout.addWidget(QLabel("Decoded JWT:"))
        self.decode_output = QTextEdit()
        self.decode_output.setReadOnly(True)
        layout.addWidget(self.decode_output)

        button_layout = QHBoxLayout()
        
        copy_decoded_btn = QPushButton("📋 Copy Output")
        copy_decoded_btn.clicked.connect(self.copy_decoded_output)
        button_layout.addWidget(copy_decoded_btn)
        
        clear_decode_btn = QPushButton("🗑 Clear")
        clear_decode_btn.clicked.connect(self.clear_decode_output)
        button_layout.addWidget(clear_decode_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)

        tab.setLayout(layout)
        return tab

    def toggle_secret_visibility(self):
        """Toggle secret key visibility"""
        if self.decode_secret_input.echoMode() == QLineEdit.Password:
            self.decode_secret_input.setEchoMode(QLineEdit.Normal)
            self.show_secret_btn.setText("🙈")
        else:
            self.decode_secret_input.setEchoMode(QLineEdit.Password)
            self.show_secret_btn.setText("👁")

    def decode_jwt_token(self):
        """Decode JWT token"""
        token = self.decode_jwt_input.text().strip()
        
        if not token:
            QMessageBox.warning(self, "Error", "Please enter a JWT token.")
            return
        
        try:
            secret = self.decode_secret_input.text()
            verify_signature = self.verify_signature_cb.isChecked()
            verify_expiration = self.verify_expiration_cb.isChecked()
            
            result = decode_jwt(
                token=token,
                secret=secret,
                verify_signature=verify_signature,
                verify_expiration=verify_expiration
            )
            
            formatted_output = format_decode_output(result)
            self.decode_output.setPlainText(formatted_output)
            
            if result['valid_structure']:
                if result['errors']:
                    QMessageBox.warning(self, "Decoded with Issues", 
                                      f"JWT decoded but has issues:\n" + "\n".join(result['errors']))
                else:
                    QMessageBox.information(self, "Success", "JWT decoded successfully!")
            else:
                QMessageBox.critical(self, "Decode Failed", 
                                   f"Failed to decode JWT:\n" + "\n".join(result['errors']))
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error during decoding:\n{str(e)}")

    def copy_decoded_output(self):
        """Copy decoded output to clipboard"""
        output_text = self.decode_output.toPlainText()
        if output_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(output_text)
            QMessageBox.information(self, "Copied", "Decoded output copied to clipboard!")
        else:
            QMessageBox.warning(self, "No Output", "No decoded output to copy.")

    def clear_decode_output(self):
        """Clear all decode inputs and outputs"""
        self.decode_jwt_input.clear()
        self.decode_secret_input.clear()
        self.decode_output.clear()

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

if __name__ == "__main__":
    run_gui()