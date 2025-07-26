from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTabWidget, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QLineEdit, QFileDialog, QMessageBox,
    QComboBox, QGroupBox, QGridLayout, QCheckBox, QProgressBar,
    QRadioButton, QButtonGroup, QSpinBox
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
import sys
import json
import threading
from encode import encode_jwt, create_default_payload, SUPPORTED_ALGORITHMS
from decode import decode_jwt, format_decode_output
from bruteforce import JWTBruteforcer, format_time, estimate_wordlist_size


class BruteforceThread(QThread):
    progress_update = pyqtSignal(dict)
    result_ready = pyqtSignal(dict)
    
    def __init__(self, bruteforcer, token, method, wordlist_path=None):
        super().__init__()
        self.bruteforcer = bruteforcer
        self.token = token
        self.method = method
        self.wordlist_path = wordlist_path
    
    def run(self):
        if self.method == 'wordlist':
            self.bruteforcer.bruteforce_from_wordlist(
                self.token, 
                self.wordlist_path,
                progress_callback=self.progress_callback,
                result_callback=self.result_callback
            )
        elif self.method == 'common':
            self.bruteforcer.bruteforce_common_secrets(
                self.token,
                progress_callback=self.progress_callback,
                result_callback=self.result_callback
            )
    
    def progress_callback(self, data):
        self.progress_update.emit(data)
    
    def result_callback(self, data):
        self.result_ready.emit(data)


class CyberJWTGui(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberJWT GUI")
        self.setMinimumSize(800, 600)
        
        self.bruteforcer = JWTBruteforcer()
        self.brute_thread = None
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_progress_display)

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
        
        token_group = QGroupBox("JWT Token")
        token_layout = QVBoxLayout()
        
        self.brute_jwt_input = QLineEdit()
        self.brute_jwt_input.setPlaceholderText("Paste JWT token to crack...")
        token_layout.addWidget(self.brute_jwt_input)
        
        token_group.setLayout(token_layout)
        layout.addWidget(token_group)
        
        method_group = QGroupBox("Attack Method")
        method_layout = QVBoxLayout()
        
        self.method_group = QButtonGroup()
        
        self.common_radio = QRadioButton("Try Common Secrets")
        self.common_radio.setChecked(True)
        self.common_radio.toggled.connect(self.on_method_changed)
        self.method_group.addButton(self.common_radio)
        method_layout.addWidget(self.common_radio)
        
        self.wordlist_radio = QRadioButton("Wordlist Attack")
        self.wordlist_radio.toggled.connect(self.on_method_changed)
        self.method_group.addButton(self.wordlist_radio)
        method_layout.addWidget(self.wordlist_radio)
        
        wordlist_layout = QHBoxLayout()
        self.wordlist_path_input = QLineEdit()
        self.wordlist_path_input.setPlaceholderText("Select wordlist file (e.g., rockyou.txt)")
        self.wordlist_path_input.setEnabled(False)
        
        self.browse_wordlist_btn = QPushButton("Browse...")
        self.browse_wordlist_btn.clicked.connect(self.browse_wordlist)
        self.browse_wordlist_btn.setEnabled(False)
        
        wordlist_layout.addWidget(QLabel("Wordlist:"))
        wordlist_layout.addWidget(self.wordlist_path_input)
        wordlist_layout.addWidget(self.browse_wordlist_btn)
        
        method_layout.addLayout(wordlist_layout)
        method_group.setLayout(method_layout)
        layout.addWidget(method_group)
        
        controls_layout = QHBoxLayout()
        
        self.start_brute_btn = QPushButton("🚀 Start Attack")
        self.start_brute_btn.clicked.connect(self.start_bruteforce)
        controls_layout.addWidget(self.start_brute_btn)
        
        self.stop_brute_btn = QPushButton("⏹ Stop Attack")
        self.stop_brute_btn.clicked.connect(self.stop_bruteforce)
        self.stop_brute_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_brute_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_label = QLabel("Ready to start attack...")
        progress_layout.addWidget(self.progress_label)
        
        self.stats_label = QLabel("")
        progress_layout.addWidget(self.stats_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.brute_results = QTextEdit()
        self.brute_results.setReadOnly(True)
        self.brute_results.setMaximumHeight(200)
        results_layout.addWidget(self.brute_results)
        
        results_btn_layout = QHBoxLayout()
        
        self.copy_secret_btn = QPushButton("📋 Copy Secret")
        self.copy_secret_btn.clicked.connect(self.copy_found_secret)
        self.copy_secret_btn.setEnabled(False)
        results_btn_layout.addWidget(self.copy_secret_btn)
        
        self.clear_results_btn = QPushButton("🗑 Clear Results")
        self.clear_results_btn.clicked.connect(self.clear_brute_results)
        results_btn_layout.addWidget(self.clear_results_btn)
        
        results_btn_layout.addStretch()
        results_layout.addLayout(results_btn_layout)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tab.setLayout(layout)
        return tab
    
    def on_method_changed(self):
        """Handle attack method change"""
        is_wordlist = self.wordlist_radio.isChecked()
        self.wordlist_path_input.setEnabled(is_wordlist)
        self.browse_wordlist_btn.setEnabled(is_wordlist)
    
    def browse_wordlist(self):
        """Browse for wordlist file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Wordlist File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.wordlist_path_input.setText(file_path)
            
            estimated_size = estimate_wordlist_size(file_path)
            if estimated_size > 0:
                self.progress_label.setText(f"Wordlist loaded: ~{estimated_size:,} entries")
    
    def start_bruteforce(self):
        """Start bruteforce attack"""
        token = self.brute_jwt_input.text().strip()
        
        if not token:
            QMessageBox.warning(self, "Error", "Please enter a JWT token to crack.")
            return
        
        if self.wordlist_radio.isChecked():
            wordlist_path = self.wordlist_path_input.text().strip()
            if not wordlist_path:
                QMessageBox.warning(self, "Error", "Please select a wordlist file.")
                return
            
            try:
                with open(wordlist_path, 'r') as f:
                    pass 
            except FileNotFoundError:
                QMessageBox.critical(self, "Error", f"Wordlist file not found: {wordlist_path}")
                return
            except PermissionError:
                QMessageBox.critical(self, "Error", f"Permission denied accessing: {wordlist_path}")
                return
        
        self.start_brute_btn.setEnabled(False)
        self.stop_brute_btn.setEnabled(True)
        self.copy_secret_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.brute_results.clear()
        
        method = 'wordlist' if self.wordlist_radio.isChecked() else 'common'
        wordlist_path = self.wordlist_path_input.text().strip() if method == 'wordlist' else None
        
        self.brute_thread = BruteforceThread(self.bruteforcer, token, method, wordlist_path)
        self.brute_thread.progress_update.connect(self.on_brute_progress)
        self.brute_thread.result_ready.connect(self.on_brute_result)
        self.brute_thread.start()
        
        self.update_timer.start(500)  
        
        if method == 'common':
            self.progress_label.setText("Trying common secrets...")
        else:
            self.progress_label.setText("Starting wordlist attack...")
    
    def stop_bruteforce(self):
        """Stop bruteforce attack"""
        if self.bruteforcer.is_running:
            self.bruteforcer.stop_bruteforce()
            self.progress_label.setText("Stopping attack...")
        
        if self.brute_thread and self.brute_thread.isRunning():
            self.brute_thread.quit()
            self.brute_thread.wait()
        
        self.update_timer.stop()
        self.reset_brute_ui()
    
    def reset_brute_ui(self):
        """Reset bruteforce UI to initial state"""
        self.start_brute_btn.setEnabled(True)
        self.stop_brute_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        if not self.bruteforcer.found_secret:
            self.progress_label.setText("Attack stopped.")
    
    def on_brute_progress(self, progress_data):
        """Handle progress updates from bruteforce thread"""
        attempts = progress_data.get('attempts', 0)
        current_secret = progress_data.get('current_secret', '')
        elapsed_time = progress_data.get('elapsed_time', 0)
        rate = progress_data.get('rate', 0)
        
        self.progress_label.setText(f"Trying: {current_secret}")
        self.stats_label.setText(
            f"Attempts: {attempts:,} | "
            f"Rate: {rate:.1f}/sec | "
            f"Time: {format_time(elapsed_time)}"
        )
    
    def on_brute_result(self, result):
        """Handle final result from bruteforce thread"""
        self.update_timer.stop()
        
        if result['success']:
            secret = result['secret']
            attempts = result['attempts']
            elapsed_time = result['elapsed_time']
            rate = result['rate']
            
            self.brute_results.setPlainText(
                f"🎉 SECRET FOUND!\n\n"
                f"Secret: {secret}\n"
                f"Attempts: {attempts:,}\n"
                f"Time: {format_time(elapsed_time)}\n"
                f"Rate: {rate:.1f} attempts/sec\n\n"
                f"You can now use this secret to decode/verify the JWT token."
            )
            
            self.progress_label.setText(f"SUCCESS! Secret found: {secret}")
            self.copy_secret_btn.setEnabled(True)
            
            self.decode_jwt_input.setText(self.brute_jwt_input.text())
            self.decode_secret_input.setText(secret)
            
            QMessageBox.information(
                self, 
                "Secret Found!", 
                f"JWT secret cracked successfully!\n\nSecret: {secret}\n"
                f"Attempts: {attempts:,}\nTime: {format_time(elapsed_time)}"
            )
        else:
            error = result['error']
            attempts = result.get('attempts', 0)
            elapsed_time = result.get('elapsed_time', 0)
            rate = result.get('rate', 0)
            
            self.brute_results.setPlainText(
                f"❌ ATTACK FAILED\n\n"
                f"Error: {error}\n"
                f"Attempts: {attempts:,}\n"
                f"Time: {format_time(elapsed_time)}\n"
                f"Rate: {rate:.1f} attempts/sec\n\n"
                f"Try a different wordlist or attack method."
            )
            
            self.progress_label.setText(f"Failed: {error}")
            
            if attempts > 0: 
                QMessageBox.warning(
                    self,
                    "Attack Failed",
                    f"Could not crack JWT secret.\n\n{error}\n\n"
                    f"Attempts: {attempts:,}\nTime: {format_time(elapsed_time)}"
                )
        
        self.reset_brute_ui()
    
    def update_progress_display(self):
        """Update progress display with current stats"""
        if self.bruteforcer.is_running:
            stats = self.bruteforcer.get_stats()
            if stats['attempts'] > 0:
                self.stats_label.setText(
                    f"Attempts: {stats['attempts']:,} | "
                    f"Rate: {stats['rate']:.1f}/sec | "
                    f"Time: {format_time(stats['elapsed_time'])}"
                )
    
    def copy_found_secret(self):
        """Copy found secret to clipboard"""
        if self.bruteforcer.found_secret is not None:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.bruteforcer.found_secret)
            QMessageBox.information(self, "Copied", "Secret copied to clipboard!")
        else:
            QMessageBox.warning(self, "No Secret", "No secret found to copy.")
    
    def clear_brute_results(self):
        """Clear bruteforce results and inputs"""
        self.brute_jwt_input.clear()
        self.wordlist_path_input.clear()
        self.brute_results.clear()
        self.progress_label.setText("Ready to start attack...")
        self.stats_label.setText("")
        self.copy_secret_btn.setEnabled(False)


def run_gui():
    app = QApplication(sys.argv)
    window = CyberJWTGui()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    run_gui()