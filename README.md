# CyberJWT 🔐

A comprehensive JWT (JSON Web Token) security testing toolkit with a user-friendly GUI. Perfect for security researchers, penetration testers, and developers who need to analyze, manipulate, and test JWT implementations.

<img width="800" height="700" alt="CyberJWT" src="https://github.com/user-attachments/assets/7886c40c-b38d-48c6-9eb1-c7673bc41451" />


## ✨ Features

### 🔍 **Parse & Analyze**
- Parse JWT tokens and display header/payload
- Validate token structure
- Analyze standard and custom claims
- Human-readable timestamp formatting

### 🔐 **Encode & Generate**
- Create JWT tokens with custom payloads
- Support for multiple algorithms (HS256, none)
- Default payload templates
- JSON validation and formatting

### 🔓 **Decode & Verify**
- Decode JWT tokens with or without verification
- Signature validation
- Expiration and timing checks
- Detailed claims analysis
- Copy-friendly output formatting

### 🚀 **Brute-force Attack**
- **Common Secrets**: Test against 40+ common weak secrets
- **Wordlist Attack**: Use custom wordlists (rockyou.txt, etc.)
- Real-time progress tracking
- Multi-threaded for performance
- Attack statistics and timing
- Auto-integration with decode functionality

## 🛠️ Installation

### Prerequisites
- Python 3.6 or higher
- PyQt5

### Install Dependencies
```bash
pip install PyQt5
```

### Clone Repository
```bash
git clone https://github.com/CyberNilsen/CyberJWT.git
cd CyberJWT
```

## 🚀 Usage

### GUI Application
```bash
python main.py
```

## 📖 User Guide

### 1. **Parse Tab**
- Paste any JWT token to analyze its structure
- View decoded header and payload
- Identify token type and algorithm

### 2. **Encode Tab**
- Select signing algorithm (HS256, none)
- Enter secret key for signing
- Create custom JSON payload or use defaults
- Generate valid JWT tokens

### 3. **Decode Tab**
- Paste JWT token for decoding
- Optional: Enter secret key for verification
- Configure verification options:
  - ✅ Verify signature
  - ✅ Check expiration
- View detailed claims analysis

### 4. **Brute-force Tab**
- **Method 1 - Common Secrets**: Quick test against weak passwords
- **Method 2 - Wordlist Attack**: Use custom wordlist files
- Real-time progress with statistics
- Found secrets auto-populate decode tab

## 🎯 Common Use Cases

### Security Testing
```bash
# Test for weak JWT secrets
1. Paste target JWT in brute-force tab
2. Start with "Common Secrets" attack
3. If unsuccessful, try wordlist attack with rockyou.txt
4. Found secret automatically enables token verification
```

### Token Analysis
```bash
# Analyze suspicious JWT tokens
1. Use Parse tab to examine token structure
2. Check claims in Decode tab
3. Verify signatures if secret is known
4. Validate expiration and timing
```

### Token Generation
```bash
# Create test tokens for development
1. Use Encode tab with custom payloads
2. Test different algorithms and secrets
3. Generate tokens for various test scenarios
```

## 📁 Project Structure

```
CyberJWT/
├── gui.py           # Main GUI application
├── encode.py        # JWT encoding functionality  
├── decode.py        # JWT decoding and parsing
├── bruteforce.py    # Brute-force attack implementation
├── main.py          # Command-line interface
└── README.md        # This file
```

## 🔧 Technical Details

### Supported Algorithms
- **HS256**: HMAC using SHA-256
- **none**: Unsigned tokens

### Brute-force Capabilities
- **Common Secrets**: ~40 frequently used weak passwords
- **Wordlist Support**: External files (UTF-8 encoded)
- **Performance**: Multi-threaded with progress tracking
- **Smart Validation**: Pre-checks token structure

### Security Features
- Signature verification
- Expiration validation
- Timing attack protection
- Safe base64 URL decoding

## 🚨 Ethical Usage

This tool is designed for:
- ✅ Security research and education
- ✅ Authorized penetration testing
- ✅ Vulnerability assessment of your own applications
- ✅ JWT implementation testing

**Important**: Only use this tool on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Areas for improvement:

- Additional JWT algorithms (RS256, ES256)
- Enhanced brute-force methods
- Import/export functionality
- Token manipulation features
- Performance optimizations

## 📋 Requirements

- Python 3.6+
- PyQt5
- Standard library modules (json, base64, hmac, hashlib, threading)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Resources

- [JWT.io](https://jwt.io/) - JWT token debugger
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT specification
- [OWASP JWT Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

## 🐛 Known Issues & Limitations

- Currently supports only HS256 and 'none' algorithms
- Brute-force limited to symmetric key algorithms
- Large wordlists may require significant memory

## 💡 Tips

- Use common secrets attack first - it's faster
- For wordlist attacks, SecLists and rockyou.txt are recommended
- Always verify found secrets in the decode tab
- Monitor attack statistics for performance optimization

---

**⚠️ Disclaimer**: This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations.
