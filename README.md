
# Obscurio - Secure Password Manager

A local, encrypted password manager built with Python using modern cryptographic standards. Designed for security-conscious users who want complete control over their credential storage.

## Project Overview

Obscurio provides secure storage for passwords and credentials using industry-standard encryption. All data is encrypted locally on your machine and never transmitted over networks.

### Key Security Features
- AES-256-GCM authenticated encryption for data confidentiality and integrity
- Scrypt key derivation function with configurable memory-hard parameters
- Local-only storage - no cloud dependencies or data transmission
- Automatic vault locking after user-configurable inactivity period
- Secure clipboard management with automatic clearing

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/deepserish-bk/Obscurio.git
   cd Obscurio
    ```
Install dependencies:

```bash
pip install -r requirements.txt
Run the application:
```
```bash
python src/obscurio.py
```
Usage

First Run

Launch Obscurio: python src/obscurio.py
Create a new vault or open existing
Set a strong master password (minimum 12 characters recommended)
Begin adding credentials
Basic Commands

Add credential: Store new username/password combinations
Retrieve credential: Search and copy credentials to clipboard
Lock vault: Manually lock the vault (also auto-locks after inactivity)
Export backup: Create encrypted backup of your vault
Technical Architecture

Cryptographic Implementation

text
User Password → Scrypt KDF → 32-byte Key → AES-GCM Encryption → Secure Vault
Key Derivation: Scrypt with N=16384, r=8, p=1 parameters
Encryption: AES-256 in GCM mode for authenticated encryption
Data Storage: JSON format with base64-encoded encrypted payloads
Authentication: GCM tags verify data integrity on decryption
File Structure
```bash
text
Obscurio/
├── src/                    # Source code
│   ├── obscurio.py        # Main application logic
│   └── __init__.py        # Package initialization
├── tests/                  # Unit tests
│   ├── test_obscurio.py   # Test cases
│   └── __init__.py
├── docs/                   # Documentation
├── requirements.txt        # Python dependencies
├── setup.py               # Package configuration
├── LICENSE                # MIT License
└── README.md              # This file

```
Development
Setting Up Development Environment

bash
# Clone and setup
git clone https://github.com/deepserish-bk/Obscurio.git
cd Obscurio
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install pytest black mypy  # Development tools
Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with verbose output
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_obscurio.py
```
ode Quality Tools
Black: Code formatting - black src/ tests/
Mypy: Type checking - mypy src/
Pytest: Testing framework
Security Considerations

Threat Model

Obscurio protects against:

File system access: Encrypted vault prevents plaintext credential extraction
Data tampering: GCM authentication tags detect unauthorized modifications
Brute-force attacks: Scrypt's memory-hard design increases attack cost
Memory scraping: Master key is held in memory only when vault is unlocked
Limitations

Does not protect against keyloggers or compromised host systems
No built-in synchronization across devices
Requires manual backups for data preservation
Contributing

Fork the repository
Create a feature branch: git checkout -b feature-name
Make changes and add tests
Ensure all tests pass: python -m pytest tests/
Submit a pull request
License

This project is licensed under the MIT License - see the LICENSE file for details.
