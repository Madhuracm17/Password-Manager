🔐 PASSWORD MANAGER
A secure password manager built using Python, HTML, CSS, and JavaScript.
It stores website credentials inside an encrypted vault using Argon2id and AES-256-GCM.

📁 MAIN FILES

File              Purpose
vault.py          Main password manager and security logic
server.py         Connects the frontend with the Python backend
attack_demo.py    Runs security tests
vault.bin         Encrypted password vault
security.log      Security event log
frontend/         Web interface

▶️ HOW TO RUN

1. Start the web application:
python -B .\server.py

2. Open the browser:
http://127.0.0.1:8000

🔑 MAIN FEATURES
• Master password protection
• AES-256-GCM encrypted vault
• Argon2id key derivation
• Secure password generation
• Password strength checking
• Add and view saved passwords
• Brute-force login protection
• Auto-lock
• Security logging
• Vault backup and restore
• Tamper detection

🧪 SECURITY TESTING
Run the security demonstration:
python -B .\attack_demo.py

This tests:
• Wrong password rejection
• Vault tampering detection
• Plaintext leakage
• Vault format
• Random salt and nonce
• SHA-256 file fingerprint
• Argon2id security

🔍 USEFUL COMMANDS

Check vault hash:
Get-FileHash .\vault.bin -Algorithm SHA256

Check if plaintext is visible:
Select-String -Path .\vault.bin -Pattern "gmail-test.com"

No output means the text was not found in the encrypted vault.
Run the command-line version:
python -B .\vault.py

🛡️ SECURITY TECHNOLOGIES

Argon2id
Used to derive a strong encryption key from the master password.

AES-256-GCM
Encrypts the stored credentials and detects tampering.

Random Salt
Makes key derivation unique for each vault encryption.

Random Nonce
Ensures each encryption operation produces different encrypted data.

SHA-256
Creates a fingerprint that can be used to detect changes to the vault file.

👩‍💻 PROJECT
PASSWORD MANAGER
Built as a cybersecurity project demonstrating secure password storage, encryption, authentication, and security testing.
