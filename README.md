# Secure Password Manager

Local, encrypted, and yours alone.

A local password vault built in Python for the Information and Network Security course. Website credentials are stored in a single encrypted file (`vault.bin`). The key is derived from a master password with **Argon2id**, and the whole vault is encrypted and authenticated with **AES-256-GCM**. A browser interface and a command-line client share the same cryptographic core.

## Features

| Feature | Web UI | CLI |
| --- | :---: | :---: |
| Create a vault with a strength-checked master password | | ✓ |
| Unlock with the master password | ✓ | ✓ |
| Add credentials (weak passwords rejected or flagged) | ✓ | ✓ |
| View stored credentials | ✓ | ✓ |
| Passwords masked on screen, with Show and Copy | ✓ | |
| Edit and delete credentials | ✓ | |
| Generate strong random passwords (12–128 characters) | ✓ | ✓ |
| Change the master password (vault is re-encrypted) | ✓ | ✓ |
| Encrypted backup and verified restore (with safety copy) | ✓ | ✓ |
| Auto-lock after inactivity | 10 s | 120 s |
| Login throttling (3 attempts, increasing delay) | | ✓ |
| Security event log (no secrets written) | ✓ | ✓ |
| Tamper detection | ✓ | ✓ |

## Security design

| Element | Choice | Purpose |
| --- | --- | --- |
| Key derivation | Argon2id, t = 3, m = 64 MiB, p = 4, 32-byte key | Makes every master-password guess slow and memory-hard (RFC 9106 second recommended setting) |
| Salt | 16 random bytes (`os.urandom`), new on every save | Same password never gives the same key; defeats precomputed tables |
| Encryption | AES-256-GCM | Confidentiality and integrity in one step |
| Nonce | 12 random bytes (`os.urandom`), new on every save | Unique per encryption; a fresh key per save rules out nonce reuse |
| Associated data | `"PMV1"` + salt | The file header is authenticated, so it cannot be swapped or altered |
| Error handling | One generic message | A wrong password and a tampered file look identical to an attacker |

Vault file format:

```
MAGIC "PMV1" (4 B) | salt (16 B) | nonce (12 B) | ciphertext | GCM tag (16 B)
```

Everything is encrypted, including website names. The master password is never stored.

## Project structure

```
Password-Manager/
├── vault.py          Cryptographic core and command-line client
├── server.py         Local web server (127.0.0.1:8000) for the browser UI
├── attack_demo.py    Automated security tests and key-derivation benchmark
├── requirements.txt  Python dependencies
└── frontend/
    ├── index.html
    ├── script.js
    └── style.css
```

Created when you run the app (not stored in the repository):

| File | Contents |
| --- | --- |
| `vault.bin` | Your encrypted vault |
| `vault_backup.bin` | Encrypted backup |
| `vault.bin.before_restore` | Safety copy made before a restore |
| `security.log` | Security events with timestamps, no secrets |

## Installation

Requires Python 3.9 or later.

```
pip install -r requirements.txt
```

## Running

1. Create a vault (first run only) with the command-line client:

   ```
   python -B vault.py
   ```

2. Start the web interface:

   ```
   python -B server.py
   ```

3. Open http://127.0.0.1:8000 in your browser.

The server only listens on your own machine (127.0.0.1), so it is not reachable from the network.

## Security testing

```
python -B attack_demo.py
```

The script runs 22 checks on a temporary demo vault (25 when a `vault.bin` exists) and never prints keys or passwords:

1. Wrong master password is rejected with a generic message
2. A single flipped bit in the header, salt, nonce, ciphertext or tag, or a truncated file, is rejected
3. Site names, usernames and JSON keys are not visible in the encrypted file
4. The file matches the expected format
5. Every save uses a new salt, nonce and ciphertext
6. A SHA-256 fingerprint changes when the file changes
7. The real `vault.bin` is not modified by the tests
8. Benchmark: password guesses per second with SHA-256 versus Argon2id

Manual checks on Windows PowerShell:

```
Get-FileHash .\vault.bin -Algorithm SHA256
Select-String -Path .\vault.bin -Pattern "gmail-test.com"
Format-Hex .\vault.bin
```

No output from `Select-String` means the text is not in the file.

## Forgotten master password

There is no recovery. The master password is never stored, so nobody, including the developer, can open a vault without it. This is deliberate: any reset feature would also be a way in for an attacker. Keep your master password written down somewhere safe and offline. A backup made under an older master password can still be restored if you remember that password.

## Known limitations

- The web unlock has no attempt limit (the CLI has one).
- The local web API has no session token; other programs on the same machine could call it while the vault is unlocked.
- An older, valid vault file swapped in for the current one is not detected (no rollback protection).
- The password-strength check is a heuristic, not an entropy estimate.
- The master password is held in memory while the vault is unlocked, and Python cannot reliably wipe strings.
- Malware or a keylogger on an unlocked machine is outside the scope of this project.

## Project

Built as a cybersecurity project for the Information and Network Security course, demonstrating secure password storage, authenticated encryption, key derivation and security testing.
