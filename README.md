# SecureVault — Zero-Knowledge Personal Data Manager

A cryptographic CLI vault for storing sensitive information using AES-256-GCM authenticated encryption, Argon2 key derivation, integrity verification, secure deletion, and a zero-knowledge architecture.


# Screenshot:
![securevault](https://github.com/PavithraaDeenadayalan/SecureVault/blob/main/help.png)
---

## Table of Contents

- [Features](#-features)
- [Security Architecture](#-security-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Cryptographic Implementation](#-cryptographic-implementation)
- [Security Considerations](#-security-considerations)
- [Project Structure](#-project-structure)

---

##  Features

### Core Functionality
-  **AES-256-GCM Encryption** - Industry-standard authenticated encryption
-  **Argon2 Key Derivation** - Memory-hard password hashing (winner of PHC)
-  **CSPRNG** - Cryptographically secure random number generation for all keys, salts, and nonces
-  **HMAC-SHA256** - Integrity verification for tamper detection
-  **Zero-Knowledge Architecture** - Master password never leaves your device

### Advanced Features
-  **DoD 5220.22-M-Inspired Secure Deletion** – 7-pass overwrite approach using zero, one, and cryptographically random data
-  **Deletion Certificates** - Tamper-evident deletion record
-  **Auto-lock Mechanism** - Automatic vault locking after 5 minutes of inactivity
-  **Encrypted Export/Import** - Secure vault backups with integrity verification
-  **Multi-type Storage** - Support for passwords, API keys, notes, and files

### User Experience
-  **Professional CLI Interface** - Clean, color-coded output with clear feedback
-  **Comprehensive Error Handling** - Informative error messages and graceful failures
-  **Cross-platform Support** - Works on Windows, macOS, and Linux

---

##  Security Architecture

### Encryption Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     SECUREVAULT ARCHITECTURE                 │
└─────────────────────────────────────────────────────────────┘

USER PASSWORD
     ↓
[Argon2 Key Derivation]
  • Time Cost: 3 iterations
  • Memory Cost: 64 MB
  • Parallelism: 4 threads
  • Salt: 256-bit random (CSPRNG)
     ↓
MASTER KEY (256-bit)
     ↓
     ├─→ [Encrypt Entry Key] ──→ Encrypted Entry Key
     │         ↓
     │    ENTRY KEY (256-bit random)
     │         ↓
     │    [AES-256-GCM]
     │    • Nonce: 96-bit random (CSPRNG)
     │    • Tag: 128-bit authentication
     │         ↓
     │    ENCRYPTED CONTENT
     │         ↓
     └─→ [HMAC-SHA256] ──→ Integrity Tag
              ↓
         VAULT FILE
    (Encrypted + Authenticated)
```

### Key Security Properties

1. **Authentication**: AES-GCM provides built-in authentication
2. **Integrity**: HMAC prevents tampering with vault file
3. **Confidentiality**: AES-256 is computationally infeasible to break
4. **Non-deterministic**: Random nonces prevent identical plaintexts from producing identical ciphertexts
5. **Key Separation**: Each entry uses a unique encryption key

---

##   Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Download

```bash
# Download the securevault.py file
git clone https://github.com/pavithraadeenadayalan/securevault.git
cd securevault
```

or for manual process

```bash
cd ~
mkdir securevault-project
cd securevault-project
nano securevault.py
vim securevault.py
# Copy all the code (from the document I gave you)
# Paste it into the file
# Save and exit:
# - In nano: Ctrl+X, then Y, then Enter
# - In vim: ESC, then :wq, then Enter
```

### Step 2: Install Dependencies

The script will automatically install required dependencies on first run, or you can install manually:

```bash
pip install cryptography click colorama argon2-cffi
# OR if pip3 doesn't work:
python3 -m pip install cryptography click colorama argon2-cffi
```

### Step 3: Make Executable (Optional - Linux/Mac)

```bash
chmod +x securevault.py
```

---

##  Quick Start

### Initialize Vault

```bash
python securevault.py init
```

You'll be prompted to create a master password. **Choose a strong password** - this is the only way to access your vault!

```
═══════════════════════════════════════════════════════════
              INITIALIZE NEW VAULT
═══════════════════════════════════════════════════════════

Enter master password: ********
Confirm master password: ********
✓ Vault initialized successfully!
ℹ Vault location: /home/user/.securevault
```
# Screenshot:
![image](https://github.com/PavithraaDeenadayalan/SecureVault/blob/main/init.png)

### Add Your First Entry

```bash
python securevault.py add
```

```
═══════════════════════════════════════════════════════════
                   ADD NEW ENTRY
═══════════════════════════════════════════════════════════

Enter master password: ********
Entry name: Gmail Password
Entry type (password/note/apikey/file): password
Content: ********
✓ Entry 'Gmail Password' added successfully!
ℹ Entry ID: a3f9c2e14b8d7f6a
```

### View Entry

```bash
python securevault.py view "Gmail Password"
```

### List All Entries

```bash
python securevault.py list
```

```
═══════════════════════════════════════════════════════════
                   VAULT ENTRIES
═══════════════════════════════════════════════════════════

Enter master password: ********

Total entries: 3

● Gmail Password (password) [2025-12-14]
● AWS API Key (apikey) [2025-12-14]
● Personal Notes (note) [2025-12-13]
```

---
# Screenshot:
![image](https://github.com/PavithraaDeenadayalan/SecureVault/blob/main/list.png)

##  Usage Guide

### All Available Commands

```bash
# Initialize a new vault
python securevault.py init

# Add entry (interactive mode)
python securevault.py add

# View specific entry
python securevault.py view "Entry Name"

# List all entries
python securevault.py list

# Delete entry (with certificate)
python securevault.py delete "Entry Name"

# Delete entry (without certificate)
python securevault.py delete "Entry Name" --no-cert

# Export encrypted backup
python securevault.py export backup.enc

# Import from backup
python securevault.py import-vault backup.enc

# View vault statistics
python securevault.py stats

# Help
python securevault.py --help
```
---
# Screenshot:
![image](https://github.com/PavithraaDeenadayalan/SecureVault/blob/main/export.png)

##  Cryptographic Implementation

### 1. Random Number Generation (CSPRNG)

**Purpose**: Generate cryptographically secure random values for keys, salts, nonces, and IDs.

**Implementation**: Uses Python's `secrets` module, which provides access to the operating system's cryptographically secure random number generator:

**Usage in SecureVault**:
```python
# Generate 256-bit encryption key
key = secrets.token_bytes(32)  # 32 bytes = 256 bits

# Generate 256-bit salt
salt = secrets.token_bytes(32)

# Generate 96-bit nonce (AES-GCM standard)
nonce = secrets.token_bytes(12)

# Generate unique entry ID
entry_id = secrets.token_hex(16)  # 16 bytes = 128 bits
```

**Why CSPRNG?**: Regular `random()` is predictable and unsuitable for security. CSPRNG provides:
- Unpredictability
- Non-reproducibility
- Sufficient entropy
- Resistance to statistical attacks

---

### 2. Key Derivation (Argon2)

**Purpose**: Convert user password into a cryptographic key.

**Why Argon2?**:
- Winner of Password Hashing Competition (2015)
- Memory-hard (resistant to GPU/ASIC attacks)
- Time-hard (adjustable computational cost)
- Recommended by OWASP, NIST

**Parameters Used**:
```python
Time Cost: 3 iterations        # Computational hardness
Memory Cost: 65536 KB (64 MB)  # Memory hardness
Parallelism: 4 threads         # CPU cores used
Salt: 256-bit random           # Unique per vault
Output: 256-bit key            # AES-256 key size
```

**Attack Resistance**:
- **Brute Force**: 64MB memory per attempt makes parallel attacks expensive
- **Rainbow Tables**: Unique salt prevents pre-computed tables
- **GPU Attacks**: Memory-hard design limits GPU advantage

---

### 3. Encryption (AES-256-GCM)

**Purpose**: Encrypt data with authentication.

**Why AES-256-GCM?**:
- **AES-256**: Widely standardized symmetric encryption algorithm providing a 256-bit key space
- **GCM Mode**: Provides both confidentiality AND authentication
- **AES-256-GCM based on the NIST-standardized AES algorithm**

**How It Works**:
```
Plaintext + Key + Nonce → AES-256-GCM → Ciphertext + Authentication Tag

Authentication Tag provides:
- Integrity protection
- Authenticity verification
- Detection of modified ciphertext or associated data

Nonce Requirement:
- A unique nonce must be used with each encryption under the same key
```

**Security Properties**:
- **Confidentiality**: AES-256 provides a 256-bit key space, making exhaustive key search computationally infeasible when implemented correctly.
- **Authentication**: 128-bit tag prevents tampering
- **Efficiency**: Hardware acceleration on modern CPUs (AES-NI)

---

### 4. Integrity Verification (HMAC-SHA256)

**Purpose**: Detect tampering with vault file.

**Implementation**:
```python
HMAC-SHA256(HMAC_Key, Ciphertext + Nonce + Tag)
```

**Why Double Protection?**:
- AES-GCM authenticates individual entries
- HMAC authenticates the entire vault file
- Defense in depth: Both must be valid

**Attack Prevention**:
- Prevents bit-flipping attacks
- Prevents ciphertext substitution
- Prevents rollback attacks

---

### 5. Secure Deletion — DoD 5220.22-M-Inspired

**Purpose:** Reduce the recoverability of deleted data through multi-pass overwriting.

SecureVault implements a 7-pass overwrite procedure based on the DoD 5220.22-M approach:

```text
Pass 1: Overwrite with 0x00 (all zeros)
Pass 2: Overwrite with 0xFF (all ones)
Pass 3-7: Overwrite with cryptographically random data
---

##  Security Considerations

### Threat Model

**SecureVault Protects Against:**
 Unauthorized access to vault file
 Password cracking attacks (Argon2 memory-hardness)
 Brute force attacks (strong key derivation)
 Data tampering (HMAC integrity checks)
 Basic data recovery attempts against overwritten files
 Weak randomness (CSPRNG for all random values)

**SecureVault Does NOT Protect Against:**
 **Keyloggers**: Malware that records your master password
 **Memory dumps**: Capturing RAM while vault is unlocked
 **Rubber-hose cryptanalysis**: Physical coercion
 **Side-channel attacks**: Timing attacks, power analysis (requires physical access)
 **Weak passwords**: If you choose "password123", no crypto can save you

### Best Practices

#### Strong Master Password
```
 Bad: password123
 Bad: MyVault2024
 Good: correct-horse-battery-staple
 Good: Tr0ub4dor&3-Extended-Version
 Good: Random passphrase from password manager
```

**Recommendations**:
- Minimum 12 characters
- Mix of letters, numbers, symbols
- Use a passphrase (easier to remember, harder to crack)
- Never reuse passwords
- Store backup in secure location (not digitally)

#### Vault Security
- Lock vault when not in use
- Don't leave vault unlocked and walk away
- Keep backups encrypted
- Store backups on separate device/location
- Use full-disk encryption on your computer

#### Operational Security
- Don't run on compromised systems
- Don't access vault over remote desktop without encryption
- Clear terminal history if it logs commands
- Verify integrity of securevault.py (check hash)

---

##  Project Structure

```
.securevault/                    # Vault directory (created in home folder)
├── vault.enc                    # Encrypted vault file
├── config.json                  # Configuration (contains salt)
└── certificates/                # Deletion certificates
    ├── cert_a3f9c2e1.json
    └── cert_b8d7f6a2.json

securevault.py                   # Main application
README.md                        # This file
```

### Vault File Format

```json
{
  "ciphertext": "hex_encoded_encrypted_data",
  "nonce": "hex_encoded_96bit_nonce",
  "tag": "hex_encoded_128bit_auth_tag",
  "hmac": "hex_encoded_256bit_integrity_tag"
}
```

### Deletion Certificate Format

```json
{
  "certificate_id": "random_id",
  "entry_id": "deleted_entry_id",
  "entry_name": "Entry Name",
  "deletion_timestamp": "2025-12-14T10:30:15",
  "deletion_method": "DOD 5220.22-M (7 passes)",
  "proof_hash": "sha256_hash_of_deletion_event"
}
```
# Screenshot:
![image](https://github.com/PavithraaDeenadayalan/SecureVault/blob/main/deleteCert.png)

## License
Copyright © 2025 Pavithraa Deenadayalan

Free for personal and educational use. 
For commercial use, please contact me.

---

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- **NIST** - AES and cryptographic standards
- **Password Hashing Competition** - Argon2
- **Python Cryptographic Authority** - `cryptography` library
- **OWASP** - Security best practices

---

## Security
⚠️ **Please do not open public issues for security vulnerabilities.**
Email security concerns to: [pavithraadeenadayalan35@gmail.com]

## Author

**Pavithraa Deenadayalan**  
GitHub: [https://github.com/pavithraadeenadayalan](https://github.com/pavithraadeenadayalan)

---

## References

- [NIST AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [DOD 5220.22-M Standard](https://www.bitraser.com/article/DoD-5220-22-m-standard-for-drive-erasure.php)

---

**Built with ❤️ for cryptography and security**
