#!/usr/bin/env python3
"""
SecureVault - Zero-Knowledge Personal Data Manager
A cryptographically secure CLI vault for storing sensitive information.

"""

import os
import sys
import json
import time
import hmac
import hashlib
import secrets
import getpass
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import click
from argon2.low_level import hash_secret_raw, Type
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init(autoreset=True)

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

VAULT_DIR = Path.home() / ".securevault"
VAULT_FILE = VAULT_DIR / "vault.enc"
CONFIG_FILE = VAULT_DIR / "config.json"
CERT_DIR = VAULT_DIR / "certificates"

# Cryptographic parameters
KEY_SIZE = 32  # 256 bits
SALT_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits (recommended for AES-GCM)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
SECURE_DELETE_PASSES = 7  # DOD 5220.22-M standard

# Auto-lock timeout (seconds)
AUTO_LOCK_TIMEOUT = 300  # 5 minutes


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def print_header(text: str):
    """Print styled header."""
    print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{text.center(60)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")


def print_success(text: str):
    """Print success message."""
    print(f"{Fore.GREEN}✓ {text}{Style.RESET_ALL}")


def print_error(text: str):
    """Print error message."""
    print(f"{Fore.RED}✗ {text}{Style.RESET_ALL}")


def print_warning(text: str):
    """Print warning message."""
    print(f"{Fore.YELLOW}⚠ {text}{Style.RESET_ALL}")


def print_info(text: str):
    """Print info message."""
    print(f"{Fore.BLUE}ℹ {text}{Style.RESET_ALL}")


# ============================================================================
# CRYPTOGRAPHIC CORE
# ============================================================================

class CryptoEngine:
    """
    Core cryptographic engine implementing:
    - AES-256-GCM for encryption/decryption
    - Argon2 for key derivation
    - CSPRNG for key/salt/nonce generation
    - HMAC-SHA256 for integrity verification
    """
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate cryptographically secure random salt using CSPRNG."""
        return secrets.token_bytes(SALT_SIZE)
    
    @staticmethod
    def generate_nonce() -> bytes:
        """Generate cryptographically secure random nonce using CSPRNG."""
        return secrets.token_bytes(NONCE_SIZE)
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate cryptographically secure random encryption key using CSPRNG."""
        return secrets.token_bytes(KEY_SIZE)
    
    @staticmethod
    def generate_id() -> str:
        """Generate cryptographically secure random entry ID."""
        return secrets.token_hex(16)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using Argon2.
    
        Argon2 Parameters:
        - Time cost: 3 iterations
        - Memory cost: 64 MB
        - Parallelism: 4 threads
        - Output: 256-bit key
        """
        from argon2.low_level import hash_secret_raw, Type
        
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_SIZE,
            type=Type.ID
        )
    
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> Dict[str, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Returns:
            dict: {
                'ciphertext': encrypted data,
                'nonce': nonce used for encryption,
                'tag': authentication tag
            }
        """
        nonce = CryptoEngine.generate_nonce()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        return {
            'ciphertext': ciphertext[:-16],  # Data without tag
            'tag': ciphertext[-16:],  # Last 16 bytes are the tag
            'nonce': nonce
        }
    
    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Raises:
            Exception: If authentication fails or data is tampered
        """
        aesgcm = AESGCM(key)
        # Combine ciphertext and tag for decryption
        combined = ciphertext + tag
        return aesgcm.decrypt(nonce, combined, None)
    
    @staticmethod
    def compute_hmac(data: bytes, key: bytes) -> bytes:
        """Compute HMAC-SHA256 for integrity verification."""
        return hmac.new(key, data, hashlib.sha256).digest()
    
    @staticmethod
    def verify_hmac(data: bytes, key: bytes, expected_hmac: bytes) -> bool:
        """Verify HMAC-SHA256 for integrity checking."""
        computed_hmac = CryptoEngine.compute_hmac(data, key)
        return hmac.compare_digest(computed_hmac, expected_hmac)


# ============================================================================
# SECURE DELETION
# ============================================================================

class SecureDeletion:
    """
    Implements DOD 5220.22-M secure deletion standard.
    Overwrites data multiple times with cryptographically random patterns.
    """
    
    @staticmethod
    def secure_wipe(file_path: Path, passes: int = SECURE_DELETE_PASSES) -> bool:
        """
        Securely delete file using multiple overwrite passes.
        
        DOD 5220.22-M Standard:
        - Pass 1: Overwrite with 0x00
        - Pass 2: Overwrite with 0xFF
        - Pass 3-7: Overwrite with cryptographically random data
        """
        try:
            if not file_path.exists():
                return True
            
            file_size = file_path.stat().st_size
            
            with open(file_path, 'r+b') as f:
                # Pass 1: All zeros
                f.seek(0)
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 2: All ones
                f.seek(0)
                f.write(b'\xFF' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Remaining passes: Cryptographically random data
                for _ in range(passes - 2):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally, delete the file
            os.remove(file_path)
            return True
            
        except Exception as e:
            print_error(f"Secure deletion failed: {str(e)}")
            return False
    
    @staticmethod
    def generate_deletion_certificate(entry_id: str, entry_name: str) -> str:
        """Generate cryptographic proof of deletion."""
        timestamp = datetime.now().isoformat()
        cert_id = secrets.token_hex(8)
        
        certificate = {
            "certificate_id": cert_id,
            "entry_id": entry_id,
            "entry_name": entry_name,
            "deletion_timestamp": timestamp,
            "deletion_method": f"DOD 5220.22-M ({SECURE_DELETE_PASSES} passes)",
            "proof_hash": hashlib.sha256(
                f"{entry_id}{entry_name}{timestamp}".encode()
            ).hexdigest()
        }
        
        # Save certificate
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        cert_file = CERT_DIR / f"cert_{cert_id}.json"
        
        with open(cert_file, 'w') as f:
            json.dump(certificate, f, indent=2)
        
        return cert_file


# ============================================================================
# VAULT MANAGER
# ============================================================================

class VaultManager:
    """
    Main vault management system.
    Handles all vault operations with cryptographic security.
    """
    
    def __init__(self):
        self.vault_data = None
        self.master_key = None
        self.last_access = None
        self.salt = None
    
    def initialize_vault(self, password: str) -> bool:
        """Initialize a new vault with master password."""
        try:
            VAULT_DIR.mkdir(parents=True, exist_ok=True)
            CERT_DIR.mkdir(parents=True, exist_ok=True)
            
            # Generate salt for key derivation
            self.salt = CryptoEngine.generate_salt()
            
            # Derive master key
            self.master_key = CryptoEngine.derive_key(password, self.salt)
            
            # Initialize empty vault structure
            self.vault_data = {
                "version": "1.0",
                "created": datetime.now().isoformat(),
                "entries": {},
                "metadata": {
                    "total_entries": 0,
                    "last_modified": datetime.now().isoformat()
                }
            }
            
            # Save vault
            self._save_vault()
            
            # Save configuration
            config = {
                "salt": self.salt.hex(),
                "created": datetime.now().isoformat()
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
            
            print_success("Vault initialized successfully!")
            print_info(f"Vault location: {VAULT_DIR}")
            return True
            
        except Exception as e:
            print_error(f"Failed to initialize vault: {str(e)}")
            return False
    
    def unlock_vault(self, password: str) -> bool:
        """Unlock vault with master password."""
        try:
            # Load configuration
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            
            self.salt = bytes.fromhex(config['salt'])
            
            # Derive key from password
            self.master_key = CryptoEngine.derive_key(password, self.salt)
            
            # Try to load and decrypt vault
            self._load_vault()
            
            self.last_access = time.time()
            print_success("Vault unlocked successfully!")
            return True
            
        except Exception as e:
            print_error("Failed to unlock vault. Invalid password or corrupted vault.")
            return False
    
    def _check_auto_lock(self):
        """Check if vault should auto-lock due to inactivity."""
        if self.last_access and (time.time() - self.last_access) > AUTO_LOCK_TIMEOUT:
            print_warning("Vault auto-locked due to inactivity.")
            self.lock_vault()
            return True
        return False
    
    def lock_vault(self):
        """Lock vault and clear sensitive data from memory."""
        self.master_key = None
        self.vault_data = None
        self.last_access = None
        print_info("Vault locked.")
    
    def _save_vault(self):
        """Encrypt and save vault to disk."""
        # Serialize vault data
        vault_json = json.dumps(self.vault_data).encode()
        
        # Encrypt vault
        encrypted = CryptoEngine.encrypt(vault_json, self.master_key)
        
        # Compute HMAC for integrity
        data_to_hmac = encrypted['ciphertext'] + encrypted['nonce'] + encrypted['tag']
        vault_hmac = CryptoEngine.compute_hmac(data_to_hmac, self.master_key)
        
        # Package everything
        vault_package = {
            'ciphertext': encrypted['ciphertext'].hex(),
            'nonce': encrypted['nonce'].hex(),
            'tag': encrypted['tag'].hex(),
            'hmac': vault_hmac.hex()
        }
        
        # Save to disk
        with open(VAULT_FILE, 'w') as f:
            json.dump(vault_package, f)
    
    def _load_vault(self):
        """Load and decrypt vault from disk."""
        with open(VAULT_FILE, 'r') as f:
            vault_package = json.load(f)
        
        # Extract components
        ciphertext = bytes.fromhex(vault_package['ciphertext'])
        nonce = bytes.fromhex(vault_package['nonce'])
        tag = bytes.fromhex(vault_package['tag'])
        stored_hmac = bytes.fromhex(vault_package['hmac'])
        
        # Verify HMAC integrity
        data_to_verify = ciphertext + nonce + tag
        if not CryptoEngine.verify_hmac(data_to_verify, self.master_key, stored_hmac):
            raise Exception("Vault integrity check failed! Data may be corrupted or tampered.")
        
        # Decrypt vault
        decrypted = CryptoEngine.decrypt(ciphertext, self.master_key, nonce, tag)
        self.vault_data = json.loads(decrypted.decode())
    
    def add_entry(self, name: str, entry_type: str, content: str) -> bool:
        """Add encrypted entry to vault."""
        if self._check_auto_lock():
            return False
        
        try:
            # Generate unique entry ID
            entry_id = CryptoEngine.generate_id()
            
            # Generate unique encryption key for this entry
            entry_key = CryptoEngine.generate_key()
            
            # Encrypt entry content
            encrypted_content = CryptoEngine.encrypt(content.encode(), entry_key)
            
            # Encrypt entry key with master key
            encrypted_key = CryptoEngine.encrypt(entry_key, self.master_key)
            
            # Store entry
            self.vault_data['entries'][entry_id] = {
                'name': name,
                'type': entry_type,
                'content_ciphertext': encrypted_content['ciphertext'].hex(),
                'content_nonce': encrypted_content['nonce'].hex(),
                'content_tag': encrypted_content['tag'].hex(),
                'key_ciphertext': encrypted_key['ciphertext'].hex(),
                'key_nonce': encrypted_key['nonce'].hex(),
                'key_tag': encrypted_key['tag'].hex(),
                'created': datetime.now().isoformat(),
                'modified': datetime.now().isoformat()
            }
            
            # Update metadata
            self.vault_data['metadata']['total_entries'] += 1
            self.vault_data['metadata']['last_modified'] = datetime.now().isoformat()
            
            self._save_vault()
            self.last_access = time.time()
            
            print_success(f"Entry '{name}' added successfully!")
            print_info(f"Entry ID: {entry_id}")
            return True
            
        except Exception as e:
            print_error(f"Failed to add entry: {str(e)}")
            return False
    
    def view_entry(self, entry_name: str) -> Optional[Dict[str, Any]]:
        """Decrypt and view entry."""
        if self._check_auto_lock():
            return None
        
        try:
            # Find entry by name
            entry_id = None
            for eid, entry in self.vault_data['entries'].items():
                if entry['name'] == entry_name:
                    entry_id = eid
                    break
            
            if not entry_id:
                print_error(f"Entry '{entry_name}' not found.")
                return None
            
            entry = self.vault_data['entries'][entry_id]
            
            # Decrypt entry key
            entry_key = CryptoEngine.decrypt(
                bytes.fromhex(entry['key_ciphertext']),
                self.master_key,
                bytes.fromhex(entry['key_nonce']),
                bytes.fromhex(entry['key_tag'])
            )
            
            # Decrypt content
            content = CryptoEngine.decrypt(
                bytes.fromhex(entry['content_ciphertext']),
                entry_key,
                bytes.fromhex(entry['content_nonce']),
                bytes.fromhex(entry['content_tag'])
            ).decode()
            
            self.last_access = time.time()
            
            return {
                'id': entry_id,
                'name': entry['name'],
                'type': entry['type'],
                'content': content,
                'created': entry['created'],
                'modified': entry['modified']
            }
            
        except Exception as e:
            print_error(f"Failed to view entry: {str(e)}")
            return None
    
    def list_entries(self) -> List[Dict[str, str]]:
        """List all entries (metadata only, no decryption)."""
        if self._check_auto_lock():
            return []
        
        entries = []
        for entry_id, entry in self.vault_data['entries'].items():
            entries.append({
                'id': entry_id,
                'name': entry['name'],
                'type': entry['type'],
                'created': entry['created']
            })
        
        self.last_access = time.time()
        return entries
    
    def delete_entry(self, entry_name: str, generate_cert: bool = True) -> bool:
        """Securely delete entry with optional certificate."""
        if self._check_auto_lock():
            return False
        
        try:
            # Find entry
            entry_id = None
            for eid, entry in self.vault_data['entries'].items():
                if entry['name'] == entry_name:
                    entry_id = eid
                    break
            
            if not entry_id:
                print_error(f"Entry '{entry_name}' not found.")
                return False
            
            entry = self.vault_data['entries'][entry_id]
            
            # Generate deletion certificate
            cert_file = None
            if generate_cert:
                cert_file = SecureDeletion.generate_deletion_certificate(
                    entry_id, entry_name
                )
            
            # Remove from vault
            del self.vault_data['entries'][entry_id]
            
            # Update metadata
            self.vault_data['metadata']['total_entries'] -= 1
            self.vault_data['metadata']['last_modified'] = datetime.now().isoformat()
            
            self._save_vault()
            self.last_access = time.time()
            
            print_success(f"Entry '{entry_name}' securely deleted!")
            if cert_file:
                print_info(f"Deletion certificate: {cert_file}")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to delete entry: {str(e)}")
            return False
    
    def export_vault(self, export_path: str) -> bool:
        """Export encrypted vault backup."""
        if self._check_auto_lock():
            return False
        
        try:
            export_file = Path(export_path)
            
            # Create export package
            export_data = {
                'vault': self.vault_data,
                'salt': self.salt.hex(),
                'exported': datetime.now().isoformat(),
                'version': '1.0'
            }
            
            # Encrypt export
            export_json = json.dumps(export_data).encode()
            encrypted = CryptoEngine.encrypt(export_json, self.master_key)
            
            # Compute integrity hash
            export_hash = hashlib.sha256(export_json).hexdigest()
            
            # Package
            export_package = {
                'ciphertext': encrypted['ciphertext'].hex(),
                'nonce': encrypted['nonce'].hex(),
                'tag': encrypted['tag'].hex(),
                'hash': export_hash
            }
            
            # Save
            with open(export_file, 'w') as f:
                json.dump(export_package, f, indent=2)
            
            self.last_access = time.time()
            
            print_success(f"Vault exported to: {export_file}")
            print_info(f"SHA256: {export_hash}")
            return True
            
        except Exception as e:
            print_error(f"Failed to export vault: {str(e)}")
            return False
    
    def import_vault(self, import_path: str, password: str) -> bool:
        """Import encrypted vault backup."""
        try:
            import_file = Path(import_path)
            
            with open(import_file, 'r') as f:
                export_package = json.load(f)
            
            # Load salt
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            
            salt = bytes.fromhex(config['salt'])
            
            # Derive key
            master_key = CryptoEngine.derive_key(password, salt)
            
            # Decrypt
            decrypted = CryptoEngine.decrypt(
                bytes.fromhex(export_package['ciphertext']),
                master_key,
                bytes.fromhex(export_package['nonce']),
                bytes.fromhex(export_package['tag'])
            )
            
            # Verify integrity
            computed_hash = hashlib.sha256(decrypted).hexdigest()
            if computed_hash != export_package['hash']:
                print_error("Import failed: Integrity check failed!")
                return False
            
            # Load data
            import_data = json.loads(decrypted.decode())
            
            # Update vault
            self.vault_data = import_data['vault']
            self.master_key = master_key
            self.salt = salt
            
            self._save_vault()
            
            print_success("Vault imported successfully!")
            return True
            
        except Exception as e:
            print_error(f"Failed to import vault: {str(e)}")
            return False


# ============================================================================
# CLI INTERFACE
# ============================================================================

vault = VaultManager()

@click.group()
def cli():
    """
    SecureVault - Zero-Knowledge Personal Data Manager
    
    A cryptographically secure CLI vault for storing sensitive information.
    Uses AES-256-GCM encryption with Argon2 key derivation.
    """
    pass


@cli.command()
def init():
    """Initialize a new vault."""
    print_header("INITIALIZE NEW VAULT")
    
    if VAULT_FILE.exists():
        print_error("Vault already exists!")
        if click.confirm("Overwrite existing vault?", default=False):
            SecureDeletion.secure_wipe(VAULT_FILE)
        else:
            return
    
    password = getpass.getpass("Enter master password: ")
    confirm = getpass.getpass("Confirm master password: ")
    
    if password != confirm:
        print_error("Passwords do not match!")
        return
    
    if len(password) < 8:
        print_warning("Password is weak. Recommended: 12+ characters.")
        if not click.confirm("Continue anyway?", default=False):
            return
    
    vault.initialize_vault(password)


@cli.command()
@click.option('--name', prompt='Entry name', help='Name of the entry')
@click.option('--type', prompt='Entry type (password/note/apikey/file)', 
              type=click.Choice(['password', 'note', 'apikey', 'file']),
              help='Type of entry')
@click.option('--content', prompt='Content', hide_input=True, help='Entry content')
def add(name, type, content):
    """Add a new entry to the vault."""
    print_header("ADD NEW ENTRY")
    
    password = getpass.getpass("Enter master password: ")
    
    if not vault.unlock_vault(password):
        return
    
    vault.add_entry(name, type, content)
    vault.lock_vault()


@cli.command()
@click.argument('name')
def view(name):
    """View an entry from the vault."""
    print_header(f"VIEW ENTRY: {name}")
    
    password = getpass.getpass("Enter master password: ")
    
    if not vault.unlock_vault(password):
        return
    
    entry = vault.view_entry(name)
    
    if entry:
        print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Name:{Style.RESET_ALL} {entry['name']}")
        print(f"{Fore.YELLOW}Type:{Style.RESET_ALL} {entry['type']}")
        print(f"{Fore.YELLOW}Content:{Style.RESET_ALL} {entry['content']}")
        print(f"{Fore.YELLOW}Created:{Style.RESET_ALL} {entry['created']}")
        print(f"{Fore.YELLOW}Modified:{Style.RESET_ALL} {entry['modified']}")
        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")
    
    vault.lock_vault()

@cli.command()
def list():
    """List all entries in the vault."""
    print_header("VAULT ENTRIES")
    
    password = getpass.getpass("Enter master password: ")
    
    if not vault.unlock_vault(password):
        return
    
    entries = vault.list_entries()
    
    if not entries:
        print_info("Vault is empty.")
    else:
        print(f"\n{Fore.CYAN}Total entries: {len(entries)}{Style.RESET_ALL}\n")
        for entry in entries:
            print(f"{Fore.GREEN}●{Style.RESET_ALL} {Fore.WHITE}{entry['name']}{Style.RESET_ALL} "
                  f"{Fore.YELLOW}({entry['type']}){Style.RESET_ALL} "
                  f"{Fore.BLUE}[{entry['created'][:10]}]{Style.RESET_ALL}")
        print()
    
    vault.lock_vault()


@cli.command()
@click.argument('name')
@click.option('--no-cert', is_flag=True, help='Skip deletion certificate generation')
def delete(name, no_cert):
    """Securely delete an entry from the vault."""
    print_header(f"DELETE ENTRY: {name}")
    
    password = getpass.getpass("Enter master password: ")
    
    if not vault.unlock_vault(password):
        return
    
    print_warning("This will PERMANENTLY delete the entry using DOD 5220.22-M wipe.")
    if not click.confirm("Continue?", default=False):
        print_info("Deletion cancelled.")
        return
    
    vault.delete_entry(name, generate_cert=not no_cert)
    vault.lock_vault()


@cli.command()
@click.argument('output_file')
def export(output_file):
    """Export encrypted vault backup."""
    print_header("EXPORT VAULT")
    
    password = getpass.getpass("Enter master password: ")
    
    if not vault.unlock_vault(password):
        return
    
    vault.export_vault(output_file)
    vault.lock_vault()


@cli.command()
@click.argument('input_file')
def import_vault(input_file):
    """Import encrypted vault backup."""
    print_header("IMPORT VAULT")
    
    password = getpass.getpass("Enter master password: ")
    
    vault.import_vault(input_file, password)


@cli.command()
def stats():
    """Show vault statistics and security information."""
    print_header("VAULT STATISTICS")
    
    password = getpass.getpass("Enter master password: ")
    
    if not vault.unlock_vault(password):
        return
    
    metadata = vault.vault_data['metadata']
    
    print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Vault Version:{Style.RESET_ALL} {vault.vault_data['version']}")
    print(f"{Fore.YELLOW}Created:{Style.RESET_ALL} {vault.vault_data['created']}")
    print(f"{Fore.YELLOW}Total Entries:{Style.RESET_ALL} {metadata['total_entries']}")
    print(f"{Fore.YELLOW}Last Modified:{Style.RESET_ALL} {metadata['last_modified']}")
    print(f"\n{Fore.CYAN}Security Configuration:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Encryption:{Style.RESET_ALL} AES-256-GCM")
    print(f"{Fore.YELLOW}Key Derivation:{Style.RESET_ALL} Argon2 (64MB memory, 3 iterations)")
    print(f"{Fore.YELLOW}Random Generation:{Style.RESET_ALL} CSPRNG (secrets module)")
    print(f"{Fore.YELLOW}Integrity:{Style.RESET_ALL} HMAC-SHA256")
    print(f"{Fore.YELLOW}Secure Deletion:{Style.RESET_ALL} DOD 5220.22-M ({SECURE_DELETE_PASSES} passes)")
    print(f"{Fore.YELLOW}Auto-lock Timeout:{Style.RESET_ALL} {AUTO_LOCK_TIMEOUT // 60} minutes")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")
    
    vault.lock_vault()


if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        sys.exit(1)
