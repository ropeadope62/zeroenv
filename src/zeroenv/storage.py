"""
Project: ZeroEnv - Git-Safe Secrets
Module: Secret Storage (storage.py)
Author: Dave C. (ropeadope62)
https://github.com/ropeadope62
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

from .crypto import ZeroEnvCrypto


class SecretsStorage:
    """Manages the encrypted secrets storage file"""
    
    SECRETS_FILE = ".secrets"
    KEY_FILE = ".secrets.key"
    
    def __init__(self, directory: Optional[str] = None):
        """
        Initialize storage
        
        Args:
            directory: Directory to store secrets (default: current directory)
        """
        self.directory = Path(directory or os.getcwd())
        self.secrets_path = self.directory / self.SECRETS_FILE
        self.key_path = self.directory / self.KEY_FILE
    
    def initialize(self, master_key: bytes, tier: str = 'standard') -> None:
        """
        Initialize ZeroEnv in the directory
        
        Creates .secrets file and .secrets.key file.
        
        Args:
            master_key: The master encryption key
            tier: Security tier ('standard', 'enhanced', or 'max')
        """
        # Validate tier
        if tier not in ZeroEnvCrypto.SECURITY_TIERS:
            raise ValueError(f"Invalid security tier: {tier}")
        
        # Create master key string to be written to .secrets.key
        key_string = ZeroEnvCrypto.key_to_string(master_key)
        self.key_path.write_text(key_string)
        
        # Create the baseline .secrets file with metadata
        initial_data = {
            "version": "1.0",
            "created_at": datetime.now().isoformat(),
            "security_tier": tier,
            "secrets": {}
        }
        
        # Generate and store salt for non-standard tiers
        if tier != 'standard':
            salt = ZeroEnvCrypto.generate_salt()
            initial_data["salt"] = ZeroEnvCrypto.key_to_string(salt)
        
        self.secrets_path.write_text(json.dumps(initial_data, indent=2))
    
    def is_initialized(self) -> bool:
        """
        Check if ZeroEnv is initialized in this directory
        
        Returns:
            True if both .secrets and .secrets.key exist
        """
        return self.secrets_path.exists() and self.key_path.exists()
    
    def load_master_key(self) -> bytes:
        """
        Load the master key from .secrets.key
        
        Returns:
            Master key bytes
            
        Raises:
            FileNotFoundError: If key file doesn't exist
        """
        if not self.key_path.exists():
            raise FileNotFoundError(
                f"Master key not found at {self.key_path}. "
                "Run 'zeroenv init' first."
            )
        
        key_string = self.key_path.read_text().strip()
        return ZeroEnvCrypto.string_to_key(key_string)
    
    def get_security_tier(self) -> str:
        """
        Get the security tier from .secrets file
        
        Returns:
            Security tier ('standard', 'enhanced', or 'max')
        """
        data = self.load_secrets_file()
        # Default to 'standard' for backward compatibility
        return data.get("security_tier", "standard")
    
    def get_salt(self) -> Optional[bytes]:
        """
        Get the salt from .secrets file
        
        Returns:
            Salt bytes or None if standard tier
        """
        data = self.load_secrets_file()
        salt_string = data.get("salt")
        if salt_string:
            return ZeroEnvCrypto.string_to_key(salt_string)
        return None
    
    def load_encryption_key(self) -> bytes:
        """
        Load and derive the encryption key based on security tier
        
        Returns:
            Derived encryption key ready for use with AESGCM
        """
        master_key = self.load_master_key()
        tier = self.get_security_tier()
        salt = self.get_salt()
        
        return ZeroEnvCrypto.derive_key(master_key, tier, salt)
    
    def load_secrets_file(self) -> dict:
        """
        Load the secrets file
        
        Returns:
            Dictionary containing encrypted secrets data
            
        Raises:
            FileNotFoundError: If secrets file doesn't exist
        """
        if not self.secrets_path.exists():
            raise FileNotFoundError(
                f"Secrets file not found at {self.secrets_path}. "
                "Run 'zeroenv init' first."
            )
        
        return json.loads(self.secrets_path.read_text())
    
    def save_secrets_file(self, data: dict) -> None:
        """
        Save the secrets file
        
        Args:
            data: Dictionary containing encrypted secrets data
        """
        self.secrets_path.write_text(json.dumps(data, indent=2))
    
    def add_secret(self, crypto: ZeroEnvCrypto, name: str, value: str) -> None:
        """
        Add or update a secret
        
        Args:
            crypto: Initialized crypto instance
            name: Secret name
            value: Secret value (will be encrypted)
        """
        data = self.load_secrets_file()
        
        encrypted = crypto.encrypt(value)
        data["secrets"][name] = {
            **encrypted,
            "updated_at": datetime.now().isoformat()
        }
        
        self.save_secrets_file(data)
    
    def get_secret(self, crypto: ZeroEnvCrypto, name: str) -> Optional[str]:
        """
        Get a decrypted secret value
        
        Args:
            crypto: Initialized crypto instance
            name: Secret name
            
        Returns:
            Decrypted secret value or None if not found
        """
        data = self.load_secrets_file()
        
        if name not in data["secrets"]:
            return None
        
        encrypted_data = data["secrets"][name]
        return crypto.decrypt(encrypted_data)
    
    def list_secrets(self) -> list:
        """
        List all secret names
        
        Returns:
            List of secret names
        """
        data = self.load_secrets_file()
        return list(data["secrets"].keys())
    
    def remove_secret(self, name: str) -> bool:
        """
        Remove a secret
        
        Args:
            name: Secret name to remove
            
        Returns:
            True if secret was removed, False if it didn't exist
        """
        data = self.load_secrets_file()
        
        if name not in data["secrets"]:
            return False
        
        del data["secrets"][name]
        self.save_secrets_file(data)
        return True
    
    def get_all_secrets(self, crypto: ZeroEnvCrypto) -> Dict[str, str]:
        """
        Get all secrets decrypted as a dictionary
        
        Args:
            crypto: Initialized crypto instance
            
        Returns:
            Dictionary of name: value pairs (all decrypted)
        """
        data = self.load_secrets_file()
        
        result = {}
        for name, encrypted_data in data["secrets"].items():
            result[name] = crypto.decrypt(encrypted_data)
        
        return result
    
    def get_secret_metadata(self, name: str) -> Optional[dict]:
        """
        Get metadata about a secret (without decrypting)
        
        Args:
            name: Secret name
            
        Returns:
            Dictionary with metadata or None if not found
        """
        data = self.load_secrets_file()
        
        if name not in data["secrets"]:
            return None
        
        secret_data = data["secrets"][name]
        return {
            "name": name,
            "updated_at": secret_data.get("updated_at", "unknown")
        }
