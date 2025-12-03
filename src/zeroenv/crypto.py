"""
Project: ZeroEnv - Git-Safe Secrets
Module: Cryptography (crypto.py)
Author: Dave C. (ropeadope62)
https://github.com/ropeadope62
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend



class ZeroEnvCrypto:
    """Handles all cryptographic operations for ZeroEnv"""
    
    # AES-256-GCM encryption parameters
    # AES-256 provides strong encryption (256-bit key = 2^256 possible keys)
    # Currently, still considered secure against brute-force attacks, 
    # Meets FIPS 140-2/140-3, NIST, NSA/CNSA Suite, PCI-DSS and OWASP standards 
    
    KEY_SIZE = 32  # 256 bits (32 bytes)
    
    # GCM mode nonce (number used once)
    # 96 bits is the recommended size for optimal GCM performance
    # Implement random nonce
    
    NONCE_SIZE = 12  # 96 bits (12 bytes)
    
    # Security tier configurations
    SECURITY_TIERS = {
        'standard': {
            'iterations': 0,  # No PBKDF2, direct key usage
            'description': 'Fast - Direct key (development)'
        },
        'enhanced': {
            'iterations': 100000,  # 100k iterations
            'description': 'Balanced - PBKDF2-SHA256 100k iterations'
        },
        'max': {
            'iterations': 500000,  # 500k iterations
            'description': 'Maximum - PBKDF2-SHA256 500k iterations (production)'
        }
    }
    
    SALT_SIZE = 16  # 128 bits for PBKDF2 salt
    
    def __init__(self, master_key: bytes):
        """
        Initialize crypto with master key
        
        Args:
            master_key: 32-byte encryption key
        """
        if len(master_key) != self.KEY_SIZE:
            raise ValueError(f"Master key must be {self.KEY_SIZE} bytes")
        
        self.aesgcm = AESGCM(master_key)
    
    def encrypt(self, plaintext: str) -> dict:
        """
        Encrypt a secret value
        
        Args:
            plaintext: The secret value to encrypt
            
        Returns:
            Dictionary containing encrypted data and nonce
        """
        # Generate random nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Encrypt the plaintext 
        ciphertext = self.aesgcm.encrypt(
            nonce,
            plaintext.encode('utf-8'),
            None  # No associated data
        )
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8')
        }
    
    def decrypt(self, encrypted_data: dict) -> str:
        """
        Decrypt a secret value
        
        Args:
            encrypted_data: Dictionary with 'ciphertext' and 'nonce' keys
            
        Returns:
            Decrypted plaintext string
        """
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        
        # Decrypt the data as into plaintext 
        plaintext = self.aesgcm.decrypt(
            nonce,
            ciphertext,
            None  # No associated data
        )
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a new random 256-bit encryption key
        
        Returns:
            32 random bytes suitable for use as master key
        """
        return os.urandom(ZeroEnvCrypto.KEY_SIZE)
    
    @staticmethod
    def generate_salt() -> bytes:
        """
        Generate a new random salt for PBKDF2
        
        Returns:
            16 random bytes for salt
        """
        return os.urandom(ZeroEnvCrypto.SALT_SIZE)
    
    @staticmethod
    def derive_key(master_key: bytes, tier: str = 'standard', salt: bytes = None) -> bytes:
        """
        Derive encryption key from master key using security tier
        
        Args:
            master_key: The master key (32 bytes)
            tier: Security tier ('standard', 'enhanced', or 'max')
            salt: Salt for PBKDF2 (required for non-standard tiers)
            
        Returns:
            Derived key (32 bytes)
            
        Raises:
            ValueError: If tier is invalid or salt is missing for non-standard tiers
        """
        if tier not in ZeroEnvCrypto.SECURITY_TIERS:
            raise ValueError(f"Invalid security tier: {tier}")
        
        iterations = ZeroEnvCrypto.SECURITY_TIERS[tier]['iterations']
        
        # Standard tier uses master key directly (no derivation)
        if iterations == 0:
            return master_key
        
        # Enhanced/Max tiers use PBKDF2
        if salt is None:
            raise ValueError(f"Salt required for '{tier}' security tier")
        
        if len(salt) != ZeroEnvCrypto.SALT_SIZE:
            raise ValueError(f"Salt must be {ZeroEnvCrypto.SALT_SIZE} bytes")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=ZeroEnvCrypto.KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        
        return kdf.derive(master_key)
    
    @staticmethod
    def key_to_string(key: bytes) -> str:
        """
        Convert key bytes to base64 string for storage
        
        Args:
            key: Key bytes
            
        Returns:
            Base64-encoded key string
        """
        return base64.b64encode(key).decode('utf-8')
    
    @staticmethod
    def string_to_key(key_string: str) -> bytes:
        """
        Convert base64 key string back to bytes
        
        Args:
            key_string: Base64-encoded key
            
        Returns:
            Key bytes
        """
        return base64.b64decode(key_string)


def generate_master_key() -> bytes:
    """
    Generate a new master key for ZeroEnv
    
    Returns:
        32-byte master key
    """
    return ZeroEnvCrypto.generate_key()
