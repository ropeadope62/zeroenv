"""
Project: ZeroEnv - Git-Safe Secrets
Module: Cryptography Tests (test_crypto.py)
Author: Dave C. (ropeadope62)
https://github.com/ropeadope62
"""


import pytest
import base64
import os
from zeroenv.crypto import ZeroEnvCrypto, generate_master_key

class TestZeroEnvCrypto:
    @pytest.fixture
    def master_key(self):
        return generate_master_key()

    @pytest.fixture
    def crypto(self, master_key):
        return ZeroEnvCrypto(master_key)

    def test_init_valid_key(self, master_key):
        """Test initialization with a valid key"""
        crypto = ZeroEnvCrypto(master_key)
        assert crypto is not None

    def test_init_invalid_key_length(self):
        """Test initialization with invalid key length"""
        invalid_key = os.urandom(16)  # Wrong size (16 bytes instead of 32)
        with pytest.raises(ValueError, match="Master key must be 32 bytes"):
            ZeroEnvCrypto(invalid_key)

    def test_encrypt_decrypt(self, crypto):
        """Test basic encryption and decryption"""
        plaintext = "secret_password_123"
        encrypted = crypto.encrypt(plaintext)
        
        assert isinstance(encrypted, dict)
        assert 'ciphertext' in encrypted
        assert 'nonce' in encrypted
        
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_randomness(self, crypto):
        """Test that encrypting the same text twice produces different outputs (due to nonce)"""
        plaintext = "same_secret"
        enc1 = crypto.encrypt(plaintext)
        enc2 = crypto.encrypt(plaintext)
        
        assert enc1['nonce'] != enc2['nonce']
        assert enc1['ciphertext'] != enc2['ciphertext']
        
        # Both should decrypt to the same value
        assert crypto.decrypt(enc1) == plaintext
        assert crypto.decrypt(enc2) == plaintext

    def test_decrypt_invalid_data(self, crypto):
        """Test decryption with tampered data"""
        plaintext = "secret"
        encrypted = crypto.encrypt(plaintext)
        
        # Tamper with ciphertext
        raw_cipher = base64.b64decode(encrypted['ciphertext'])
        tampered_cipher = bytearray(raw_cipher)
        tampered_cipher[0] ^= 0xFF  # Flip bits
        encrypted['ciphertext'] = base64.b64encode(tampered_cipher).decode('utf-8')
        
        # Should raise an exception (likely from cryptography library)
        with pytest.raises(Exception):
            crypto.decrypt(encrypted)

    def test_generate_key(self):
        """Test key generation"""
        key = ZeroEnvCrypto.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_key_conversion(self):
        """Test key string conversion methods"""
        key = ZeroEnvCrypto.generate_key()
        key_str = ZeroEnvCrypto.key_to_string(key)
        
        assert isinstance(key_str, str)
        
        key_back = ZeroEnvCrypto.string_to_key(key_str)
        assert key_back == key


class TestSecurityTiers:
    """Tests for security tier functionality"""
    
    @pytest.fixture
    def master_key(self):
        return generate_master_key()
    
    def test_security_tiers_defined(self):
        """Test that all security tiers are properly defined"""
        assert 'standard' in ZeroEnvCrypto.SECURITY_TIERS
        assert 'enhanced' in ZeroEnvCrypto.SECURITY_TIERS
        assert 'max' in ZeroEnvCrypto.SECURITY_TIERS
        
        # Check tier configurations
        assert ZeroEnvCrypto.SECURITY_TIERS['standard']['iterations'] == 0
        assert ZeroEnvCrypto.SECURITY_TIERS['enhanced']['iterations'] == 100000
        assert ZeroEnvCrypto.SECURITY_TIERS['max']['iterations'] == 500000
    
    def test_generate_salt(self):
        """Test salt generation"""
        salt = ZeroEnvCrypto.generate_salt()
        assert isinstance(salt, bytes)
        assert len(salt) == 16  # SALT_SIZE
        
        # Test uniqueness
        salt2 = ZeroEnvCrypto.generate_salt()
        assert salt != salt2
    
    def test_derive_key_standard(self, master_key):
        """Test key derivation with standard tier (no PBKDF2)"""
        derived = ZeroEnvCrypto.derive_key(master_key, tier='standard')
        assert derived == master_key  # Should be identical
        assert len(derived) == 32
    
    def test_derive_key_enhanced(self, master_key):
        """Test key derivation with enhanced tier"""
        salt = ZeroEnvCrypto.generate_salt()
        derived = ZeroEnvCrypto.derive_key(master_key, tier='enhanced', salt=salt)
        
        assert len(derived) == 32
        assert derived != master_key  # Should be different from master
        
        # Test deterministic - same inputs produce same output
        derived2 = ZeroEnvCrypto.derive_key(master_key, tier='enhanced', salt=salt)
        assert derived == derived2
    
    def test_derive_key_max(self, master_key):
        """Test key derivation with max tier"""
        salt = ZeroEnvCrypto.generate_salt()
        derived = ZeroEnvCrypto.derive_key(master_key, tier='max', salt=salt)
        
        assert len(derived) == 32
        assert derived != master_key  # Should be different from master
    
    def test_derive_key_different_tiers_different_keys(self, master_key):
        """Test that different tiers produce different derived keys"""
        salt = ZeroEnvCrypto.generate_salt()
        
        standard = ZeroEnvCrypto.derive_key(master_key, tier='standard')
        enhanced = ZeroEnvCrypto.derive_key(master_key, tier='enhanced', salt=salt)
        max_key = ZeroEnvCrypto.derive_key(master_key, tier='max', salt=salt)
        
        # All should be different
        assert standard != enhanced
        assert standard != max_key
        assert enhanced != max_key
    
    def test_derive_key_invalid_tier(self, master_key):
        """Test error with invalid tier"""
        with pytest.raises(ValueError, match="Invalid security tier"):
            ZeroEnvCrypto.derive_key(master_key, tier='invalid')
    
    def test_derive_key_missing_salt(self, master_key):
        """Test error when salt is missing for non-standard tiers"""
        with pytest.raises(ValueError, match="Salt required"):
            ZeroEnvCrypto.derive_key(master_key, tier='enhanced', salt=None)
        
        with pytest.raises(ValueError, match="Salt required"):
            ZeroEnvCrypto.derive_key(master_key, tier='max', salt=None)
    
    def test_derive_key_invalid_salt_size(self, master_key):
        """Test error with wrong salt size"""
        wrong_salt = os.urandom(8)  # Wrong size
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            ZeroEnvCrypto.derive_key(master_key, tier='enhanced', salt=wrong_salt)
    
    def test_encrypt_decrypt_with_derived_key(self, master_key):
        """Test that encryption/decryption works with derived keys"""
        salt = ZeroEnvCrypto.generate_salt()
        derived_key = ZeroEnvCrypto.derive_key(master_key, tier='enhanced', salt=salt)
        
        crypto = ZeroEnvCrypto(derived_key)
        plaintext = "sensitive_data"
        
        encrypted = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(encrypted)
        
        assert decrypted == plaintext
