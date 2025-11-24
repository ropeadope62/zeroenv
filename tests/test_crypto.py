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
