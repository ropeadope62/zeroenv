"""
Project: ZeroEnv - Git-Safe Secrets
Module: Secret Storage Tests (test_storage.py)
Author: Dave C. (ropeadope62)
https://github.com/ropeadope62
"""


import pytest
import json
import os
from pathlib import Path
from zeroenv.storage import SecretsStorage
from zeroenv.crypto import ZeroEnvCrypto, generate_master_key

class TestSecretsStorage:
    @pytest.fixture
    def temp_dir(self, tmp_path):
        """Fixture to provide a temporary directory"""
        return str(tmp_path)

    @pytest.fixture
    def storage(self, temp_dir):
        """Fixture to provide an initialized storage instance"""
        return SecretsStorage(temp_dir)

    @pytest.fixture
    def master_key(self):
        return generate_master_key()

    @pytest.fixture
    def crypto(self, master_key):
        return ZeroEnvCrypto(master_key)

    def test_init_paths(self, temp_dir):
        """Test that paths are correctly set"""
        storage = SecretsStorage(temp_dir)
        assert storage.directory == Path(temp_dir)
        assert storage.secrets_path == Path(temp_dir) / ".secrets"
        assert storage.key_path == Path(temp_dir) / ".secrets.key"

    def test_initialize(self, storage, master_key):
        """Test initialization creates files"""
        assert not storage.is_initialized()
        
        storage.initialize(master_key)
        
        assert storage.is_initialized()
        assert storage.key_path.exists()
        assert storage.secrets_path.exists()
        
        # Verify key file content
        saved_key_str = storage.key_path.read_text()
        assert ZeroEnvCrypto.string_to_key(saved_key_str) == master_key
        
        # Verify secrets file content
        data = json.loads(storage.secrets_path.read_text())
        assert data['version'] == "1.0"
        assert data['secrets'] == {}

    def test_load_master_key(self, storage, master_key):
        """Test loading the master key"""
        storage.initialize(master_key)
        loaded_key = storage.load_master_key()
        assert loaded_key == master_key

    def test_load_master_key_not_found(self, storage):
        """Test error when key file is missing"""
        with pytest.raises(FileNotFoundError):
            storage.load_master_key()

    def test_add_get_secret(self, storage, crypto, master_key):
        """Test adding and retrieving secrets"""
        storage.initialize(master_key)
        
        name = "API_KEY"
        value = "123456"
        
        storage.add_secret(crypto, name, value)
        
        # Verify it's in the file
        data = storage.load_secrets_file()
        assert name in data['secrets']
        
        # Verify we can retrieve it
        retrieved = storage.get_secret(crypto, name)
        assert retrieved == value

    def test_get_secret_not_found(self, storage, crypto, master_key):
        """Test retrieving a non-existent secret"""
        storage.initialize(master_key)
        assert storage.get_secret(crypto, "NONEXISTENT") is None

    def test_list_secrets(self, storage, crypto, master_key):
        """Test listing secrets"""
        storage.initialize(master_key)
        storage.add_secret(crypto, "A", "1")
        storage.add_secret(crypto, "B", "2")
        
        secrets = storage.list_secrets()
        assert len(secrets) == 2
        assert "A" in secrets
        assert "B" in secrets

    def test_remove_secret(self, storage, crypto, master_key):
        """Test removing a secret"""
        storage.initialize(master_key)
        storage.add_secret(crypto, "TO_REMOVE", "val")
        
        assert storage.remove_secret("TO_REMOVE") is True
        assert storage.get_secret(crypto, "TO_REMOVE") is None
        
        # Try removing again
        assert storage.remove_secret("TO_REMOVE") is False

    def test_get_all_secrets(self, storage, crypto, master_key):
        """Test retrieving all secrets decrypted"""
        storage.initialize(master_key)
        secrets_map = {"A": "1", "B": "2", "C": "3"}
        
        for k, v in secrets_map.items():
            storage.add_secret(crypto, k, v)
            
        all_secrets = storage.get_all_secrets(crypto)
        assert all_secrets == secrets_map


class TestSecurityTiers:
    """Tests for security tier functionality in storage"""
    
    @pytest.fixture
    def temp_dir(self, tmp_path):
        return str(tmp_path)
    
    @pytest.fixture
    def master_key(self):
        return generate_master_key()
    
    def test_initialize_standard_tier(self, temp_dir, master_key):
        """Test initialization with standard tier"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='standard')
        
        assert storage.is_initialized()
        
        # Check metadata
        data = storage.load_secrets_file()
        assert data['security_tier'] == 'standard'
        assert 'salt' not in data  # Standard tier doesn't need salt
    
    def test_initialize_enhanced_tier(self, temp_dir, master_key):
        """Test initialization with enhanced tier"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='enhanced')
        
        # Check metadata
        data = storage.load_secrets_file()
        assert data['security_tier'] == 'enhanced'
        assert 'salt' in data  # Enhanced tier needs salt
        
        # Verify salt can be loaded
        salt = storage.get_salt()
        assert isinstance(salt, bytes)
        assert len(salt) == 16
    
    def test_initialize_max_tier(self, temp_dir, master_key):
        """Test initialization with max tier"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='max')
        
        data = storage.load_secrets_file()
        assert data['security_tier'] == 'max'
        assert 'salt' in data
    
    def test_initialize_invalid_tier(self, temp_dir, master_key):
        """Test error with invalid tier"""
        storage = SecretsStorage(temp_dir)
        with pytest.raises(ValueError, match="Invalid security tier"):
            storage.initialize(master_key, tier='invalid')
    
    def test_get_security_tier(self, temp_dir, master_key):
        """Test retrieving security tier"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='enhanced')
        
        tier = storage.get_security_tier()
        assert tier == 'enhanced'
    
    def test_get_security_tier_default(self, temp_dir, master_key):
        """Test default tier for backward compatibility"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='standard')
        
        # Manually remove tier from file to simulate old format
        data = storage.load_secrets_file()
        del data['security_tier']
        storage.save_secrets_file(data)
        
        # Should default to 'standard'
        tier = storage.get_security_tier()
        assert tier == 'standard'
    
    def test_get_salt_standard_tier(self, temp_dir, master_key):
        """Test that standard tier returns no salt"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='standard')
        
        salt = storage.get_salt()
        assert salt is None
    
    def test_get_salt_enhanced_tier(self, temp_dir, master_key):
        """Test salt retrieval for enhanced tier"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='enhanced')
        
        salt = storage.get_salt()
        assert salt is not None
        assert isinstance(salt, bytes)
        assert len(salt) == 16
    
    def test_load_encryption_key_standard(self, temp_dir, master_key):
        """Test loading encryption key for standard tier"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='standard')
        
        encryption_key = storage.load_encryption_key()
        assert encryption_key == master_key  # Should be same for standard
    
    def test_load_encryption_key_enhanced(self, temp_dir, master_key):
        """Test loading encryption key for enhanced tier"""
        storage = SecretsStorage(temp_dir)
        storage.initialize(master_key, tier='enhanced')
        
        encryption_key = storage.load_encryption_key()
        assert len(encryption_key) == 32
        assert encryption_key != master_key  # Should be derived
        
        # Test deterministic - loading again should give same key
        encryption_key2 = storage.load_encryption_key()
        assert encryption_key == encryption_key2
    
    def test_add_get_secret_with_tiers(self, temp_dir, master_key):
        """Test adding and retrieving secrets with different tiers"""
        for tier in ['standard', 'enhanced', 'max']:
            # Use separate directory for each tier
            tier_dir = os.path.join(temp_dir, tier)
            os.makedirs(tier_dir, exist_ok=True)
            
            storage = SecretsStorage(tier_dir)
            storage.initialize(master_key, tier=tier)
            
            encryption_key = storage.load_encryption_key()
            crypto = ZeroEnvCrypto(encryption_key)
            
            # Add secret
            secret_name = f"SECRET_{tier.upper()}"
            secret_value = f"value_for_{tier}"
            storage.add_secret(crypto, secret_name, secret_value)
            
            # Retrieve secret
            retrieved = storage.get_secret(crypto, secret_name)
            assert retrieved == secret_value
    
    def test_backward_compatibility_no_tier(self, temp_dir, master_key):
        """Test backward compatibility with old .secrets files without tier"""
        storage = SecretsStorage(temp_dir)
        
        # Create old-style .secrets file without tier
        storage.key_path.write_text(ZeroEnvCrypto.key_to_string(master_key))
        old_data = {
            "version": "1.0",
            "created_at": "2023-01-01T00:00:00",
            "secrets": {}
        }
        storage.save_secrets_file(old_data)
        
        # Should work with default 'standard' tier
        assert storage.get_security_tier() == 'standard'
        
        encryption_key = storage.load_encryption_key()
        crypto = ZeroEnvCrypto(encryption_key)
        
        # Should be able to add and retrieve secrets
        storage.add_secret(crypto, "OLD_SECRET", "old_value")
        retrieved = storage.get_secret(crypto, "OLD_SECRET")
        assert retrieved == "old_value"
