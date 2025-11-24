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
