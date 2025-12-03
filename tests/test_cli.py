"""
Project: ZeroEnv - Git-Safe Secrets
Module: CLI Tests (test_cli.py)
Author: Dave C. (ropeadope62)
https://github.com/ropeadope62
"""

import pytest
from click.testing import CliRunner
from zeroenv.cli import main
import os
import json

class TestCli:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def temp_dir(self, tmp_path):
        return str(tmp_path)

    def test_init(self, runner, temp_dir):
        """Test 'init' command"""
        result = runner.invoke(main, ['init', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "ZeroEnv initialized successfully" in result.output
        
        # Verify files created
        assert os.path.exists(os.path.join(temp_dir, '.secrets'))
        assert os.path.exists(os.path.join(temp_dir, '.secrets.key'))
        assert os.path.exists(os.path.join(temp_dir, '.gitignore'))

    def test_init_already_initialized(self, runner, temp_dir):
        """Test 'init' when already initialized"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        result = runner.invoke(main, ['init', '--directory', temp_dir])
        
        assert result.exit_code == 1
        assert "ZeroEnv is already initialized" in result.output

    def test_add_secret(self, runner, temp_dir):
        """Test 'add' command"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        
        result = runner.invoke(main, ['add', 'API_KEY', '12345', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "Added secret: API_KEY" in result.output

    def test_get_secret(self, runner, temp_dir):
        """Test 'get' command"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        runner.invoke(main, ['add', 'API_KEY', '12345', '--directory', temp_dir])
        
        result = runner.invoke(main, ['get', 'API_KEY', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "12345" in result.output

    def test_get_secret_hidden(self, runner, temp_dir):
        """Test 'get' command with --no-show"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        runner.invoke(main, ['add', 'API_KEY', '12345', '--directory', temp_dir])
        
        result = runner.invoke(main, ['get', 'API_KEY', '--no-show', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "12345" not in result.output
        assert "Secret API_KEY exists" in result.output

    def test_ls_secrets(self, runner, temp_dir):
        """Test 'ls' command"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        runner.invoke(main, ['add', 'A', '1', '--directory', temp_dir])
        runner.invoke(main, ['add', 'B', '2', '--directory', temp_dir])
        
        result = runner.invoke(main, ['ls', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "A" in result.output
        assert "B" in result.output
        # assert "***" in result.output  # Values are not shown in table when hidden

    def test_ls_secrets_values(self, runner, temp_dir):
        """Test 'ls --values' command"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        runner.invoke(main, ['add', 'A', '1', '--directory', temp_dir])
        
        result = runner.invoke(main, ['ls', '--values', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "1" in result.output

    def test_rm_secret(self, runner, temp_dir):
        """Test 'rm' command"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        runner.invoke(main, ['add', 'TO_DEL', 'val', '--directory', temp_dir])
        
        # Test with --yes to skip confirmation
        result = runner.invoke(main, ['rm', 'TO_DEL', '--yes', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "Removed secret: TO_DEL" in result.output
        
        # Verify it's gone
        result = runner.invoke(main, ['get', 'TO_DEL', '--directory', temp_dir])
        assert result.exit_code == 1

    def test_export_env(self, runner, temp_dir):
        """Test 'export' command (env format)"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        runner.invoke(main, ['add', 'KEY', 'VALUE', '--directory', temp_dir])
        
        result = runner.invoke(main, ['export', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "KEY=VALUE" in result.output

    def test_export_json(self, runner, temp_dir):
        """Test 'export' command (json format)"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        runner.invoke(main, ['add', 'KEY', 'VALUE', '--directory', temp_dir])
        
        result = runner.invoke(main, ['export', '--format', 'json', '--directory', temp_dir])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data['KEY'] == 'VALUE'

    def test_run_command(self, runner, temp_dir):
        """Test 'run' command"""
        runner.invoke(main, ['init', '--directory', temp_dir])
        runner.invoke(main, ['add', 'TEST_VAR', 'hello_world', '--directory', temp_dir])
        
        # We'll run a python command that writes the env var to a file
        # This avoids issues with capturing subprocess stdout via CliRunner
        import sys
        out_file = os.path.join(temp_dir, 'out.txt')
        # Escape backslashes for Windows paths in the python string
        out_file_escaped = out_file.replace('\\', '\\\\')
        
        cmd = [sys.executable, "-c", f"import os; open('{out_file_escaped}', 'w').write(os.environ.get('TEST_VAR'))"]
        
        result = runner.invoke(main, ['run', '--directory', temp_dir, '--'] + cmd)
        
        assert result.exit_code == 0
        
        with open(out_file, 'r') as f:
            content = f.read()
            assert content == "hello_world"


class TestSecurityTiersInCLI:
    """Tests for security tier functionality in CLI"""
    
    @pytest.fixture
    def runner(self):
        return CliRunner()
    
    @pytest.fixture
    def temp_dir(self, tmp_path):
        return str(tmp_path)
    
    def test_init_standard_tier(self, runner, temp_dir):
        """Test init with standard tier (default)"""
        result = runner.invoke(main, ['init', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "Security Tier: Standard" in result.output
        assert "Fast - Direct key" in result.output
        
        # Verify .secrets file
        with open(os.path.join(temp_dir, '.secrets'), 'r') as f:
            data = json.load(f)
            assert data['security_tier'] == 'standard'
            assert 'salt' not in data
    
    def test_init_enhanced_tier(self, runner, temp_dir):
        """Test init with enhanced tier"""
        result = runner.invoke(main, ['init', '--tier', 'enhanced', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "Security Tier: Enhanced" in result.output
        assert "PBKDF2-SHA256 100k" in result.output
        
        # Verify .secrets file
        with open(os.path.join(temp_dir, '.secrets'), 'r') as f:
            data = json.load(f)
            assert data['security_tier'] == 'enhanced'
            assert 'salt' in data
    
    def test_init_max_tier(self, runner, temp_dir):
        """Test init with max tier"""
        result = runner.invoke(main, ['init', '--tier', 'max', '--directory', temp_dir])
        assert result.exit_code == 0
        assert "Security Tier: Max" in result.output
        assert "PBKDF2-SHA256 500k" in result.output
        
        # Verify .secrets file
        with open(os.path.join(temp_dir, '.secrets'), 'r') as f:
            data = json.load(f)
            assert data['security_tier'] == 'max'
            assert 'salt' in data
    
    def test_init_tier_case_insensitive(self, runner, temp_dir):
        """Test that tier option is case-insensitive"""
        result = runner.invoke(main, ['init', '--tier', 'ENHANCED', '--directory', temp_dir])
        assert result.exit_code == 0
        
        with open(os.path.join(temp_dir, '.secrets'), 'r') as f:
            data = json.load(f)
            assert data['security_tier'] == 'enhanced'
    
    def test_add_get_with_enhanced_tier(self, runner, temp_dir):
        """Test add/get operations with enhanced tier"""
        runner.invoke(main, ['init', '--tier', 'enhanced', '--directory', temp_dir])
        
        # Add secret
        result = runner.invoke(main, ['add', 'API_KEY', 'secret123', '--directory', temp_dir])
        assert result.exit_code == 0
        
        # Get secret
        result = runner.invoke(main, ['get', 'API_KEY', '--directory', temp_dir])
        assert result.exit_code == 0
        assert 'secret123' in result.output
    
    def test_ls_shows_tier(self, runner, temp_dir):
        """Test that ls command shows security tier"""
        runner.invoke(main, ['init', '--tier', 'enhanced', '--directory', temp_dir])
        runner.invoke(main, ['add', 'KEY1', 'val1', '--directory', temp_dir])
        
        result = runner.invoke(main, ['ls', '--directory', temp_dir])
        assert result.exit_code == 0
        # Check for tier in output (may have line breaks in Rich formatting)
        assert 'Enhanced' in result.output
        assert 'Securit' in result.output  # May be split as "Securit\ny:"
    
    def test_export_with_max_tier(self, runner, temp_dir):
        """Test export with max tier"""
        runner.invoke(main, ['init', '--tier', 'max', '--directory', temp_dir])
        runner.invoke(main, ['add', 'KEY', 'VALUE', '--directory', temp_dir])
        
        result = runner.invoke(main, ['export', '--directory', temp_dir])
        assert result.exit_code == 0
        assert 'KEY=VALUE' in result.output
    
    def test_run_with_enhanced_tier(self, runner, temp_dir):
        """Test run command with enhanced tier"""
        runner.invoke(main, ['init', '--tier', 'enhanced', '--directory', temp_dir])
        runner.invoke(main, ['add', 'TEST_VAR', 'tier_value', '--directory', temp_dir])
        
        import sys
        out_file = os.path.join(temp_dir, 'out.txt')
        out_file_escaped = out_file.replace('\\', '\\\\')
        
        cmd = [sys.executable, "-c", f"import os; open('{out_file_escaped}', 'w').write(os.environ.get('TEST_VAR', ''))"]
        
        result = runner.invoke(main, ['run', '--directory', temp_dir, '--'] + cmd)
        assert result.exit_code == 0
        
        with open(out_file, 'r') as f:
            content = f.read()
            assert content == 'tier_value'
    
    def test_all_commands_with_different_tiers(self, runner, tmp_path):
        """Test that all commands work correctly with each tier"""
        for tier in ['standard', 'enhanced', 'max']:
            # Use separate directory for each tier
            tier_dir = str(tmp_path / tier)
            os.makedirs(tier_dir, exist_ok=True)
            
            # Init
            result = runner.invoke(main, ['init', '--tier', tier, '--directory', tier_dir])
            assert result.exit_code == 0
            
            # Add
            result = runner.invoke(main, ['add', 'KEY', 'value', '--directory', tier_dir])
            assert result.exit_code == 0
            
            # Get
            result = runner.invoke(main, ['get', 'KEY', '--directory', tier_dir])
            assert result.exit_code == 0
            assert 'value' in result.output
            
            # List
            result = runner.invoke(main, ['ls', '--values', '--directory', tier_dir])
            assert result.exit_code == 0
            assert 'value' in result.output
            
            # Export
            result = runner.invoke(main, ['export', '--directory', tier_dir])
            assert result.exit_code == 0
            assert 'KEY=value' in result.output
            
            # Remove
            result = runner.invoke(main, ['rm', 'KEY', '--yes', '--directory', tier_dir])
            assert result.exit_code == 0
    
    def test_backward_compatibility_legacy_secrets(self, runner, temp_dir):
        """Test that legacy .secrets files without tier still work"""
        # Create old-style .secrets file
        from zeroenv.crypto import generate_master_key, ZeroEnvCrypto
        master_key = generate_master_key()
        
        key_path = os.path.join(temp_dir, '.secrets.key')
        with open(key_path, 'w') as f:
            f.write(ZeroEnvCrypto.key_to_string(master_key))
        
        secrets_path = os.path.join(temp_dir, '.secrets')
        old_data = {
            "version": "1.0",
            "created_at": "2023-01-01T00:00:00",
            "secrets": {}
        }
        with open(secrets_path, 'w') as f:
            json.dump(old_data, f)
        
        # Should be able to add and get secrets
        result = runner.invoke(main, ['add', 'OLD_KEY', 'old_value', '--directory', temp_dir])
        assert result.exit_code == 0
        
        result = runner.invoke(main, ['get', 'OLD_KEY', '--directory', temp_dir])
        assert result.exit_code == 0
        assert 'old_value' in result.output
        
        # ls should show Standard tier as default
        result = runner.invoke(main, ['ls', '--directory', temp_dir])
        assert result.exit_code == 0
        # Check for tier in output (may have line breaks in Rich formatting)
        assert 'Standard' in result.output
        assert 'Securit' in result.output  # May be split as "Securit\ny:"
