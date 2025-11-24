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
