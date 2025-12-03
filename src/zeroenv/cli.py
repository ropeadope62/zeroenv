"""
Project: ZeroEnv - Git-Safe Secrets
Module: Main module and Command-Line Interface (cli.py)
Author: Dave C. (ropeadope62)
https://github.com/ropeadope62
"""

import os
import sys
import subprocess
import click
from pathlib import Path

from . import __version__
from .crypto import ZeroEnvCrypto, generate_master_key
from .storage import SecretsStorage
from . import ui


def update_gitignore(directory):
    """
    Add .secrets.key to .gitignore to prevent accidental commits.
    
    Args:
        directory: The directory containing the .gitignore file
    """
    gitignore_path = Path(directory) / '.gitignore'
    gitignore_entry = '.secrets.key'
    gitignore_comment = '# ZeroEnv - Master Key (DO NOT COMMIT)'
    
    try:
        if gitignore_path.exists():
            # Read existing .gitignore content
            gitignore_content = gitignore_path.read_text(encoding='utf-8')
            
            # Check if entry already exists to avoid duplicates
            if gitignore_entry not in gitignore_content:
                # Append to existing .gitignore
                with open(gitignore_path, 'a', encoding='utf-8') as f:
                    # Add blank line if file doesn't end with newline
                    if gitignore_content and not gitignore_content.endswith('\n'):
                        f.write('\n')
                    f.write(f'\n{gitignore_comment}\n{gitignore_entry}\n')
                ui.print_success(f"Added '{gitignore_entry}' to .gitignore")
            else:
                ui.print_info(f"'{gitignore_entry}' already in .gitignore")
        else:
            # Create new .gitignore file
            gitignore_path.write_text(
                f'{gitignore_comment}\n{gitignore_entry}\n',
                encoding='utf-8'
            )
            ui.print_success(f"Created .gitignore with '{gitignore_entry}'")
    except (IOError, OSError) as e:
        ui.print_error(f"Failed to update .gitignore: {e}")
        ui.print_info("Please manually add .secrets.key to .gitignore")


@click.group()
@click.version_option(version=__version__, prog_name="zeroenv")
def main():
    """
    ZeroEnv - Git-Safe Secrets
    """
    pass


@main.command()
@click.option('--directory', '-d', default='.', help='Directory to initialize')
@click.option(
    '--tier',
    type=click.Choice(['standard', 'enhanced', 'max'], case_sensitive=False),
    default='standard',
    help='Security tier: standard (fast), enhanced (100k iterations), max (500k iterations)'
)
def init(directory, tier):
    """
    Initialize ZeroEnv in the current directory
    
    Creates .secrets (encrypted storage) and .secrets.key (master key).
    
    Security Tiers:
      standard - Direct key usage, fastest (development)
      enhanced - PBKDF2 100k iterations (balanced)
      max      - PBKDF2 500k iterations (production)
    """
    storage = SecretsStorage(directory)
    
    if storage.is_initialized():
        ui.print_error("ZeroEnv is already initialized in this directory")
        ui.print_info(f"Found: {storage.secrets_path}")
        ui.print_info(f"Found: {storage.key_path}")
        sys.exit(1)

    # Generate master key and initialize the secrets storage with tier
    master_key = generate_master_key()
    storage.initialize(master_key, tier=tier.lower())
    
    # Update .gitignore to exclude master key from version control
    update_gitignore(directory)
    
    # Show success message with tier info
    ui.print_init_success(tier.lower())


@main.command()
@click.argument('name', required=False)
@click.argument('value', required=False)
@click.option('--directory', '-d', default='.', help='Directory with ZeroEnv')
def add(name, value, directory):
    """
    Add or update a secret
    
    Usage:
      zeroenv add                    # Interactive mode
      zeroenv add NAME VALUE         # Direct mode
      zeroenv add NAME               # Prompt for value only
    """
    storage = SecretsStorage(directory)
    
    # Check if ZeroEnv is initialized
    if not storage.is_initialized():
        ui.print_error("ZeroEnv not initialized. Run 'zeroenv init'.")
        sys.exit(1)
    
    # Load encryption key (derived from master key based on tier)
    encryption_key = storage.load_encryption_key()
    crypto = ZeroEnvCrypto(encryption_key)
    
    # Interactive mode if no name provided
    if not name:
        name = ui.prompt_value("Secret name", hide_input=False)
    
    # Prompt for value (secret name) if not provided
    if not value:
        value = ui.prompt_value(f"Value for {name}")
    
    # Add the secret
    storage.add_secret(crypto, name, value)
    ui.print_success(f"Added secret: {name}")


@main.command()
@click.argument('name')
@click.option('--directory', '-d', default='.', help='Directory with ZeroEnv')
@click.option('--show/--no-show', default=True, help='Show the secret value')
def get(name, directory, show):
    """
    Get the value of a secret
    
    Usage:
      zeroenv get SECRET_NAME
    """
    storage = SecretsStorage(directory)
    
    # Check if initialized
    if not storage.is_initialized():
        ui.print_error("ZeroEnv not initialized. Run 'zeroenv init' first.")
        sys.exit(1)
    
    # Load encryption key (derived from master key based on tier)
    encryption_key = storage.load_encryption_key()
    crypto = ZeroEnvCrypto(encryption_key)
    
    # Get secret
    value = storage.get_secret(crypto, name)
    
    if value is None:
        ui.print_error(f"Secret not found: {name}")
        sys.exit(1)
    
    if show:
        print(value)
    else:
        ui.print_info(f"Secret {name} exists (use --show to display)")


@main.command(name='ls')
@click.option('--directory', '-d', default='.', help='Directory with ZeroEnv')
@click.option('--values', is_flag=True, help='Show secret values')
def list_secrets(directory, values):
    """
    List all secrets
    
    Usage:
      zeroenv ls              # List names only
      zeroenv ls --values     # List with values
    """
    storage = SecretsStorage(directory)
    
    # Check if initialized
    if not storage.is_initialized():
        ui.print_error("ZeroEnv not initialized. Run 'zeroenv init' first.")
        sys.exit(1)
    
    # Prepare secrets dictionary based on --values flag
    secrets = {}
    if values:
        # Load encryption key (derived from master key based on tier)
        encryption_key = storage.load_encryption_key()
        crypto = ZeroEnvCrypto(encryption_key)
        secrets = storage.get_all_secrets(crypto)
    else:
        # List the secret names but mask their value
        secrets = {name: "***" for name in storage.list_secrets()}
    
    # Display secrets table with imported function
    tier = storage.get_security_tier()
    ui.print_secrets_table(secrets, show_values=values, tier=tier)


@main.command()
@click.argument('name')
@click.option('--directory', '-d', default='.', help='Directory with ZeroEnv')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation')
def rm(name, directory, yes):
    """
    Remove a secret
    
    Usage:
      zeroenv rm SECRET_NAME
    """
    storage = SecretsStorage(directory)
    
    # Check if initialized
    if not storage.is_initialized():
        ui.print_error("ZeroEnv not initialized. Run 'zeroenv init' first.")
        sys.exit(1)
    
    # Confirm deletion
    if not yes:
        if not ui.confirm(f"Remove secret '{name}'?"):
            ui.print_info("Cancelled")
            sys.exit(0)
    
    # Remove
    if storage.remove_secret(name):
        ui.print_success(f"Removed secret: {name}")
    else:
        ui.print_error(f"Secret not found: {name}")
        sys.exit(1)


@main.command()
@click.argument('command', nargs=-1, required=True)
@click.option('--directory', '-d', default='.', help='Directory with ZeroEnv')
def run(command, directory):
    """
    Run a command with secrets injected as environment variables
    
    Usage:
      zeroenv run python app.py
      zeroenv run npm start
      zeroenv run -- python -m myapp --flag
    
    Use -- before the command if it has flags that conflict with zeroenv.
    """
    storage = SecretsStorage(directory)
    
    # Check if initialized
    if not storage.is_initialized():
        ui.print_error("ZeroEnv not initialized. Run 'zeroenv init' first.")
        sys.exit(1)
    
    # Load encryption key (derived from master key based on tier)
    encryption_key = storage.load_encryption_key()
    crypto = ZeroEnvCrypto(encryption_key)
    secrets = storage.get_all_secrets(crypto)
    
    # Prepare environment
    env = os.environ.copy()
    env.update(secrets)
    
    # Show info
    ui.print_success(f"Injected {len(secrets)} secret(s)")
    
    # Execute the command with secrets injected into environment
    try:
        # Run subprocess with modified environment variables
        result = subprocess.run(
            command,
            env=env,
            check=False
        )
        # Exit with the same return code as the subprocess
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        # Allow user to close with ctrl C
        ui.print_info("\nInterrupted")
        sys.exit(130)
    except Exception as e:
        # Handle any other errors during command execution
        ui.print_error(f"Failed to run command: {e}")
        sys.exit(1)


@main.command()
@click.option('--directory', '-d', default='.', help='Directory with ZeroEnv')
@click.option('--format', '-f', type=click.Choice(['env', 'json']), default='env', help='Output format')
def export(directory, format):
    """
    Export secrets in various formats
    
    Usage:
      zeroenv export              # .env format
      zeroenv export -f json      # JSON format
      zeroenv export > .env       # Save to file
    """
    storage = SecretsStorage(directory)
    
    # Check if initialized
    if not storage.is_initialized():
        ui.print_error("ZeroEnv not initialized. Run 'zeroenv init' first.")
        sys.exit(1)
    
    # Load encryption key (derived from master key based on tier)
    encryption_key = storage.load_encryption_key()
    crypto = ZeroEnvCrypto(encryption_key)
    secrets = storage.get_all_secrets(crypto)
    
    # Export secrets in the requested format
    if format == 'env':
        # Output in .env file format (KEY=VALUE)
        for name, value in sorted(secrets.items()):
            # Deal with special characters in the secret value
            if ' ' in value or '"' in value or "'" in value:
                value = f'"{value}"'
            print(f"{name}={value}")
    elif format == 'json':
        # Output in JSON format with indentation
        import json
        print(json.dumps(secrets, indent=2))


@main.command()
@click.option('--directory', '-d', default='.', help='Directory with ZeroEnv')
def info(directory):
    """
    Display ZeroEnv configuration and security tier information
    
    Usage:
      zeroenv info
    """
    storage = SecretsStorage(directory)
    
    # Check if initialized
    if not storage.is_initialized():
        ui.print_error("ZeroEnv not initialized. Run 'zeroenv init' first.")
        sys.exit(1)
    
    # Get tier and secrets count
    tier = storage.get_security_tier()
    secrets_count = len(storage.list_secrets())
    
    # Display info panel
    ui.print_info_panel(tier, secrets_count, directory)


if __name__ == '__main__':
    main()
