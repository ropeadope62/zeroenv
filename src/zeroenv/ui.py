"""
Project: ZeroEnv - Git-Safe Secrets
Module: UI and Formatting (ui.py)
Author: Dave C. (ropeadope62)
https://github.com/ropeadope62
"""

# UI / Formatting elements using Rich

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def print_success(message: str) -> None:
    """Print a success message"""
    console.print(f"{message}", style="bold green")


def print_error(message: str) -> None:
    """Print an error message"""
    console.print(f"{message}", style="bold red")


def print_info(message: str) -> None:
    """Print an info message"""
    console.print(f"{message}", style="bold blue")


def print_warning(message: str) -> None:
    """Print a warning message"""
    console.print(f"{message}", style="bold yellow")


def print_secret(name: str, value: str, show_value: bool = True) -> None:
    """
    Print a secret (with option to hide value)
    
    Args:
        name: Secret name
        value: Secret value
        show_value: Whether to show the actual value
    """
    if show_value:
        console.print(f"[bold cyan]{name}[/bold cyan] = [yellow]{value}[/yellow]")
    else:
        console.print(f"[bold cyan]{name}[/bold cyan]")


def print_secrets_table(secrets: dict, show_values: bool = False, tier: str = None) -> None:
    """
    Print secrets in a nice table format
    
    Args:
        secrets: Dictionary of secret names to values
        show_values: Whether to show actual values
        tier: Security tier to display in title
    """
    if not secrets:
        print_info("No secrets found. Add some with 'zeroenv add'")
        return
    
    # Build title with tier info
    title = "Secrets"
    if tier:
        tier_display = tier.capitalize()
        title = f"Secrets [dim](Security: {tier_display})[/dim]"
    
    table = Table(
        title=title,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    
    table.add_column("Name", style="cyan", no_wrap=True)
    if show_values:
        table.add_column("Value", style="yellow")
    
    for name, value in sorted(secrets.items()):
        if show_values:
            table.add_row(name, value)
        else:
            table.add_row(name)
    
    console.print(table)


def print_init_success(tier: str = 'standard') -> None:
    """
    Print success message for initialization
    
    Args:
        tier: Security tier used for initialization
    """
    from .crypto import ZeroEnvCrypto
    
    tier_info = ZeroEnvCrypto.SECURITY_TIERS.get(tier, {})
    tier_desc = tier_info.get('description', 'Unknown')
    tier_name = tier.capitalize()
    
    panel = Panel(
        f"[bold green]✓ ZeroEnv initialized successfully![/bold green]\n\n"
        f"[bold]Security Tier:[/bold] [cyan]{tier_name}[/cyan]\n"
        f"[dim]{tier_desc}[/dim]\n\n"
        "[bold]Created:[/bold]\n"
        "  • [cyan].secrets[/cyan] - Encrypted storage (AES-256-GCM) "
        "[dim]→ safe to commit[/dim]\n"
        "  • [cyan].secrets.key[/cyan] - Master encryption key "
        "[dim]→ kept local only[/dim]\n\n"
        "[bold yellow]Quick Start:[/bold yellow]\n"
        "  [dim]1.[/dim] Add a secret    "
        "[bold cyan]zeroenv add API_KEY[/bold cyan]\n"
        "  [dim]2.[/dim] List secrets    "
        "[bold cyan]zeroenv ls[/bold cyan]\n"
        "  [dim]3.[/dim] Run with secrets "
        "[bold cyan]zeroenv run python app.py[/bold cyan]\n\n"
        "[dim]Your secrets are encrypted locally "
        "and never leave your machine.[/dim]",
        title="[bold green]Success[/bold green]",
        border_style="green",
        box=box.DOUBLE,
        padding=(1, 2)
    )
    console.print(panel)


def print_help_hint(command: str) -> None:
    """Print a helpful hint about a command"""
    console.print(f"Tip: Run [bold]zeroenv {command} --help[/bold] for more info", style="dim")


def print_header(title: str) -> None:
    """Print a section header"""
    console.rule(f"[bold cyan]{title}[/bold cyan]")


def print_info_panel(tier: str, secrets_count: int, directory: str) -> None:
    """
    Print information panel about current ZeroEnv configuration
    
    Args:
        tier: Security tier
        secrets_count: Number of secrets stored
        directory: Directory path
    """
    from .crypto import ZeroEnvCrypto
    
    tier_info = ZeroEnvCrypto.SECURITY_TIERS.get(tier, {})
    tier_desc = tier_info.get('description', 'Unknown')
    tier_name = tier.capitalize()
    iterations = tier_info.get('iterations', 0)
    
    # Format iterations
    if iterations == 0:
        iter_display = "None (direct key usage)"
    else:
        iter_display = f"{iterations:,} iterations"
    
    panel = Panel(
        f"[bold cyan]Security Tier:[/bold cyan] {tier_name}\n"
        f"[dim]{tier_desc}[/dim]\n\n"
        f"[bold cyan]PBKDF2 Iterations:[/bold cyan] {iter_display}\n"
        f"[bold cyan]Encryption:[/bold cyan] AES-256-GCM\n"
        f"[bold cyan]Secrets Stored:[/bold cyan] {secrets_count}\n\n"
        f"[bold cyan]Location:[/bold cyan]\n"
        f"  • {directory}/.secrets\n"
        f"  • {directory}/.secrets.key",
        title="[bold cyan]ZeroEnv Configuration[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2)
    )
    console.print(panel)


def prompt_value(prompt_text: str, hide_input: bool = True) -> str:
    """
    Prompt user for input
    
    Args:
        prompt_text: Text to show the user
        hide_input: Whether to hide input (for secrets)
        
    Returns:
        User input
    """
    from rich.prompt import Prompt
    
    if hide_input:
        return Prompt.ask(prompt_text, password=True)
    else:
        return Prompt.ask(prompt_text)


def confirm(question: str, default: bool = False) -> bool:
    """
    Ask user for confirmation
    
    Args:
        question: Question to ask
        default: Default answer
        
    Returns:
        True if user confirmed
    """
    from rich.prompt import Confirm
    return Confirm.ask(question, default=default)
