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


def print_secrets_table(secrets: dict, show_values: bool = False) -> None:
    """
    Print secrets in a nice table format
    
    Args:
        secrets: Dictionary of secret names to values
        show_values: Whether to show actual values
    """
    if not secrets:
        print_info("No secrets found. Add some with 'zeroenv add'")
        return
    
    table = Table(
        title="Secrets",
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


def print_init_success() -> None:
    """Print success message for initialization"""
    panel = Panel(
        "[bold green]✓ ZeroEnv initialized successfully![/bold green]\n\n"
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
