"""Banner module for RT-MASK."""
from rich.console import Console
from rich.panel import Panel

BANNER = r"""
██████╗ ████████╗      ███╗   ███╗ █████╗ ███████╗██╗  ██╗
██╔══██╗╚══██╔══╝      ████╗ ████║██╔══██╗██╔════╝██║ ██╔╝
██████╔╝   ██║   █████╗██╔████╔██║███████║███████╗█████╔╝ 
██╔══██╗   ██║         ██║╚██╔╝██║██╔══██║╚════██║██╔═██╗ 
██║  ██║   ██║         ██║ ╚═╝ ██║██║  ██║███████║██║  ██╗
╚═╝  ╚═╝   ╚═╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                           
     Red Team - Multi-Architecture Subnet Konfigurator     
"""

VERSION = "2.0.0"
AUTHOR = "msimon96"
GITHUB = "https://github.com/msimon96/RT-MASK"

def print_banner():
    """Print the RT-MASK banner with styling."""
    console = Console()
    
    # Create a styled panel with the banner
    panel = Panel(
        BANNER,
        title=f"[bold cyan]RT-MASK v{VERSION}[/bold cyan]",
        subtitle=f"[blue]by {AUTHOR} - {GITHUB}[/blue]",
        border_style="cyan",
        padding=(1, 2),
    )
    
    # Print the panel
    console.print(panel)

if __name__ == "__main__":
    print_banner()
