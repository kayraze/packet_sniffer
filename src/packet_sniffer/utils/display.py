from rich.console import Console
from rich.table import Table

console = Console()

def print_packet_info(src: str, dst: str, proto: str, length: int) -> None:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Source", style="bold green")
    table.add_column("Destination", style="bold red")
    table.add_column("Protocol", style="bold yellow")
    table.add_column("Length", style="bold magenta")

    table.add_row(src, dst, proto, str(length))
    console.print(table)