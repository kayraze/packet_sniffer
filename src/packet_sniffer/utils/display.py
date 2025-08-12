from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.markup import escape

console = Console()


def print_packet_info(
    src: str, dst: str, proto: str, length: int, data: str = None
) -> None:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Source", style="bold green")
    table.add_column("Destination", style="bold red")
    table.add_column("Protocol", style="bold yellow")
    table.add_column("Length", style="bold magenta")
    # table.add_column("Data", style="white", overflow="fold")

    # display_data = (data[:50] + "...") if data and len(data) > 50 else (data or "-")
    # data_text = Text(display_data, markup=False)

    if data is not None:
        table.add_column("Data", style="white", overflow="fold")

    # Escape the data to prevent markup interpretation
    safe_data = escape(data) if data else ""

    table.add_row(src, dst, proto, str(length), safe_data)
    console.print(table)
