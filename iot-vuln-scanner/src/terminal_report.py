"""
terminal_report.py
Everything the scanner prints in the terminal (tables, colors, progress bar), made with rich.
"""

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from src.findings import device_issues, open_ports_text


# highlight=False: otherwise rich colors every number and IP randomly
console = Console(highlight=False)

RISK_STYLE = {"high": "bold red", "medium": "bold yellow", "low": "green"}
STATUS_STYLE = {
    "OK": "green",
    "PASS": "green",
    "WARNING": "yellow",
    "MISSING": "red",
    "MANUAL": "cyan",
    "UNKNOWN": "dim",
    "INFO": "dim",
}
MAX_ISSUES_SHOWN = 6


# ---------- small helpers ----------

def ok(message: str) -> None:
    console.print(f"[green][+][/] {message}")


def warn(message: str) -> None:
    console.print(f"[yellow][!][/] {message}")


def error(message: str) -> None:
    console.print(f"[bold red][-][/] {message}")


def info(message: str) -> None:
    console.print(f"[cyan][*][/] {message}")


def risk_text(risk: str) -> Text:
    risk = (risk or "low").lower()
    return Text(risk.upper(), style=RISK_STYLE.get(risk, ""))


def status_text(status: str) -> Text:
    return Text(status.upper(), style=STATUS_STYLE.get(status.upper(), ""))


def score_style(score: int) -> str:
    return "bold green" if score >= 75 else "bold yellow" if score >= 50 else "bold red"


# ---------- header / progress ----------

def print_banner(version: str) -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]IoT Vulnerability Scanner[/] [dim]v{version}[/]\n"
            "Finds the devices on your network and checks how exposed they are.\n"
            "[dim]Only scan networks you own or have permission to test.[/]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def print_scan_header(network: str, mode: str, nvd: bool, workers: int, admin: bool) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Network", escape(network))
    table.add_row("Mode", f"{mode} ({'more ports + deep checks' if mode == 'full' else 'IoT ports, fast'})")
    table.add_row("CVE lookup", "NVD + CISA KEV" if nvd else "off (use --nvd)")
    table.add_row("Workers", str(workers))
    table.add_row("Admin", "[green]yes[/]" if admin else "[yellow]no (results may be incomplete)[/]")
    console.print(table)
    console.print()


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def device_done_line(device: dict) -> str:
    identity = device.get("identity", {})
    risk = device.get("risk", "low")
    errors = " [dim](scan problem)[/]" if device.get("scan_errors") else ""
    return (
        f"  [{RISK_STYLE.get(risk, '')}]{risk.upper():<6}[/] {device.get('ip', ''):<15} "
        f"{escape(identity.get('type', 'Unknown device'))}{errors}"
    )


# ---------- results ----------

def print_summary(scan: dict) -> None:
    """Prints the score and the table with every device."""
    info_data = scan.get("scan", {})
    devices = scan.get("devices", [])
    counts = info_data.get("risk_counts", {})
    score = info_data.get("network_score", 100)

    headline = Text.assemble(
        ("Network score: ", "bold"),
        (f"{score}/100", score_style(score)),
        "    ",
        ("HIGH ", "bold red"), str(counts.get("high", 0)),
        "   ",
        ("MEDIUM ", "bold yellow"), str(counts.get("medium", 0)),
        "   ",
        ("LOW ", "green"), str(counts.get("low", 0)),
        "   ",
        ("Devices ", "bold"), str(len(devices)),
    )
    console.print()
    console.print(Panel(headline, title="Scan summary", border_style="cyan", box=box.ROUNDED))

    if not devices:
        warn("No devices found.")
        return

    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", expand=False)
    table.add_column("IP", no_wrap=True)
    table.add_column("Hostname", max_width=22, overflow="ellipsis", no_wrap=True)
    table.add_column("Type", max_width=31)
    table.add_column("Vendor", max_width=24, overflow="ellipsis", no_wrap=True)
    table.add_column("Open ports", max_width=24)
    table.add_column("Risk", justify="center")
    for device in devices:
        identity = device.get("identity", {})
        hostname = device.get("hostname", "")
        # Text(...) instead of plain strings: a device name with [brackets] would
        # otherwise be read as rich markup and break the table
        table.add_row(
            device.get("ip", ""),
            Text("-" if hostname.startswith("Unknown") else hostname, style="dim" if hostname.startswith("Unknown") else ""),
            Text(identity.get("type", "Unknown device")),
            Text(identity.get("vendor", device.get("vendor", "Unknown"))),
            Text(open_ports_text(device, with_service=False)),
            risk_text(device.get("risk", "low")),
        )
    console.print(table)


def print_device(device: dict, show_all: bool = False) -> None:
    """Prints one device with its issues and fixes."""
    identity = device.get("identity", {})
    risk = device.get("risk", "low")
    issues = device_issues(device)

    body = Table.grid(padding=(0, 2))
    body.add_column(style="dim", no_wrap=True)
    body.add_column()
    body.add_row("Vendor", Text(f"{identity.get('vendor', 'Unknown')} / {identity.get('model', 'Unknown model')}"))
    body.add_row("MAC", Text(str(device.get("mac", "unknown"))))
    hostname = str(device.get("hostname", "Unknown hostname"))
    if not hostname.startswith("Unknown"):
        body.add_row("Hostname", Text(hostname))
    body.add_row("Open ports", Text(open_ports_text(device)))
    if device.get("ssdp", {}).get("server"):
        body.add_row("UPnP", Text(device["ssdp"]["server"]))

    issue_table = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    issue_table.add_column(no_wrap=True)
    issue_table.add_column()
    shown = issues if show_all else issues[:MAX_ISSUES_SHOWN]
    for issue in shown:
        title = Text(issue["title"], style="bold")
        title.append(f"\n{issue['detail']}", style="")
        title.append(f"\nFix: {issue['fix']}", style="green")
        issue_table.add_row(risk_text(issue["severity"]), title)
    for scan_error in device.get("scan_errors", []):
        issue_table.add_row(Text("ERROR", style="dim"), Text(scan_error, style="dim"))

    content = Table.grid()
    content.add_row(body)
    if shown or device.get("scan_errors"):
        content.add_row("")
        content.add_row(issue_table)
    else:
        content.add_row(Text("\nNo issues found by these checks.", style="green"))
    if len(issues) > len(shown):
        content.add_row(Text(f"... and {len(issues) - len(shown)} more in the report", style="dim"))

    title = Text.assemble(
        (device.get("ip", ""), "bold"), "  ", identity.get("type", "Unknown device"), "  ", risk_text(risk)
    )
    console.print(Panel(content, title=title, title_align="left", border_style=RISK_STYLE.get(risk, "white").split()[-1]))


def print_attention(scan: dict) -> None:
    """Prints the details of the devices with medium/high risk (or scan errors)."""
    devices = [
        device
        for device in scan.get("devices", [])
        if device.get("risk") in ("high", "medium") or device.get("scan_errors")
    ]
    if not devices:
        ok("No device needs attention. Nice!")
        return
    console.print()
    console.rule("[bold]Devices that need attention[/]", style="dim")
    order = {"high": 0, "medium": 1, "low": 2}
    for device in sorted(devices, key=lambda item: order.get(item.get("risk", "low"), 3)):
        print_device(device)


def _checks_table(checks: list[dict], title: str) -> Table:
    table = Table(title=title, title_justify="left", title_style="bold", box=box.SIMPLE, header_style="bold")
    table.add_column("Check", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Details")
    for check in checks:
        table.add_row(check["name"], status_text(check["status"]), Text(check["details"]))
    return table


def print_network_checks(checks: list[dict]) -> None:
    if checks:
        console.print(_checks_table(checks, "Network checks"))


def print_diagnostics(checks: list[dict]) -> None:
    console.print(_checks_table(checks, "Setup check"))
    problems = [check for check in checks if check["status"] in ("MISSING", "WARNING")]
    if any(check["status"] == "MISSING" for check in problems):
        error("Something is missing, fix it before scanning (see README > Setup).")
    elif problems:
        warn("The scanner can run, but some results may be incomplete.")
    else:
        ok("Everything looks ready to scan.")


def print_outputs(paths: list[str]) -> None:
    console.print()
    for path in paths:
        ok(f"Saved [bold]{escape(path)}[/]")


def print_network_map(scan: dict) -> None:
    """Shows the devices grouped by type, like a small network map."""
    info_data = scan.get("scan", {})
    tree = Tree(f"[bold]{escape(str(info_data.get('network', 'network')))}[/]", guide_style="dim")
    groups: dict[str, list[dict]] = {}
    for device in scan.get("devices", []):
        groups.setdefault(device.get("identity", {}).get("type", "Unknown network device"), []).append(device)
    for device_type in sorted(groups):
        branch = tree.add(f"[bold]{escape(device_type)}[/] [dim]({len(groups[device_type])})[/]")
        for device in groups[device_type]:
            label = Text.assemble(
                (f"{device.get('ip', ''):<15} ", ""),
                risk_text(device.get("risk", "low")),
                (f"  {device.get('identity', {}).get('vendor', '')}", "dim"),
            )
            branch.add(label)
    console.print()
    console.print(Panel(tree, title="Network map", title_align="left", border_style="cyan"))


def print_comparison(diff: dict) -> None:
    title = f"Changes since {str(diff.get('old_date', 'last scan')).replace('T', ' ')}"
    table = Table(title=title, title_justify="left", title_style="bold", box=box.SIMPLE, header_style="bold")
    table.add_column("Change")
    table.add_column("Device")
    table.add_column("Details")

    for device in diff["new_devices"]:
        table.add_row("[cyan]NEW[/]", device.get("ip", ""), Text(device.get("identity", {}).get("type", "")))
    for device in diff["missing_devices"]:
        table.add_row("[dim]GONE[/]", device.get("ip", ""), Text(device.get("identity", {}).get("type", "")))
    for change in diff["changed_devices"]:
        details = []
        if change["opened_ports"]:
            details.append(f"opened {', '.join(map(str, change['opened_ports']))}")
        if change["closed_ports"]:
            details.append(f"closed {', '.join(map(str, change['closed_ports']))}")
        if change["old_risk"] != change["new_risk"]:
            details.append(f"risk {change['old_risk'].upper()} -> {change['new_risk'].upper()}")
        if change["old_ip"] != change["ip"]:
            details.append(f"IP was {change['old_ip']}")
        table.add_row("[yellow]CHANGED[/]", change["ip"], "; ".join(details))

    if table.row_count:
        console.print(table)
    else:
        ok("Nothing changed since the previous scan.")
    if diff.get("old_score") is not None and diff.get("new_score") is not None:
        info(f"Network score: {diff['old_score']} -> {diff['new_score']}")


# ---------- interactive menu ----------

MENU = [
    ("1", "Scan the network"),
    ("2", "Check setup (Nmap, Npcap, admin rights)"),
    ("3", "Show the last scan"),
    ("4", "Compare the last two scans"),
    ("5", "Exit"),
]


def ask_menu_choice() -> str:
    console.print()
    for key, label in MENU:
        console.print(f"  [bold cyan]{key}[/]  {label}")
    return Prompt.ask("\nChoose", choices=[key for key, _ in MENU], default="1", console=console)


def ask_scan_settings(default_network: str) -> dict:
    network = Prompt.ask("Network to scan", default=default_network, console=console)
    mode = Prompt.ask("Mode", choices=["quick", "full"], default="quick", console=console)
    nvd = Confirm.ask("Look up known CVEs online (NVD, slower)?", default=False, console=console)
    return {"network": network.strip(), "mode": mode, "nvd": nvd}


def confirm_authorized(network: str) -> bool:
    return Confirm.ask(
        f"Do you own [bold]{escape(network)}[/] or have permission to scan it?",
        default=False,
        console=console,
    )
