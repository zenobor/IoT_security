"""
terminal_report.py
Everything the scanner prints in the terminal (tables, colors, progress bar), made with rich.
"""

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from src.findings import device_issues, open_ports, open_ports_text


# highlight=False: otherwise rich colors every number and IP randomly
console = Console(highlight=False)

ACCENT = "cyan"
RISK_COLOR = {"high": "red", "medium": "yellow", "low": "green"}
RISK_ORDER = {"high": 0, "medium": 1, "low": 2}
STATUS_COLOR = {
    "OK": "green",
    "PASS": "green",
    "WARNING": "yellow",
    "MISSING": "red",
    "MANUAL": "cyan",
    "UNKNOWN": "bright_black",
    "INFO": "bright_black",
}
MAX_ISSUES_SHOWN = 6


def _unicode() -> bool:
    """Old Windows consoles (cp1252) can't print box characters, so we fall back to ASCII."""
    return (console.encoding or "").lower().replace("-", "").startswith("utf")


def _symbols() -> dict[str, str]:
    if _unicode():
        return {"ok": "✔", "warn": "▲", "error": "✖", "info": "•", "dot": "●", "full": "█", "empty": "░", "sep": "·"}
    return {"ok": "+", "warn": "!", "error": "x", "info": "*", "dot": "*", "full": "#", "empty": "-", "sep": "|"}


# Same as box.SIMPLE_HEAD (only a line under the header) but with plain "-"
ASCII_SIMPLE_HEAD = box.Box(
    "    \n"
    "    \n"
    " -- \n"
    "    \n"
    "    \n"
    "    \n"
    "    \n"
    "    \n",
    ascii=True,
)


def _box(unicode_box: box.Box = box.ROUNDED) -> box.Box:
    if _unicode():
        return unicode_box
    return ASCII_SIMPLE_HEAD if unicode_box is box.SIMPLE_HEAD else box.ASCII


# ---------- small helpers ----------

def ok(message: str) -> None:
    console.print(f" [green]{_symbols()['ok']}[/] {message}")


def warn(message: str) -> None:
    console.print(f" [yellow]{_symbols()['warn']}[/] {message}")


def error(message: str) -> None:
    console.print(f" [bold red]{_symbols()['error']}[/] {message}")


def info(message: str) -> None:
    console.print(f" [{ACCENT}]{_symbols()['info']}[/] {message}")


def risk_text(risk: str) -> Text:
    """Colored "● HIGH" label used in tables."""
    risk = (risk or "low").lower()
    return Text(f"{_symbols()['dot']} {risk.upper()}", style=f"bold {RISK_COLOR.get(risk, 'white')}")


def risk_badge(risk: str) -> Text:
    """Label with a colored background, used next to each issue."""
    risk = (risk or "low").lower()
    color = RISK_COLOR.get(risk, "white")
    return Text(f" {risk.upper():^6} ", style=f"bold black on {color}")


def status_text(status: str) -> Text:
    return Text(status.upper(), style=f"bold {STATUS_COLOR.get(status.upper(), 'white')}")


def score_color(score: int) -> str:
    return "green" if score >= 75 else "yellow" if score >= 50 else "red"


def score_label(score: int) -> str:
    return "Good" if score >= 75 else "Needs work" if score >= 50 else "At risk"


def score_bar(score: int, width: int = 24) -> Text:
    symbols = _symbols()
    filled = round(max(0, min(score, 100)) / 100 * width)
    return Text.assemble(
        (symbols["full"] * filled, score_color(score)),
        (symbols["empty"] * (width - filled), "bright_black"),
    )


def _is_unknown(value: str) -> bool:
    return not value or value.lower().startswith("unknown")


def _section(title: str) -> None:
    console.print()
    console.print(Rule(Text(title, style="bold"), style="bright_black", align="left", characters="─" if _unicode() else "-"))


# ---------- header ----------

# Big logo, made with figlet (font "ANSI Shadow"). Needs a Unicode terminal and 85+ columns.
BIG_BANNER = """
██╗ ██████╗ ████████╗  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██║██╔═══██╗╚══██╔══╝  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
██║██║   ██║   ██║     ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
██║██║   ██║   ██║     ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
██║╚██████╔╝   ██║     ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
╚═╝ ╚═════╝    ╚═╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝
                       ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
                       ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
                       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
                       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
                       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
                       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""

# Small logo (font "slant"), only plain ASCII: used on small or old terminals.
SMALL_BANNER = r"""
    ____    ______   _____                      _ __
   /  _/___/_  __/  / ___/___  _______  _______(_) /___  __
   / // __ \/ /     \__ \/ _ \/ ___/ / / / ___/ / __/ / / /
 _/ // /_/ / /     ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ /
/___/\____/_/     /____/\___/\___/\__,_/_/  /_/\__/\__, /
                 _____                            /____/
                / ___/_________ _____  ____  ___  _____
                \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
               ___/ / /__/ /_/ / / / / / / /  __/ /
              /____/\___/\__,_/_/ /_/_/ /_/\___/_/
"""

# Muted colors, so the logo doesn't shout: from slate blue (left) to soft steel blue (right)
GRADIENT_START = (88, 110, 140)
GRADIENT_END = (120, 150, 170)


def _gradient_line(line: str, width: int) -> Text:
    """Colors one line of the logo. The full blocks are a little lighter than the "shadow" lines (3D effect)."""
    text = Text()
    for column, char in enumerate(line):
        ratio = column / max(width - 1, 1)
        red, green, blue = (round(start + (end - start) * ratio) for start, end in zip(GRADIENT_START, GRADIENT_END))
        if char == " ":
            text.append(char)
        elif char == "█":  # the full block
            text.append(char, style=f"#{red:02x}{green:02x}{blue:02x}")
        else:
            text.append(char, style=f"#{red // 2:02x}{green // 2:02x}{blue // 2:02x}")
    return text


def print_banner(version: str) -> None:
    """Big gradient logo, used by the menu and by "scan"."""
    big_lines = BIG_BANNER.strip("\n").splitlines()
    small_lines = SMALL_BANNER.strip("\n").splitlines()
    big_width = max(len(line) for line in big_lines)
    small_width = max(len(line) for line in small_lines)

    console.print()
    if console.width > big_width and _unicode():
        lines, width = big_lines, big_width
    elif console.width > small_width:
        lines, width = small_lines, small_width
    else:
        lines, width = [], 0
    for line in lines:
        console.print(_gradient_line(line, width))
    if not lines:
        console.print(f"[bold {ACCENT}]IoT Security Scanner[/]")

    sep = _symbols()["sep"]
    console.print(
        f"\n [bold]v{escape(version)}[/] [bright_black]{sep}[/] ARP + SSDP + Nmap + NVD "
        f"[bright_black]{sep}[/] [bright_black]a university project by zeno[/]"
    )
    console.print(" [yellow]Only scan networks you own or have permission to test.[/]")


def print_header(version: str, command: str) -> None:
    """One-line header for the other commands (show, compare, doctor)."""
    sep = _symbols()["sep"]
    console.print()
    console.print(
        f" [bold {ACCENT}]IoT Security Scanner[/] [bright_black]v{escape(version)} {sep}[/] {escape(command)}"
    )


def print_scan_header(
    network: str, mode: str, nvd: bool, workers: int, admin: bool, custom_ports: bool = False, title: str = "New scan"
) -> None:
    table = Table.grid(padding=(0, 3))
    table.add_column(style="bright_black", no_wrap=True)
    table.add_column()
    if custom_ports:
        mode_text = f"{mode} [bright_black](custom ports)[/]"
    elif mode == "full":
        mode_text = "full [bright_black](more ports + deep checks)[/]"
    else:
        mode_text = "quick [bright_black](IoT ports)[/]"
    table.add_row("Network", f"[bold]{escape(network)}[/]")
    table.add_row("Mode", mode_text)
    table.add_row("CVE lookup", "NVD + CISA KEV" if nvd else "[bright_black]off (add --nvd)[/]")
    table.add_row("Workers", str(workers))
    table.add_row("Admin", "[green]yes[/]" if admin else "[yellow]no[/] [bright_black](results may be incomplete)[/]")
    console.print()
    console.print(
        Panel(table, title=f"[bold]{escape(title)}[/]", title_align="left", border_style=ACCENT, box=_box(), padding=(0, 2), expand=False)
    )


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(style=ACCENT),
        TextColumn("{task.description}"),
        BarColumn(bar_width=28, complete_style=ACCENT, finished_style="green"),
        MofNCompleteColumn(),
        TextColumn("[bright_black]{task.fields[current]}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def device_done_line(device: dict) -> Text:
    """Printed above the progress bar every time a device is done."""
    identity = device.get("identity", {})
    risk = device.get("risk", "low")
    ports = len(open_ports(device))
    line = Text("   ")
    line.append_text(risk_text(risk))
    line.append(" " * (8 - len(risk)))
    line.append(f"{device.get('ip', ''):<16}", style="bold")
    line.append(identity.get("type", "Unknown device"))
    line.append(f"  {_symbols()['sep']} {ports} open port{'s' if ports != 1 else ''}", style="bright_black")
    if device.get("scan_errors"):
        line.append("  (scan problem)", style="yellow")
    return line


# ---------- results ----------

def print_summary(scan: dict) -> None:
    """Prints the score panel and the table with every device."""
    info_data = scan.get("scan", {})
    devices = scan.get("devices", [])
    counts = info_data.get("risk_counts", {})
    score = info_data.get("network_score", 100)
    sep = _symbols()["sep"]

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bright_black", no_wrap=True)
    grid.add_column()
    grid.add_row(
        "Network score",
        Text.assemble(score_bar(score), "  ", (f"{score}/100", f"bold {score_color(score)}"), "  ", (score_label(score), score_color(score))),
    )
    risks = Text()
    for level in ("high", "medium", "low"):
        risks.append_text(risk_text(level))
        risks.append(f" {counts.get(level, 0)}    ")
    grid.add_row("Devices", Text.assemble((str(len(devices)), "bold"), "      ", risks))
    details = [str(info_data.get("network", "")), f"{info_data.get('mode', 'quick')} mode"]
    if info_data.get("nvd"):
        details.append("NVD")
    if info_data.get("started_at"):
        details.append(str(info_data["started_at"]).replace("T", " ")[:16])
    if info_data.get("duration_seconds") is not None:
        details.append(f"{info_data['duration_seconds']} s")
    grid.add_row("Scan", Text(f" {sep} ".join(item for item in details if item)))

    console.print()
    console.print(Panel(grid, title="[bold]Scan summary[/]", title_align="left", border_style=ACCENT, box=_box(), padding=(1, 2)))

    if not devices:
        warn("No devices found.")
        return

    console.print(Padding(_devices_table(devices), (0, 1)))


def _devices_table(devices: list[dict]) -> Table:
    # rich squeezes columns badly when they don't fit, so on small terminals
    # we hide the least useful columns instead (hostname first, then vendor)
    show_hostname = console.width >= 118
    show_vendor = console.width >= 96

    table = Table(box=_box(box.SIMPLE_HEAD), header_style="bold bright_black", pad_edge=False, padding=(0, 1))
    table.add_column("IP", no_wrap=True, style="bold")
    if show_hostname:
        table.add_column("Hostname", max_width=16, overflow="ellipsis", no_wrap=True)
    table.add_column("Type", max_width=28, overflow="ellipsis", no_wrap=True)
    if show_vendor:
        table.add_column("Vendor", max_width=20, overflow="ellipsis", no_wrap=True)
    table.add_column("Open ports", max_width=18)
    table.add_column("Risk", no_wrap=True)

    for device in devices:
        identity = device.get("identity", {})
        hostname = str(device.get("hostname", ""))
        vendor = str(identity.get("vendor", device.get("vendor", "Unknown")))
        ports = open_ports_text(device, with_service=False)
        # Text(...) instead of plain strings: a device name with [brackets] would
        # otherwise be read as rich markup and break the table
        row = [device.get("ip", "")]
        if show_hostname:
            row.append(Text("-", style="bright_black") if _is_unknown(hostname) else Text(hostname))
        row.append(Text(identity.get("type", "Unknown device")))
        if show_vendor:
            row.append(Text(vendor, style="bright_black" if _is_unknown(vendor) or vendor.startswith("Private") else ""))
        row += [Text(ports, style="bright_black" if ports == "none" else ""), risk_text(device.get("risk", "low"))]
        table.add_row(*row)
    return table


def _device_panel(device: dict, show_all: bool = False) -> Panel:
    identity = device.get("identity", {})
    risk = device.get("risk", "low")
    issues = device_issues(device)
    upnp = str(device.get("ssdp", {}).get("server", ""))

    facts = Table.grid(padding=(0, 3))
    facts.add_column(style="bright_black", no_wrap=True)
    facts.add_column()
    facts.add_row("Vendor", Text(str(identity.get("vendor", "Unknown"))))
    model = str(identity.get("model", ""))
    if not _is_unknown(model) and model != upnp:
        # the "model" is the first product Nmap/UPnP recognised (e.g. "OpenSSH"), not always the real model
        facts.add_row("Software", Text(model))
    facts.add_row("MAC", Text(str(device.get("mac", "unknown"))))
    hostname = str(device.get("hostname", ""))
    if not _is_unknown(hostname):
        facts.add_row("Hostname", Text(hostname))
    facts.add_row("Open ports", Text(open_ports_text(device)))
    if upnp:
        facts.add_row("UPnP", Text(upnp))

    parts = [facts]
    shown = issues if show_all else issues[:MAX_ISSUES_SHOWN]
    if shown or device.get("scan_errors"):
        issue_table = Table.grid(padding=(0, 2))
        issue_table.add_column(no_wrap=True)
        issue_table.add_column()
        for number, issue in enumerate(shown):
            if number:
                issue_table.add_row("", "")
            body = Text(issue["title"], style="bold")
            if issue["detail"]:
                body.append(f"\n{issue['detail']}", style="")
            if issue["fix"]:
                body.append(f"\nFix: {issue['fix']}", style="green")
            issue_table.add_row(risk_badge(issue["severity"]), body)
        for scan_error in device.get("scan_errors", []):
            issue_table.add_row(Text(" ERROR  ", style="bold black on bright_black"), Text(scan_error, style="bright_black"))
        parts += [Text(""), issue_table]
        if len(issues) > len(shown):
            parts.append(Text(f"+ {len(issues) - len(shown)} more in the report (or: show --ip {device.get('ip', '')})", style="bright_black"))
    else:
        parts += [Text(""), Text("No issues found by these checks.", style="green")]

    title = Text.assemble((device.get("ip", ""), "bold"), "  ", identity.get("type", "Unknown device"), "  ", risk_text(risk))
    return Panel(
        Group(*parts), title=title, title_align="left", border_style=RISK_COLOR.get(risk, "white"), box=_box(), padding=(1, 2)
    )


def print_device(device: dict, show_all: bool = False) -> None:
    """Prints one device with its issues and fixes."""
    console.print()
    console.print(_device_panel(device, show_all))


def print_attention(scan: dict) -> None:
    """Prints the details of the devices with medium/high risk (or scan errors)."""
    devices = [
        device
        for device in scan.get("devices", [])
        if device.get("risk") in ("high", "medium") or device.get("scan_errors")
    ]
    if not devices:
        console.print()
        ok("No device needs attention. Nice!")
        return
    _section(f"Devices that need attention ({len(devices)})")
    for device in sorted(devices, key=lambda item: RISK_ORDER.get(item.get("risk", "low"), 3)):
        print_device(device)


def _checks_table(checks: list[dict]) -> Table:
    table = Table(box=_box(box.SIMPLE_HEAD), header_style="bold bright_black", pad_edge=False, padding=(0, 1))
    table.add_column("Check", no_wrap=True, style="bold")
    table.add_column("Status", no_wrap=True)
    table.add_column("Details")
    for check in checks:
        table.add_row(Text(check["name"]), status_text(check["status"]), Text(check["details"]))
    return table


def print_network_checks(checks: list[dict]) -> None:
    if checks:
        _section("Network checks")
        console.print(Padding(_checks_table(checks), (0, 1)))


def print_diagnostics(checks: list[dict]) -> None:
    _section("Setup check")
    console.print(Padding(_checks_table(checks), (0, 1)))
    if any(check["status"] == "MISSING" for check in checks):
        error("Something is missing, fix it before scanning (see README > Setup).")
    elif any(check["status"] == "WARNING" for check in checks):
        warn("The scanner can run, but some results may be incomplete.")
    else:
        ok("Everything looks ready to scan.")


def print_outputs(paths: list[str], duration: int | None = None) -> None:
    _section("Reports")
    for path in paths:
        ok(f"Saved [bold]{escape(path)}[/]")
    if duration is not None:
        info(f"Scan took {duration} s")
    console.print()
    console.print(" [bright_black]Next steps[/]")
    console.print("   python main.py show --ip <IP>   [bright_black]every issue of one device[/]")
    console.print("   python main.py show --map       [bright_black]devices grouped by type[/]")
    console.print("   python main.py compare          [bright_black]what changed since the previous scan[/]")


def print_network_map(scan: dict) -> None:
    """Shows the devices grouped by type, like a small network map."""
    info_data = scan.get("scan", {})
    tree = Tree(
        Text(str(info_data.get("network", "network")), style=f"bold {ACCENT}"),
        guide_style="bright_black",
    )
    groups: dict[str, list[dict]] = {}
    for device in scan.get("devices", []):
        groups.setdefault(device.get("identity", {}).get("type", "Unknown network device"), []).append(device)
    for device_type in sorted(groups):
        branch = tree.add(Text.assemble((device_type, "bold"), (f"  ({len(groups[device_type])})", "bright_black")))
        for device in groups[device_type]:
            risk = device.get("risk", "low")
            label = Text.assemble(
                (f"{device.get('ip', ''):<16}", ""),
                risk_text(risk),
                " " * (8 - len(risk)),
                (str(device.get("identity", {}).get("vendor", "")), "bright_black"),
            )
            branch.add(label)
    console.print()
    console.print(Panel(tree, title="[bold]Network map[/]", title_align="left", border_style=ACCENT, box=_box(), padding=(1, 2)))


def print_comparison(diff: dict) -> None:
    _section(f"Changes since {str(diff.get('old_date', 'last scan')).replace('T', ' ')}")
    table = Table(box=_box(box.SIMPLE_HEAD), header_style="bold bright_black", pad_edge=False, padding=(0, 1))
    table.add_column("Change", no_wrap=True)
    table.add_column("Device", no_wrap=True, style="bold")
    table.add_column("Details")

    for device in diff["new_devices"]:
        table.add_row(Text("NEW", style="bold cyan"), device.get("ip", ""), Text(device.get("identity", {}).get("type", "")))
    for device in diff["missing_devices"]:
        table.add_row(Text("GONE", style="bright_black"), device.get("ip", ""), Text(device.get("identity", {}).get("type", "")))
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
        table.add_row(Text("CHANGED", style="bold yellow"), change["ip"], Text("; ".join(details)))

    if table.row_count:
        console.print(Padding(table, (0, 1)))
    else:
        ok("Nothing changed since the previous scan.")
    old_score, new_score = diff.get("old_score"), diff.get("new_score")
    if old_score is not None and new_score is not None:
        trend = "green" if new_score > old_score else "red" if new_score < old_score else "bright_black"
        info(f"Network score: {old_score} -> [bold {trend}]{new_score}[/]")


# ---------- interactive menu ----------

MENU = [
    ("1", "Scan the network", "find devices and check them"),
    ("2", "Check setup", "Nmap, Npcap, admin rights"),
    ("3", "Show the last scan", "summary, issues and network map"),
    ("4", "Compare scans", "what changed since the previous scan"),
    ("5", "Demo", "example with made-up devices, good for screenshots"),
    ("q", "Quit", ""),
]


def print_readiness(nmap_found: bool, admin: bool, network: str) -> None:
    """One short status line under the logo, so problems are visible before the first scan."""
    if not nmap_found:
        error("Nmap is not installed: get it from nmap.org, then reopen the terminal.")
    elif not admin:
        warn("Not running as administrator: some devices may be missed. Use start.bat (Windows) or sudo.")
    else:
        ok(f"Ready to scan [bold]{escape(network)}[/]")


def wait_for_enter() -> None:
    console.print()
    Prompt.ask(" [bright_black]Press Enter to go back to the menu[/]", default="", show_default=False, console=console)


def ask_menu_choice() -> str:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=f"bold {ACCENT}", no_wrap=True)
    table.add_column(style="bold", no_wrap=True)
    table.add_column(style="bright_black")
    for key, label, hint in MENU:
        table.add_row(Text(f"[{key}]"), label, hint)  # Text(): "[q]" would be read as markup
    console.print()
    console.print(Panel(table, title="[bold]Menu[/]", title_align="left", border_style=ACCENT, box=_box(), padding=(1, 2), expand=False))
    return Prompt.ask(
        " Choose an option", choices=[key for key, *_ in MENU], default="1", show_choices=False, console=console
    ).lower()


def ask_scan_settings(default_network: str) -> dict:
    console.print(" [bright_black]Press Enter to keep the value in brackets.[/]")
    network = Prompt.ask(" Network to scan", default=default_network, console=console)
    console.print(" [bright_black]quick = IoT ports, fast   /   full = more ports + deep checks, slower[/]")
    mode = Prompt.ask(" Mode", choices=["quick", "full"], default="quick", console=console)
    nvd = Confirm.ask(" Also look up known CVEs online (NVD, slower)?", default=False, console=console)
    return {"network": network.strip(), "mode": mode, "nvd": nvd}


def confirm_authorized(network: str) -> bool:
    return Confirm.ask(
        f" Do you own [bold]{escape(network)}[/] or have permission to scan it?",
        default=False,
        console=console,
    )
