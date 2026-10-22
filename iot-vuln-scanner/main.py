"""
IoT Vulnerability Scanner - command line entry point.

    python main.py                  interactive menu
    python main.py scan [options]   scan a network
    python main.py doctor           check that Nmap / Npcap / admin rights are OK
    python main.py show [file]      show a saved scan again
    python main.py compare [a] [b]  compare two saved scans
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

from src import compare, diagnostics, discovery, report, scanner, vuln_check
from src import terminal_report as ui


PROJECT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_DIR / "reports"
LATEST_JSON = REPORTS_DIR / "scan_results.json"
PREVIOUS_JSON = REPORTS_DIR / "previous_results.json"
MAX_HOSTS = 65_536


# ---------- argument parsing ----------

def _load_config(path: str | None) -> dict:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as file:
            config = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read config file: {exc}") from exc
    if not isinstance(config, dict):
        raise SystemExit("Config file must contain a JSON object")
    return {key.replace("-", "_"): value for key, value in config.items()}


def _workers(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 16:
        raise argparse.ArgumentTypeError("workers must be between 1 and 16")
    return number


def _timeout(value: str) -> float:
    number = float(value)
    if not 0.5 <= number <= 30:
        raise argparse.ArgumentTypeError("timeout must be between 0.5 and 30 seconds")
    return number


def build_parser(config: dict | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Scan your own network for IoT devices and common security problems.",
        epilog="Run without arguments for the interactive menu. Only scan networks you are allowed to test.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {scanner.VERSION}")
    commands = parser.add_subparsers(dest="command", metavar="command")

    scan = commands.add_parser("scan", help="scan a network", description="Scan a network and save the reports.")
    scan.add_argument("--network", default="auto", help="network in CIDR format, e.g. 192.168.1.0/24 (default: auto-detect)")
    scan.add_argument("--mode", choices=("quick", "full"), default="quick", help="quick = IoT ports; full = more ports + deep checks")
    scan.add_argument("--ports", help="custom ports, e.g. 22,80,443,554 or 1-1024")
    scan.add_argument("--timeout", type=_timeout, default=2, help="seconds to wait for ARP/SSDP answers (default: 2)")
    scan.add_argument("--workers", type=_workers, default=4, help="devices scanned at the same time (default: 4)")
    scan.add_argument("--nvd", action="store_true", help="look up known CVEs on the NVD API (needs Internet)")
    scan.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"), help="NVD API key (or set NVD_API_KEY), makes --nvd faster")
    scan.add_argument("--offline", action="store_true", help="never use the Internet (disables --nvd)")
    scan.add_argument("--output", default=str(REPORTS_DIR / "scan_report.md"), help="Markdown report path")
    scan.add_argument("--html-output", help="also save an HTML report")
    scan.add_argument("--csv-output", help="also save a CSV file")
    scan.add_argument("--json-output", default=str(LATEST_JSON), help="JSON results path (used by show/compare)")
    scan.add_argument("--config", help="JSON file with default options (see config.example.json)")
    scan.add_argument("-y", "--yes", action="store_true", help="skip the 'do you have permission?' question")
    scan.add_argument("--no-details", action="store_true", help="only print the summary table")
    if config:
        scan.set_defaults(**config)

    commands.add_parser("doctor", help="check that Nmap, Npcap and admin rights are OK")

    show = commands.add_parser("show", help="show a saved scan again")
    show.add_argument("file", nargs="?", default=str(LATEST_JSON), help="JSON results (default: last scan)")
    show.add_argument("--ip", help="only show this device, with all its issues")
    show.add_argument("--map", action="store_true", help="also show the network map")

    compare_parser = commands.add_parser("compare", help="compare two saved scans")
    compare_parser.add_argument("old", nargs="?", default=str(PREVIOUS_JSON), help="older JSON (default: previous scan)")
    compare_parser.add_argument("new", nargs="?", default=str(LATEST_JSON), help="newer JSON (default: last scan)")

    commands.add_parser("menu", help="interactive menu (same as running without arguments)")
    return parser


def parse_args(argv: list[str]) -> argparse.Namespace:
    # Old style "python main.py --network ..." still works: it means "scan".
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv = ["scan", *argv]

    config = {}
    if argv and argv[0] == "scan":
        config_parser = argparse.ArgumentParser(add_help=False)
        config_parser.add_argument("--config")
        config_args, _ = config_parser.parse_known_args(argv[1:])
        config = _load_config(config_args.config)
    return build_parser(config).parse_args(argv)


# ---------- helpers ----------

def resolve_network(value: str) -> str:
    """Turns "auto" into the local network and checks that the range makes sense."""
    if value == "auto":
        detected = discovery.detect_local_network()
        if not detected:
            raise SystemExit("Could not detect the local network. Use --network, e.g. --network 192.168.1.0/24")
        value = detected

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SystemExit(f"'{value}' is not a valid network. Example: 192.168.1.0/24") from exc
    if network.version != 4:
        raise SystemExit("Only IPv4 networks are supported (ARP does not exist in IPv6).")
    # ARP only works on the local network anyway, and this avoids scanning
    # someone else's public IPs by mistake (e.g. a typo in the address)
    if not network.is_private:
        raise SystemExit(f"{network} is not a private network. This tool is only meant for your own LAN.")
    if network.num_addresses > MAX_HOSTS:
        raise SystemExit(f"{network} is too big ({network.num_addresses} addresses). Use /16 or smaller.")
    return str(network)


def validate_ports(port_spec: str | None) -> str | None:
    if port_spec is None:
        return None
    # The ports end up in the Nmap command line, so only numbers, commas and dashes are allowed
    if not re.fullmatch(r"\d+(-\d+)?(,\d+(-\d+)?)*", port_spec):
        raise SystemExit("Ports must look like 22,80,443 or 1-1024")
    for number in re.findall(r"\d+", port_spec):
        if not 1 <= int(number) <= 65535:
            raise SystemExit(f"Port {number} is not valid (1-65535)")
    return port_spec


def load_scan(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"{path} not found. Run a scan first: python main.py scan")
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read {path}: {exc}")
    # Old result files only had the device list.
    data.setdefault("scan", {})
    data.setdefault("network_checks", [])
    return data


def save_reports(scan: dict, args: argparse.Namespace) -> list[str]:
    json_path = Path(args.json_output)
    # Keep the previous results so "compare" works without a big history folder.
    if json_path.resolve() == LATEST_JSON.resolve() and json_path.exists():
        shutil.copyfile(json_path, PREVIOUS_JSON)

    saved = []
    for path, writer in (
        (args.output, report.generate_report),
        (args.json_output, report.generate_json_report),
        (args.html_output, report.generate_html_report),
        (args.csv_output, report.generate_csv_report),
    ):
        if path:
            writer(scan, path)
            saved.append(_pretty_path(path))
    return saved


def _pretty_path(path: str) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(path)


# ---------- commands ----------

def run_scan(args: argparse.Namespace) -> int:
    network = resolve_network(args.network)
    port_spec = validate_ports(args.ports)

    # Responsible use: always ask before scanning. If there is no terminal to ask
    # (e.g. started from another program) the user must pass --yes explicitly.
    if not args.yes:
        if not sys.stdin.isatty():
            ui.error("Add --yes to confirm you are allowed to scan this network.")
            return 2
        if not ui.confirm_authorized(network):
            ui.warn("Scan cancelled.")
            return 1

    options = scanner.ScanOptions(
        network=network,
        mode=args.mode,
        timeout=args.timeout,
        ports=port_spec,
        nvd=args.nvd and not args.offline,
        offline=args.offline,
        workers=args.workers,
        nvd_api_key=args.nvd_api_key,
    )
    ui.print_scan_header(network, options.mode, options.nvd, options.workers, diagnostics.is_admin())
    if args.nvd and args.offline:
        ui.warn("--offline is set, so the NVD lookup is skipped.")
    if options.nvd and not options.nvd_api_key:
        ui.info("No NVD API key: CVE lookups are slow (NVD allows 5 requests / 30 s).")

    started_at = datetime.now()
    try:
        with ui.console.status("Looking for devices (ARP + SSDP)..."):
            devices, ssdp = scanner.discover_devices(options)
            if options.nvd:
                options.kev_ids = vuln_check.load_kev(offline=options.offline)
    except PermissionError:
        ui.error("Permission denied. Run the terminal as administrator (or with sudo).")
        return 1
    except OSError as exc:
        ui.error(f"Network discovery failed: {exc}")
        ui.info("Run 'python main.py doctor' to check Npcap and admin rights.")
        return 1

    if not devices:
        ui.warn("No devices answered. Check the network range, Wi-Fi isolation and admin rights.")
    else:
        ui.ok(f"Found [bold]{len(devices)}[/] devices ({len(ssdp)} answered UPnP)")

    with ui.create_progress() as progress:
        task = progress.add_task("Analysing devices", total=len(devices))

        def on_done(result: dict) -> None:
            progress.console.print(ui.device_done_line(result))
            progress.advance(task)

        results = scanner.analyse_devices(devices, options, ssdp, on_done=on_done)

    scan = scanner.build_scan(options, results, started_at)
    saved = save_reports(scan, args)

    ui.print_summary(scan)
    if not args.no_details:
        ui.print_attention(scan)
        ui.print_network_checks(scan["network_checks"])
    if PREVIOUS_JSON.exists() and Path(args.json_output).resolve() == LATEST_JSON.resolve():
        diff = compare.compare_scans(load_scan(str(PREVIOUS_JSON)), scan)
        if compare.has_changes(diff):
            ui.print_comparison(diff)
    ui.print_outputs(saved)
    ui.info(f"Scan took {scan['scan']['duration_seconds']} s")
    return 0


def run_doctor(_args: argparse.Namespace | None = None) -> int:
    checks = diagnostics.check_system()
    ui.print_diagnostics(checks)
    return 1 if any(check["status"] == "MISSING" for check in checks) else 0


def run_show(args: argparse.Namespace) -> int:
    scan = load_scan(args.file)
    if args.ip:
        device = next((item for item in scan.get("devices", []) if item.get("ip") == args.ip), None)
        if not device:
            ui.error(f"{args.ip} is not in {args.file}")
            return 1
        ui.print_device(device, show_all=True)
        return 0

    info = scan.get("scan", {})
    if info:
        ui.info(f"Scan of {info.get('network')} on {str(info.get('started_at', '')).replace('T', ' ')} ({info.get('mode')} mode)")
    ui.print_summary(scan)
    ui.print_attention(scan)
    ui.print_network_checks(scan.get("network_checks", []))
    if args.map:
        ui.print_network_map(scan)
    return 0


def run_compare(args: argparse.Namespace) -> int:
    diff = compare.compare_scans(load_scan(args.old), load_scan(args.new))
    ui.print_comparison(diff)
    return 0


def run_menu() -> int:
    ui.print_banner(scanner.VERSION)
    default_network = discovery.detect_local_network() or "192.168.1.0/24"
    while True:
        choice = ui.ask_menu_choice()
        try:
            if choice == "1":
                settings = ui.ask_scan_settings(default_network)
                argv = ["scan", "--network", settings["network"], "--mode", settings["mode"]]
                if settings["nvd"]:
                    argv.append("--nvd")
                run_scan(parse_args(argv))
            elif choice == "2":
                run_doctor()
            elif choice == "3":
                run_show(parse_args(["show", "--map"]))
            elif choice == "4":
                run_compare(parse_args(["compare"]))
            else:
                return 0
        except SystemExit as exc:
            # Bad input inside the menu should not close the program.
            if exc.code not in (0, None):
                ui.error(str(exc.code))


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = parse_args(argv)
    try:
        if args.command is None or args.command == "menu":
            if not sys.stdin.isatty():
                build_parser().print_help()
                return 0
            return run_menu()
        ui.print_banner(scanner.VERSION)
        handlers = {"scan": run_scan, "doctor": run_doctor, "show": run_show, "compare": run_compare}
        return handlers[args.command](args)
    except KeyboardInterrupt:
        ui.console.print()
        ui.warn("Stopped by the user (Ctrl+C).")
        return 130
    except SystemExit as exc:
        if isinstance(exc.code, str):
            ui.error(exc.code)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
