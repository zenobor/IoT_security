# IoT Security Scanner

Desktop and Python tool for finding IoT devices on an authorized local network and checking common security risks.

## What it does

- Finds devices with ARP and identifies vendor, hostname and device type.
- Checks ports and services with Nmap.
- Checks Telnet, FTP, SSH, UPnP, HTTP/TLS and default credentials.
- Calculates a network score from `0` to `100`.
- Creates Markdown, HTML, CSV and JSON reports.
- Includes a PySide6 desktop app and Nmap/Npcap diagnostics.

## Quick start on Windows

```powershell
git clone https://github.com/zenobor/IoT_security.git
cd IoT_security\iot-vuln-scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Install Nmap and Npcap, then check Nmap:

```powershell
nmap --version
```

## Run the scanner

Fast scan:

```powershell
python main.py --mode quick --network 192.168.1.0/24 --output scan_report.md
```

Deeper read-only scan:

```powershell
python main.py --mode full --network 192.168.1.0/24 --output scan_report.md
```

The terminal prints a final ASCII summary with the network score and every device.

Optional exports:

```powershell
python main.py --mode quick --network 192.168.1.0/24 --output scan_report.md --html-output scan_report.html --csv-output scan_results.csv --json-output scan_results.json
```

## Desktop app

```powershell
python app.py
```

Or run the Windows build:

```powershell
.\dist\IoTScanner\IoTScanner.exe
```

The app includes Devices, Network map, Report, Log and Diagnostics tabs.

## Tests

```powershell
python -m pytest tests
```

GitHub Actions runs the tests on every push and pull request.

Use this tool only on networks you own or are authorized to test.