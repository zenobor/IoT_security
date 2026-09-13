# IoT Security Scanner

Desktop and Python tool for finding IoT devices on an authorized local network and checking common security risks.

## What it does

- Finds devices with ARP and identifies vendor, hostname and device type.
- Checks ports and services with Nmap.
- Checks Telnet, FTP, SSH, UPnP, HTTP/TLS and known default-credential vendors.
- Checks web authentication, cleartext traffic and firmware/service banners.
- Flags exposed RDP, VNC, databases, Redis, MQTT and OPC UA services.
- Reports manual checks for weak passwords, Wi-Fi security and VLAN/guest isolation.
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

`quick` checks the 100 most common ports. `full` checks the 1,000 most common ports and runs deeper read-only checks. The terminal prints an ASCII summary with the network score, risk counts, warnings and manual checks.

Useful options:

```powershell
python main.py --offline --network 192.168.1.0/24
python main.py --ports 22,80,443,554 --network 192.168.1.0/24
python main.py --mode full --nvd --network 192.168.1.0/24
```

The scanner never guesses passwords or uses brute force. Password strength, Wi-Fi encryption and VLAN/guest isolation are reported as manual checks when they cannot be verified from the scanning computer.

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

The app includes a network score, device details, a network map, report preview, logs and Nmap/Npcap diagnostics.

## Tests

```powershell
python -m pytest tests
```

GitHub Actions runs the tests on every push and pull request.

Use this tool only on networks you own or are authorized to test.