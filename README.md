# IoT Security Scanner

University project about IoT security. A Python program for the terminal that finds the devices on your network, checks them for common IoT security problems and gives each one a risk level (LOW / MEDIUM / HIGH), with a report that explains how to fix what it found.

> ⚠️ **Only use it on your own network or on a network where you have permission.**

## Why I made this

Cheap IoT devices (cameras, smart plugs, TV boxes, routers from the ISP...) are often the weakest point of a home network. Botnets like Mirai got huge just by logging into devices with Telnet open and the factory password. I wanted to see how my own devices were doing, and to understand how tools like Nmap work, so I built a small scanner that puts together the checks I studied in the course.

## What it checks

- **Devices**: ARP scan + SSDP/UPnP discovery, vendor from the MAC address, device type
- **Ports and versions**: Nmap, with the ports used by IoT devices
- **IoT rules**: Telnet, FTP, plain HTTP, UPnP, ADB, TR-069, MQTT, vendors with default passwords
- **Full mode**: web panels without login, old TLS, MQTT without password, camera streams without password, safe Nmap vuln scripts
- **Known CVEs** (optional): NVD API + CISA list of actively exploited vulnerabilities

It never guesses passwords and never changes anything on the devices.

## Setup

Requirements: **Python 3.11+** and **Nmap** (<https://nmap.org/download.html>, on Windows keep the **Npcap** option checked).

```powershell
git clone https://github.com/zenobor/IoT_security.git
cd IoT_security\iot-vuln-scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Open the terminal **as Administrator** (on Linux use `sudo`), then check that everything is ready:

```powershell
python main.py doctor
```

## Usage

```powershell
python main.py                     # interactive menu
python main.py scan                # quick scan (network found automatically)
python main.py scan --mode full    # more ports + deep checks (slower)
python main.py scan --nvd          # also look up known CVEs online
python main.py show --map          # show the last scan again
python main.py compare             # what changed since the previous scan
```

All the options: `python main.py scan --help`.

Results are saved in `reports/` (Markdown report + JSON). This folder is ignored by git because it contains information about your network.

## How the risk is calculated

Every problem gives points (e.g. Telnet = 3, ADB = 4, critical CVE = 4-5). **0-2** = LOW, **3-6** = MEDIUM, **7+** = HIGH. The network score goes from 0 to 100. The weights are in `src/scoring.py`.

## Tests

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

## License

MIT, see [LICENSE](LICENSE).
