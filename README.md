# IoT Security Scanner

University project about IoT security. It's a Python program that runs in the terminal, finds the devices connected to my home network and checks them for the most common security problems of IoT devices (Telnet open, default passwords, UPnP, unprotected camera streams, MQTT without a password, known CVEs...).

At the end it gives every device a risk level (LOW / MEDIUM / HIGH), a score from 0 to 100 for the whole network, and a report that explains what is wrong and how to fix it.

> ⚠️ **Only use it on your own network or on a network where you have permission.** Scanning other people's networks without permission can be illegal. The program asks you to confirm this before every scan.

---

## Why I made this

Cheap IoT devices (cameras, smart plugs, TV boxes, routers from the ISP...) are often the weakest point of a home network. Botnets like Mirai got huge just by logging into devices with Telnet open and the factory password. I wanted to see how my own devices were doing, and to understand how tools like Nmap work, so I built a small scanner that puts together the checks I studied in the course.

## What it checks

| Check | How |
| --- | --- |
| Device discovery | ARP scan of the network (Scapy) + SSDP/UPnP discovery |
| Vendor and device type | MAC address lookup (OUI) + services found + UPnP "SERVER" header |
| Open ports and versions | Nmap with a list of ports used by IoT devices (MQTT, RTSP, ADB, TR-069...) |
| Telnet / FTP / plain HTTP | Unencrypted services where passwords can be sniffed |
| UPnP | Devices that answer SSDP can open ports on the router by themselves |
| ADB (5555) | Android TV boxes with debugging open = anyone can control them |
| TR-069 (7547) | ISP remote management port |
| MQTT (1883) | In full mode it tries to connect **without** a password to see if the broker allows it |
| RTSP (554) | In full mode it checks if the camera stream answers without a password |
| Web panels | In full mode: does the page ask for a login? Security headers? Old TLS? |
| Default passwords | Flags vendors known for factory passwords (it never tries to log in) |
| Known CVEs (optional) | NVD API using the CPE that Nmap finds, and the CISA list of actively exploited CVEs |
| Nmap vuln scripts | In full mode, only the scripts in the `vuln and safe` category |
| Wi-Fi | Reads the Wi-Fi security of the PC's connection (WPA2/WPA3 or weak) |

The program **never guesses passwords** and never changes anything on the devices. The "default password" check is only a reminder based on the vendor name.

## How it works

```
 ARP + SSDP          Nmap (per device, in parallel)        checks                 output
┌───────────┐     ┌───────────────────────────────┐     ┌─────────────┐     ┌──────────────────┐
│ find the  │ --> │ ports, services, versions,    │ --> │ IoT rules   │ --> │ terminal summary │
│ devices   │     │ CPE, (vuln scripts in full)   │     │ deep checks │     │ MD / HTML / CSV  │
└───────────┘     └───────────────────────────────┘     │ NVD + KEV   │     │ JSON (show/diff) │
                                                        │ risk score  │     └──────────────────┘
                                                        └─────────────┘
```

Every device gets risk points from what was found (for example Telnet = 3, ADB = 4, MQTT without password = 3, a CRITICAL CVE = 4/5). 0-2 points is **LOW**, 3-6 is **MEDIUM**, 7 or more is **HIGH**. Only the 3 worst CVEs of a device count, so one old service with 50 CVEs doesn't make everything else invisible. The network score starts at 100 and goes down based on how many risky devices there are. The weights are in `src/scoring.py`.

---

## Setup

You need:

- **Python 3.11+**
- **Nmap**: <https://nmap.org/download.html> (on Windows the installer also installs **Npcap**, keep that option checked)

Then:

```powershell
git clone https://github.com/zenobor/IoT_security.git
cd IoT_security\iot-vuln-scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On Linux / macOS it's the same, but activate with `source .venv/bin/activate` and run the scanner with `sudo`.

If PowerShell blocks the activation script, run this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**Open the terminal as Administrator**: ARP discovery and Nmap need it, otherwise some devices or ports may be missing.

To check that everything is installed correctly:

```powershell
python main.py doctor
```

## Usage

The easiest way is the interactive menu: just run the program without anything else.

```powershell
python main.py
```

```
  1  Scan the network
  2  Check setup (Nmap, Npcap, admin rights)
  3  Show the last scan
  4  Compare the last two scans
  5  Exit
```

Every option also exists as a command, so you can use it in scripts:

```powershell
python main.py scan                                  # finds your network automatically
python main.py scan --network 192.168.1.0/24         # choose the network
python main.py scan --mode full                      # more ports + deep checks (slower)
python main.py scan --mode full --nvd                # also look up known CVEs online
python main.py scan --ports 22,80,443,554            # only these ports
python main.py show                                  # show the last scan again
python main.py show --ip 192.168.1.23                # all the details of one device
python main.py show --map                            # devices grouped by type
python main.py compare                               # what changed since the previous scan
python main.py doctor                                # check Nmap / Npcap / admin rights
```

The main options of `scan`:

| Option | What it does |
| --- | --- |
| `--network` | Network in CIDR format. Default `auto` = the network of your PC |
| `--mode quick` | ~50 common IoT ports, fast (default) |
| `--mode full` | Ports 1-1024 + IoT ports, web/TLS/MQTT/RTSP checks, Nmap vuln scripts |
| `--nvd` | Look up CVEs on the NVD API (needs Internet) |
| `--nvd-api-key` | Free NVD key, makes `--nvd` much faster (or set the `NVD_API_KEY` variable) |
| `--offline` | Never use the Internet |
| `--workers` | How many devices are scanned at the same time (default 4) |
| `--html-output`, `--csv-output` | Also save an HTML / CSV report |
| `--config` | Read the options from a JSON file (see `config.example.json`) |
| `-y`, `--yes` | Skip the "do you have permission?" question |

`python main.py scan --help` shows all of them.

Without an API key the NVD only allows 5 requests every 30 seconds, so `--nvd` can be slow the first time. The results are cached in `cache/` for a week, so the next scans are faster. You can get a free key here: <https://nvd.nist.gov/developers/request-an-api-key>.

### Example output

This is how the summary looks (the devices here are made up for the example):

```
╭──────────────────────────────── Scan summary ────────────────────────────────╮
│ Network score: 62/100    HIGH 2   MEDIUM 0   LOW 2   Devices 4               │
╰──────────────────────────────────────────────────────────────────────────────╯
  IP             Hostname      Type                          Open ports     Risk
 ────────────────────────────────────────────────────────────────────────────────
  192.168.1.1    router.home   Router or network device      53, 80, 7547   HIGH
  192.168.1.23   -             IP camera                     23, 80, 554    HIGH
  192.168.1.40   -             Smart home device             1883, 6668     LOW
  192.168.1.52   -             Phone or laptop (private MAC) none           LOW

┌─ 192.168.1.23  IP camera  HIGH ──────────────────────────────────────────────┐
│  HIGH    Telnet is open                                                       │
│          Passwords travel in clear text and Telnet is the #1 target of IoT    │
│          botnets (e.g. Mirai).                                                │
│          Fix: Disable Telnet in the device settings, or update the firmware.  │
│  ...                                                                          │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Reports

Every scan saves its results in the `reports/` folder:

- `scan_report.md`: the readable report (summary, devices, problems + how to fix them)
- `scan_results.json`: all the data, used by `show` and `compare`
- `previous_results.json`: the scan before, so `compare` works without other files
- with `--html-output` / `--csv-output` also an HTML page and a CSV for Excel

The `reports/` and `cache/` folders are in `.gitignore`, because the results contain information about your home network and should not end up on GitHub.

---

## Project structure

```
iot-vuln-scanner/
├── main.py               # command line: menu, scan, show, compare, doctor
├── src/
│   ├── discovery.py      # ARP scan, SSDP/UPnP discovery, auto-detects the network
│   ├── fingerprint.py    # vendor (MAC), hostname, Nmap scan, device type
│   ├── rules.py          # IoT rules (Telnet, UPnP, ADB, MQTT, default passwords...)
│   ├── deep_checks.py    # full mode: web panels, TLS, MQTT, RTSP
│   ├── vuln_check.py     # NVD API, CISA KEV list, Nmap vuln scripts
│   ├── scoring.py        # risk points -> LOW/MEDIUM/HIGH, network score
│   ├── findings.py       # turns the results into "problem + fix" sentences
│   ├── scanner.py        # puts everything together (devices scanned in parallel)
│   ├── report.py         # Markdown / HTML / CSV / JSON reports
│   ├── compare.py        # differences between two scans
│   ├── diagnostics.py    # "doctor" command + Wi-Fi check
│   └── terminal_report.py  # everything printed in the terminal (rich)
├── data/default_creds.json  # vendors known for factory passwords
├── tests/                # pytest tests (no real network needed)
├── app.py                # old desktop version (optional, see below)
└── config.example.json
```

## Tests

The tests replace Nmap, Scapy and the network with fake data, so they run anywhere in a few seconds:

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

GitHub Actions runs them on Windows and Ubuntu with Python 3.11, 3.12 and 3.13 at every push.

## Desktop app (optional)

Before switching to the terminal version I made a small desktop window with PySide6. It still works and it uses the same scanner underneath, but the terminal is now the main way to use the project:

```powershell
pip install -r requirements-gui.txt
python app.py
```

---

## Limitations

- It only sees what is reachable from my PC. If the router isolates Wi-Fi clients, some devices won't show up.
- The device type is a guess based on the vendor and the open ports, so it can be wrong.
- The NVD search depends on Nmap recognising the exact version. A lot of IoT devices don't show their version, so many CVEs can't be found this way.
- Some phones and laptops use a random MAC address, so the vendor shows as "Private (randomized) MAC".
- UDP is only checked for SSDP. A full UDP scan would take too long for a home network.
- It doesn't check the router's settings (WPS, remote admin, firmware) because it would need the router password.

## What I would add next

- mDNS discovery (to get names like "Living-Room-TV")
- Checking the router from outside (which ports are open to the Internet)
- A scheduled scan that warns when a new device joins the network
- Better device recognition using the UPnP description XML

## Concepts used

- ARP and why it only works inside the local network
- Nmap service/version detection and CPE names
- MQTT and RTSP at the packet level (the MQTT CONNECT packet is built by hand in `deep_checks.py`)
- Using a rate-limited API (NVD) with a local cache
- Tests with fake objects (pytest monkeypatch) so they don't need a real network

## License

MIT, see [LICENSE](LICENSE).
