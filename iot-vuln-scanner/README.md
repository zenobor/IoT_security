# IoT Vulnerability Scanner

Tool per analizzare la propria rete WiFi, identificare i dispositivi IoT connessi e verificarne le vulnerabilità note.

## ⚠️ Uso responsabile

Questo strumento va usato **esclusivamente sulla propria rete o su reti per cui si ha un'autorizzazione esplicita**. Scansionare reti altrui senza permesso può essere illegale.

## Funzionalità (in sviluppo)

- [ ] Discovery dei dispositivi sulla rete locale (ARP scan)
- [ ] Fingerprinting (vendor, servizi, versioni)
- [ ] Controllo vulnerabilità note (nmap scripts + NVD API)
- [ ] Regole specifiche IoT (Telnet aperto, credenziali default, UPnP esposto)
- [ ] Report finale con livello di rischio per dispositivo

## Setup

```bash
python -m venv venv
source venv/bin/activate  # su Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Utilizzo

```bash
python main.py
```

## Struttura del progetto

```
src/
├── discovery.py     # scansione ARP + nmap
├── fingerprint.py   # identificazione vendor/servizi
├── vuln_check.py    # controllo CVE note
├── rules.py         # regole IoT-specifiche
├── scoring.py       # calcolo livello di rischio
└── report.py        # generazione report
```

## Stato del progetto

Progetto in fase iniziale di sviluppo.
