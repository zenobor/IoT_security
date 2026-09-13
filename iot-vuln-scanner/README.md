# IoT Vulnerability Scanner

Tool per analizzare la propria rete WiFi, identificare i dispositivi IoT connessi e verificarne le vulnerabilità note.

## ⚠️ Uso responsabile

Questo strumento va usato **esclusivamente sulla propria rete o su reti per cui si ha un'autorizzazione esplicita**. Scansionare reti altrui senza permesso può essere illegale.

## Funzionalità

- [x] Discovery dei dispositivi sulla rete locale (ARP scan)
- [x] Fingerprinting (vendor, servizi, versioni)
- [x] Controllo vulnerabilità note (Nmap scripts + NVD API)
- [x] Regole specifiche IoT (Telnet aperto, credenziali default, UPnP esposto)
- [x] Report finale con livello di rischio per dispositivo

## Copiare il progetto in VS Code

Apri PowerShell e clona il repository GitHub:

```powershell
git clone https://github.com/zenobor/IoT_security.git
cd IoT_security\iot-vuln-scanner
code .
```

`git clone` copia il progetto sul computer. `cd` entra nella cartella del programma. `code .` apre quella cartella in VS Code.

Se il comando `code` non e disponibile, apri VS Code, scegli **File > Open Folder** e seleziona la cartella `iot-vuln-scanner`.

## Installazione su Windows

Crea e attiva un ambiente virtuale:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

L'ambiente virtuale tiene separate le dipendenze di questo progetto da quelle globali di Python.

Il progetto usa anche Nmap. Installa Nmap dal sito ufficiale e verifica l'installazione:

```powershell
nmap --version
```

Se PowerShell blocca l'attivazione dell'ambiente virtuale, esegui una volta:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Avviare una scansione

Mostra tutti i comandi disponibili:

```powershell
python main.py --help
```

Avvia una scansione della propria rete autorizzata:

```powershell
python main.py --network 192.168.1.0/24 --timeout 2 --output scan_report.md
```

I parametri significano:

- `--network`: rete da analizzare in formato CIDR.
- `--timeout`: secondi di attesa per le risposte ARP.
- `--output`: nome del report Markdown da creare.

Il programma trova i dispositivi, legge vendor e porte, controlla le vulnerabilita e salva il risultato in `scan_report.md`.

Per eseguire i test installa prima `pytest`:

```powershell
python -m pip install pytest
python -m pytest tests
```

## Comandi Git principali

```powershell
git pull origin main
git status
git log --oneline -5
git add .
git commit -m "Describe the change"
git push origin main
```

- `git pull` scarica gli aggiornamenti da GitHub.
- `git status` mostra i file modificati.
- `git log` mostra gli ultimi commit.
- `git add .` prepara le modifiche.
- `git commit` salva una versione nella cronologia locale.
- `git push` pubblica i commit su GitHub.

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

Il progetto e funzionante per una prima scansione locale, ma deve essere usato solo su reti proprie o autorizzate.
