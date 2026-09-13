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
- [x] Riepilogo del rischio e consigli pratici
- [x] Export JSON, HTML e CSV
- [x] Hostname, porte personalizzate e modalita offline
- [x] Controlli approfonditi non invasivi su HTTP, HTTPS e TLS
- [x] Configurazione da file e test automatici GitHub
- [x] App desktop PySide6
- [x] Network security score e mappa dispositivi
- [x] Finestra dettagli dispositivo e diagnostica Nmap/Npcap

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

Per aprire l'app desktop:

```powershell
python app.py
```

Nella finestra puoi scegliere rete, porte, modalita e opzioni. Premi **Start scan** per avviare il programma, guarda il punteggio globale, i dispositivi nella tab **Devices**, la mappa nella tab **Network map** e il report completo nella tab **Report**. Fai doppio click su un dispositivo per vedere i dettagli. La tab **Diagnostics** controlla Nmap e Npcap. Puoi anche premere **Cancel** durante una scansione. Quando usi l'`.exe`, i report vengono salvati in `C:\Users\TUO_UTENTE\IoTScannerReports`.

Mostra tutti i comandi disponibili:

```powershell
python main.py --help
```

Avvia una scansione della propria rete autorizzata:

```powershell
python main.py --network 192.168.1.0/24 --timeout 2 --output scan_report.md
```

La modalita predefinita `quick` controlla le porte piu comuni ed evita i test piu lenti:

```powershell
python main.py --mode quick --network 192.168.1.0/24 --output scan_report.md
```

Per una scansione piu completa, che esegue anche gli script di vulnerabilita Nmap:

```powershell
python main.py --mode full --network 192.168.1.0/24 --output scan_report.md
```

La modalita `full` controlla le 1.000 porte piu comuni e poi esegue richieste di sola lettura sui pannelli web trovati. Controlla risposta HTTP, header di sicurezza e problemi TLS. Ogni host ha un timeout, quindi la scansione continua anche quando un dispositivo non risponde. Non prova password, non esegue login e non modifica i dispositivi.

Aggiungi `--nvd` se vuoi interrogare anche il database NVD per le CVE. Questa opzione puo richiedere piu tempo e una connessione Internet.

Per salvare anche i risultati in JSON:

```powershell
python main.py --network 192.168.1.0/24 --timeout 2 --output scan_report.md --json-output scan_results.json
```

Per creare anche HTML e CSV:

```powershell
python main.py --mode quick --network 192.168.1.0/24 --output scan_report.md --html-output scan_report.html --csv-output scan_results.csv --json-output scan_results.json
```

Per controllare solo alcune porte:

```powershell
python main.py --ports 22,23,80,443,554,8080 --network 192.168.1.0/24
```

Per usare il file di configurazione di esempio:

```powershell
python main.py --config config.example.json
```

Per una scansione senza richieste Internet:

```powershell
python main.py --offline --network 192.168.1.0/24
```

I file generati sono:

- `scan_report.md`: report breve in Markdown.
- `scan_report.html`: report leggibile nel browser.
- `scan_results.csv`: tabella per Excel o altri strumenti.
- `scan_results.json`: risultati completi per altri programmi.

I parametri significano:

- `--network`: rete da analizzare in formato CIDR.
- `--timeout`: secondi di attesa per le risposte ARP.
- `--output`: nome del report Markdown da creare.
- `--json-output`: file JSON opzionale per usare i risultati in altri programmi.
- `--html-output`: report HTML opzionale da aprire nel browser.
- `--csv-output`: tabella CSV opzionale da aprire in Excel.
- `--ports`: porte o intervalli, per esempio `22,80,443,8000-8100`.
- `--mode`: `quick` (predefinita) o `full`.
- `--nvd`: abilita le richieste alla NVD API.
- `--offline`: disabilita le richieste a NVD e ai servizi Internet.
- `--config`: legge i valori predefiniti da un file JSON.

Il programma trova i dispositivi, legge vendor e porte, controlla le vulnerabilita e salva il risultato in `scan_report.md`. Il report mostra anche quanti dispositivi hanno rischio alto, medio o basso e consigli pratici.

Alla fine della scansione il terminale stampa anche un riepilogo ASCII con:

- punteggio della rete da 0 a 100;
- numero di dispositivi high, medium e low risk;
- IP, hostname, tipo, rischio e porte aperte per ogni dispositivo.

Esempio:

```text
+==============================================================================+
| IoT VULNERABILITY SCAN - FINAL SUMMARY                                       |
+==============================================================================+
| Network score: 74/100   HIGH: 1   MEDIUM: 2   LOW: 6                        |
| 192.168.1.20    | camera               | IP camera              | HIGH   | 554 |
+==============================================================================+
```

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

GitHub Actions esegue automaticamente i test quando viene fatto un push o aperta una pull request.

## Struttura del progetto

```
src/
├── discovery.py     # scansione ARP + nmap
├── fingerprint.py   # identificazione vendor/servizi
├── vuln_check.py    # controllo CVE note
├── rules.py         # regole IoT-specifiche
├── scoring.py       # calcolo livello di rischio
└── report.py        # generazione report Markdown, HTML, CSV e JSON

app.py               # interfaccia desktop PySide6
config.example.json  # configurazione di esempio
```

## Stato del progetto

Il progetto e funzionante per una prima scansione locale, ma deve essere usato solo su reti proprie o autorizzate.
