# IoT Security

Scanner Python per trovare dispositivi IoT nella propria rete e controllare alcuni problemi di sicurezza comuni.

## Guida del progetto

Le istruzioni complete per installare, aprire e usare il progetto sono disponibili in [iot-vuln-scanner/README.md](iot-vuln-scanner/README.md).

## Avvio veloce su Windows

```powershell
git clone https://github.com/zenobor/IoT_security.git
cd IoT_security\iot-vuln-scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py --network 192.168.1.0/24 --output scan_report.md
```

Usa lo scanner solo su reti proprie o autorizzate. Per la guida completa, consulta il README nella cartella `iot-vuln-scanner`.