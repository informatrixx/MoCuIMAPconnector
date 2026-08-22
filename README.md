# MoCu IMAP Connector

Produktionsfähiger, read-only MCP-Server für den kontrollierten Zugriff auf ein GMX-IMAP-Postfach.

- **Read-only**: Es werden nur Mails gelesen. Es werden keine Mails gelöscht, verschoben, markiert, versendet oder in andere Ordner geschrieben.
- **MCP-Server**: Streamable-HTTP (MCP-SDK 2.0.0).
- **Sicherheit**: Keine externen APIs, keine Index-DB, keine Telemetrie, keine Persistenz von Mail-Inhalten.

## 1) Technologieprüfung

Aktiv getestete Umgebung in diesem Projekt:

- Python: 3.13.5 (>= 3.12)
- MCP-Python-SDK: 2.0.0 (installierte Version im venv)
- Server-Transport: `streamable-http`

Diese Version wird verwendet, sofern keine neuere stabile und produktionsrelevante Version nachweislich nötig ist.

## 2) Installation

```bash
cd /var/codex/MoCuIMAPconnector
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 3) Konfiguration

Lege eine eigene `.env` an (siehe `.env.example`) und fülle nur folgende Werte aus:

```env
IMAP_HOST=imap.gmx.net
IMAP_PORT=993
IMAP_SSL=true

IMAP_USERNAME=
IMAP_PASSWORD=

MCP_BIND=127.0.0.1
MCP_PORT=8765
MCP_HTTP_PATH=/mcp
CURSOR_SIGNING_KEY=
SEARCH_SCAN_BATCH_SIZE=100

MAX_SEARCH_RESULTS=100
DEFAULT_SEARCH_LIMIT=50
MAX_ATTACHMENT_SIZE_MB=25
MCP_MAX_REQUEST_BODY_SIZE=4194304
LOG_LEVEL=INFO
```

Hinweise:

- IMAP muss im GMX-Konto aktiviert sein.
- Für `IMAP_PASSWORD` ausschließlich ein **anwendungsspezifisches Passwort** verwenden.
- Passwort niemals in ChatGPT-Eingaben, Logs oder Tickets einfügen.
- Zugriff nur mit diesem Postfach-User und App-Passwort.

## 4) MCP-Tools

Die folgenden Tools stehen zur Verfügung:

- `list_mailboxes`
- `search_emails`
- `get_email`
- `list_attachments`
- `get_attachment`
- `find_invoice_candidates`

Tool-Ergebnisse enthalten nur Mail-Metadaten oder Anhangs-Metadaten.

## 5) Skripte

### IMAP-Verbindung prüfen

```bash
. .venv/bin/activate
python scripts/test_imap_connection.py
```

Optional:

```bash
python scripts/test_imap_connection.py --list-mailboxes
```

Ausgabe ist bewusst minimal:

```text
IMAP connection: OK
Mailboxes: 12
```

### MCP-Tools lokal inspizieren

```bash
. .venv/bin/activate
python scripts/test_mcp.py
```

## 6) Server starten

```bash
. .venv/bin/activate
python -m mocu_imap_mcp.server
```

Der Server läuft standardmäßig auf `127.0.0.1:8765/mcp`.

## 7) Tests und Qualität

```bash
. .venv/bin/activate
pytest -q
ruff check src tests scripts
mypy src
```

Unit-Tests decken u. a. ab:

- RFC2047-/RFC2231-Header-Decoding
- Multipart-Erkennung mit `text/plain`, `text/html`, PDF-Anhang
- Datumsbereich für IMAP (`SINCE`/`BEFORE`)
- UID-/Cursor-Mechanik
- Geheimnis-Redaktion in Settings/Exceptions/Logs

CI-Workflow:

- `.github/workflows/ci.yml` (Python 3.12/3.13, ruff, mypy, pytest)

## 8) Deployment – Variante A (bevorzugt)

Variante A: Private Bereitstellung über **OpenAI Secure MCP Tunnel**.

Für eine produktive ChatGPT-Anbindung darf kein ungeschützter öffentlicher MCP-Port verwendet werden.

Hinweis:

- Dokumentiere hier aktuell verwendete, dokumentationskonforme OpenAI-Befehle.
- Wenn keine verifizierte aktuelle Tunnel-Doku vorliegt, bitte den folgenden Platzhalter unverändert lassen:

```text
TODO: aktuellen Secure-MCP-Tunnel-Befehl aus der offiziellen OpenAI-Dokumentation einsetzen.
```

Beispielprinzip:

- Dienst bindet nur lokal auf `127.0.0.1:8765`
- Tunnel wird durch OpenAI für die Authentifizierung/Exposition bereitgestellt
- Authentisierung erfolgt dann über den OpenAI-MCP-Mechanismus

## 9) Deployment – Variante B (Reverse Proxy)

Siehe [`deploy/nginx.conf.example`](deploy/nginx.conf.example).

Hinweis:

- Standard-Domain hier nicht hartkodieren.
- Platzhalterdomain: `imap-mcp.example.at`
- TLS muss extern gesetzt sein.

## 10) Systemd (für Debian)

Siehe [`deploy/mocu-imap-mcp.service`](deploy/mocu-imap-mcp.service) und Beispiel-Umgebungsdatei
[`deploy/mocu-imap-mcp.env.example`](deploy/mocu-imap-mcp.env.example).

## 11) Sicherheit und Datenschutz

- kein Zugriff auf Dateisysteme außerhalb erwarteter Pfade im Serverbetrieb
- kein Schreiben von Mailinhalten auf Platte
- keine externen Netzwerkaufrufe für Mail/Anhänge
- keine KI-Auswertung im Server; alle Auswertungen erfolgen nur in ChatGPT nach Bedarf

## 12) Unterstützte Umgebungsvariablen

- `IMAP_HOST`
- `IMAP_PORT`
- `IMAP_SSL`
- `IMAP_USERNAME`
- `IMAP_PASSWORD`
- `IMAP_CONNECTION_TIMEOUT`
- `IMAP_CONNECTION_RETRIES`
- `IMAP_RETRY_DELAY`
- `MCP_BIND`
- `MCP_PORT`
- `MCP_HTTP_PATH`
- `MAX_SEARCH_RESULTS`
- `DEFAULT_SEARCH_LIMIT`
- `SEARCH_SCAN_BATCH_SIZE`
- `MAX_ATTACHMENT_SIZE_MB`
- `MCP_MAX_REQUEST_BODY_SIZE`
- `LOG_LEVEL`
- `CURSOR_SIGNING_KEY`
- `MCP_ALLOWED_HOSTS`
- `MCP_ALLOWED_ORIGINS`

Weitere optionale Werte siehe `src/mocu_imap_mcp/config.py`.
