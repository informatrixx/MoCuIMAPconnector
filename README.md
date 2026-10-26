# MoCu IMAP Connector

Read-only Multi-Account MCP Connector für generische IMAP-Postfächer.
Entwicklungsstand auf Basis `5ef37bb`; kein Release. Ein Deployment verwaltet
mehrere Konten einer gemeinsamen Vertrauensgruppe, kein Multi-Tenant-SaaS.

## Funktionen und Datenschutz

IMAPS auf 993, STARTTLS auf 143, UID-basierte Suche, deterministische
Rechnungskandidaten, Textansicht und gezielter Attachment-Zugriff.
Keine Mailbox-Schreiboperationen, kein SMTP, kein Provider-OAuth, keine KI,
kein OpenAI API-Key, keine Mailkopien, kein Suchindex und keine Analytics.
E-Mail-Inhalte sind untrusted; Anweisungen darin werden nicht ausgeführt,
URLs und externe Bilder werden nicht abgerufen.

SQLite speichert Kontometadaten, AES-256-GCM-verschlüsselte Passwörter,
gehashte Setup-Tokens und die Schemaversion. AAD bindet Credentials an
Formatversion und Account-ID; HKDF trennt den Cursorschlüssel. Der Master-Key
liegt separat. Ein kompromittierter laufender Server mit Zugriff auf DB
und Key kann Credentials entschlüsseln.

## Installation und Prüfung

Python >=3.12. Lokal verwendet: Python 3.13.5, MCP 2.0.0.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m pytest
python -m ruff check src tests scripts
python -m mypy src
python scripts/test_mcp.py
```

Der Smoke-Test verwendet ausschließlich temporäre synthetische Daten.
Start: `python -m mocu_imap_mcp.server`.
RuntimeSettings liest Prozess-Environment, keine automatische `.env`-Datei.
Alte Settings/Tool-Registrierung bleiben intern für Protokollregressionen;
der Prozessstart verwendet die Multi-Account-Implementierung.

## Authentifizierung und Freigabe

Separater OAuth/OIDC-Gateway und ein Keycloak-Referenzprofil sind implementiert.
Installation: [AUTH_DEPLOYMENT](docs/AUTH_DEPLOYMENT.md).
Auch unter einem bestehenden nginx-/PHP-Host möglich, z. B. `/imap/`:
[Unterordner-Deployment](docs/AUTH_DEPLOYMENT.md#unterordner-auf-einem-bestehenden-nginx-php-host).
Nachweise und noch erforderliche Live-Abnahme: [AUTH_ACCEPTANCE](docs/AUTH_ACCEPTANCE.md).
Der Connector implementiert keinen OAuth-Authorization-Server.

- `ACCESS_MODE=local`: lokale Mailzugriffe erlaubt, administrative Tools und
  Setup gesperrt. Nicht als Authentifizierung vor einem öffentlichen Proxy verwenden.
- `ACCESS_MODE=trusted_proxy`: nur explizite direkte Peer-IP-Adressen aus
  `TRUSTED_PROXY_IPS` dürfen verifizierte Issuer-, Subject-, Role-, Scope- und
  Auth-Type-Header liefern. Unbekannte Peers/Rollen
  werden abgewiesen. Kein Vertrauen in X-Forwarded-For.
- Proxy muss Identity-Header aus externen Requests ersetzen, OAuth-Tokens
  prüfen und administrative Browser-Sessions authentifizieren. Leser dürfen
  alle aktivierten Konten lesen; Admin-Rechte autorisieren lokale Änderungen.
- `compose.auth.yaml` verdrahtet zwei interne Auth-Verifier mit nginx.
  TLS oder ein Tunnel allein ersetzen keine administrative Autorisierung.
- ChatGPT benötigt den offiziell unterstützten MCP-OAuth-Weg am Gateway,
  einschließlich Discovery und Token-Verifikation. Das ist vom IMAP-Passwort
  getrennt. Keine selbst erfundenen Tunnel-Kommandos einsetzen.

Offizielle Quellen, geprüft am 2026-10-21:
[OpenAI MCP-Authentifizierung](https://developers.openai.com/plugins/build/auth),
[cryptography AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM).

## Docker auf Debian

Runtime-Abhängigkeiten sind in `requirements.lock` fixiert. Basisimage:
Python 3.13 slim. Keine Credentials im Build; `.dockerignore` lässt nur
explizite Projektdateien zu. Image läuft als UID/GID 10001, Root-Dateisystem
read-only, keine Capabilities, kein Docker-Socket. Nur /data persistent
beschreibbar, /tmp als begrenztes tmpfs.

Master-Key einmalig außerhalb des Checkout anlegen. Das Beispiel überschreibt
keinen existierenden Key und gibt ihn nicht aus:

```bash
sudo install -d -m 0700 /etc/mocu-imap-mcp
sudo python3 - <<'PY'
import base64, os, secrets
fd = os.open('/etc/mocu-imap-mcp/master.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
with os.fdopen(fd, 'wb') as stream:
    stream.write(base64.urlsafe_b64encode(secrets.token_bytes(32)))
os.chown('/etc/mocu-imap-mcp/master.key', 10001, 10001)
PY
export MOCU_MASTER_KEY_HOST_FILE=/etc/mocu-imap-mcp/master.key
export PUBLIC_BASE_URL=https://imap-mcp.example.at
export OIDC_ISSUER=https://auth.example.at/realms/mocu
# Tatsächliche direkte Proxy-IP als JSON-Liste einsetzen:
export TRUSTED_PROXY_IPS='["127.0.0.1"]'
docker compose build
docker compose up -d
docker compose ps
curl --fail http://127.0.0.1:8765/healthz
```

Compose-Secrets sind Dateimounts. Host-Dateirechte schützen die Quelldatei;
UID 10001 muss sie im Container lesen können. Benanntes Volume wird mit UID
10001 initialisiert. Bei Host-nginx vor Docker ist der direkte Peer oft eine
Bridge-Adresse: konkret ermitteln, keine ganzen privaten Netze vertrauen.
Host-Port bleibt auf 127.0.0.1. Domain/Allowlist in Compose anpassen.
Health enthält keine Kontodaten; Readiness prüft SQLite ohne IMAP-Login.

## Alternative systemd

Bei bereits vorhandenem Service-User die useradd-Zeile überspringen:

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin mocu-imap-mcp
sudo install -d -m 0755 /opt/mocu-imap-mcp
sudo cp -a src pyproject.toml README.md requirements.lock /opt/mocu-imap-mcp/
sudo python3 -m venv /opt/mocu-imap-mcp/.venv
sudo /opt/mocu-imap-mcp/.venv/bin/pip install -r /opt/mocu-imap-mcp/requirements.lock
sudo /opt/mocu-imap-mcp/.venv/bin/pip install --no-deps /opt/mocu-imap-mcp
sudo install -m 0600 deploy/mocu-imap-mcp.env.example /etc/mocu-imap-mcp.env
sudoedit /etc/mocu-imap-mcp.env
sudo install -m 0644 deploy/mocu-imap-mcp.service /etc/systemd/system/mocu-imap-mcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now mocu-imap-mcp
```

Master-Key vorher separat erzeugen. Für systemd Datei und Verzeichniszugriff
dem Benutzer mocu-imap-mcp gewähren, nicht UID 10001 aus Docker voraussetzen.
StateDirectory erstellt das geschützte DB-Verzeichnis. Keine Key-Werte im
Environment. Docker und systemd nicht gleichzeitig auf demselben Port betreiben.

## Konfiguration, Migration und Einrichtung

Beispiele: `.env.example`, `deploy/mocu-imap-mcp.env.example`.
Listenfelder verwenden JSON. Alte `IMAP_USERNAME`, `IMAP_PASSWORD`,
`IMAP_HOST`, `IMAP_PORT`, `CURSOR_SIGNING_KEY` und
`CURSOR_SIGNING_KEY_HEX` entfernen. Der neue Start weist sie ab.
Kein automatischer Credential-Import. Alte Cursor und Ressourcen neu erzeugen.

Nach Einrichtung des geschützten Admin-Zugangs:

1. `begin_account_setup()` liefert einen zehn Minuten gültigen HTTPS-Link.
2. Formular in der authentifizierten Admin-Session öffnen; Zugangsdaten dort eingeben.
3. TLS-Verbindung und LIST werden geprüft, dann das Konto verschlüsselt gespeichert.
4. `list_accounts()` liefert IDs; `get_account_status(account_id)` prüft den Login.
5. `begin_account_setup(account_id)` aktualisiert nach erfolgreicher Prüfung
   Kontokonfiguration und Passwort. Fehler erhalten das bisherige Konto.
6. `set_account_enabled(account_id, false)` deaktiviert,
   `delete_account(account_id)` entfernt nur lokale Konfiguration. Beide verlangen Admin-Rechte.

Tokenbesitz allein reicht nicht: dieselbe Admin-Identität (Issuer + Subject),
Browser-Session und CSRF-/Origin-Prüfung sind erforderlich. Migration auf DB-Schema 2
invalidiert alte ungebundene Setup-Tokens, erhält aber verschlüsselte Accounts.
Drei Verbindungsversuche pro Token, atomare Claims. Abgebrochene Claims bleiben
bis Ablauf gesperrt. Setup-Tokenpfade werden nicht in Access-Logs geschrieben.
Rate-Limit am vorgeschalteten Proxy aktivieren; Beispiel enthält Setup-Limits.

GMX: imap.gmx.net, 993, SSL. IMAP im Konto aktivieren und anwendungsspezifisches
Passwort verwenden. **Passwort niemals in ChatGPT eingeben.** Private,
Loopback-/Link-Local-Ziele und andere Ports sind gesperrt. DNS-IP-Prüfung
und Socket-Verbindung verwenden dieselben Adressen; TLS prüft den Hostnamen.

Manueller Test nach Einrichtung und mit gesetztem Runtime-Environment:

```bash
python scripts/test_imap_connection.py ACCOUNT_UUID
```

## Mailzugriff und Suche

```text
find_invoice_candidates(date_from="2025-01-01", date_to="2025-12-31")
search_emails(account_ids=["ACCOUNT_UUID"], subject="Rechnung März", limit=50)
get_email(account_id, mailbox, uidvalidity, uid, include_body=true)
list_attachments(account_id, mailbox, uidvalidity, uid)
get_attachment(account_id, mailbox, uidvalidity, uid, part_id)
```

Ohne Account-Auswahl: alle aktivierten Konten. Treffer tragen Account-ID und
UIDVALIDITY. Weiter mit Cursor und identischen Suchparametern; Cursor läuft nach
einer Stunde ab. Standard 50, Maximum 100 Treffer. Bei Scan-/Zeitbudgetende:
scan_budget_exhausted=true und ggf. weniger Treffer, Fortsetzung per Cursor.
Zeitbudget wird zwischen Nachrichten geprüft; einzelne IMAP-Kommandos haben
einen eigenen Timeout. Account-/Mailbox-Planung liegt vor der Scanphase.

Fehlende Ordner und ausgefallene Konten werden nicht still übersprungen.
Änderungen der Kontenauswahl erfordern eine neue Suche. UIDVALIDITY-Wechsel
macht Mailreferenzen ungültig. MIME-Ressourcen enthalten Account-ID und
UIDVALIDITY; manipulierte MIME-Prefixe werden abgewiesen. Suche lädt Header/
BODYSTRUCTURE, Body-Lesen nur Textparts, Attachment-Zugriff nur den gewünschten
Part. Hashes werden beim Auflisten nicht durch Download berechnet.
Rechnungskandidaten sind keine Klassifikation; Auswertung übernimmt ChatGPT.

## Backup, Restore und Key-Rotation

Dienst stoppen. SQLite konsistent sichern; Key separat sichern. Nicht beides
im selben unverschlüsselten Archiv aufbewahren. Keine laufende WAL-Hauptdatei
isoliert kopieren. Backup-Pfade dürfen noch nicht existieren.

```bash
python scripts/manage_storage.py backup --service-stopped --backup /safe/backup/mocu.sqlite3
python scripts/manage_storage.py rotate --service-stopped --backup /safe/backup/pre-rotation.sqlite3 --new-key-file /safe/keys/new.key
```

Neuen Key vorher separat erzeugen. Rotation erfolgt transaktional und ohne
Klartext-Zwischenexport; Fehler vor Commit erhalten die alten Daten.
Nach Erfolg Secret-Mount auf neuen Key ändern und neu starten. Alte Cursor
werden ungültig. Rollback nach Commit: zusammengehörige alte DB und alten
Key bei gestopptem Dienst wiederherstellen, Rechte prüfen. Start prüft alle
gespeicherten Credentials und scheitert mit falschem Key.

## Einschränkungen

Live-ChatGPT-Anbindung und echte Testpostfächer müssen beim Betreiber noch
abgenommen werden. Keycloak Resource Indicators sind experimentell.
Kein internes Netz als IMAP-Ziel, keine automatische
Key-Verwaltung, keine mehreren Replikate auf derselben SQLite-Datenbank.
