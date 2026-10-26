# Debian: Installation neben einer vorhandenen nginx-/PHP-Seite

Für eine neue Installation unter `https://admin.example.at/imap/`. In allen
Beispielen `admin.example.at` durch die eigene Domain ersetzen. Die bestehende
Webseite und deren Zertifikatspfade werden nicht überschrieben. Die Anleitung
setzt nginx mit gültigem HTTPS-Zertifikat, Docker mit Compose v2, sudo und
Python >=3.12 voraus. Bereits vorhandene Docker-/Webserver-Installationen nicht
durch andere Pakete ersetzen. Bei einer bestehenden MoCu-Installation stattdessen
deren Konfiguration, Master-Key und Datenvolumes weiterverwenden.

## 1. Voraussetzungen und Checkout

```bash
cat /etc/os-release
python3 --version
docker compose version
sudo nginx -t
```

Falls Python zu alt ist oder Compose fehlt, hier anhalten und die Voraussetzung
gezielt herstellen. Danach auf dem Zielserver:

```bash
set -e
python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python >=3.12 erforderlich"'
sudo apt-get update
sudo apt-get install --no-upgrade git python3-venv acl ca-certificates
sudo git clone --branch develop https://github.com/informatrixx/MoCuIMAPconnector.git /opt/mocu-imap-mcp
cd /opt/mocu-imap-mcp
sudo python3 -m venv .venv
sudo .venv/bin/python -m pip install -r requirements.lock
sudo .venv/bin/python -m pip install --no-deps -e .
sudo .venv/bin/python -m pip check
```

Der Containerprozess läuft als UID/GID 10001. Auf dem Host wird dafür kein
zusätzlicher root-Service angelegt. Kein IMAP-Passwort in Shell oder Chat eingeben.

## 2. Öffentliche Konfiguration

Diese Befehle sind für eine neue, leere Installation. Existiert eine Zieldatei
bereits, anhalten und prüfen; keine vorhandenen Keys oder Accounts ersetzen.

```bash
set -e
sudo install -d -m 0700 /etc/mocu-auth /etc/mocu-auth/config /etc/mocu-auth/secrets /etc/mocu-auth/tls
sudo test ! -e /etc/mocu-auth/public.env
sudo test ! -L /etc/mocu-auth/public.env
sudo install -m 0600 deploy/auth/subpath.env.example /etc/mocu-auth/public.env
python3 -c 'import uuid; print(uuid.uuid4())'
sudoedit /etc/mocu-auth/public.env
```

Die ausgegebene UUID als feste Operator-Subject-ID aufbewahren und in **beiden**
Listen `ALLOWED_SUBJECTS` und `ADMIN_SUBJECTS` einsetzen. Später bei
`--initial-subject` dieselbe UUID verwenden. Die öffentlichen URLs müssen lauten:

```dotenv
PUBLIC_BASE_URL=https://admin.example.at/imap
MCP_HOST=admin.example.at
AUTH_HOST=admin.example.at
OIDC_BASE_URL=https://admin.example.at/imap/oidc
OIDC_ISSUER=https://admin.example.at/imap/oidc/realms/mocu
AUTH_LISTEN_IP=127.0.0.1
AUTH_HTTPS_PORT=8443
```

`CHATGPT_REDIRECT_URI` muss die exakte Redirect-URI der tatsächlichen
ChatGPT-Verbindung enthalten. Keine pauschale Callback-Adresse annehmen; siehe
[offizielle OpenAI-Authentifizierung](https://developers.openai.com/plugins/build/auth#protect-callbacks-with-issuer-identification).
Die übrigen Werte der Beispieldatei prüfen, insbesondere einen freien Docker-
Adressbereich und freien Loopback-Port 8443. Alle Dateien bleiben außerhalb des Git-Checkouts.

## 3. Secrets und Operator-Anmeldung

```bash
sudo python3 - <<'PY'
import base64
import getpass
import os
import secrets
from pathlib import Path

root = Path('/etc/mocu-auth/secrets')
names = ('master_key', 'provider_db', 'admin_client', 'chatgpt_client', 'initial_user')
if any((root / name).exists() or (root / name).is_symlink() for name in names):
    raise SystemExit('Vorhandene Secrets gefunden; Einrichtung anhalten und pruefen')
password = getpass.getpass('Neues Loginpasswort fuer den MoCu-Operator (nicht IMAP): ')
if len(password) < 16:
    raise SystemExit('Mindestens 16 Zeichen erforderlich')
for name in names:
    value = (password.encode() if name == 'initial_user' else
             base64.urlsafe_b64encode(secrets.token_bytes(32)) if name == 'master_key' else
             secrets.token_urlsafe(48).encode())
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value + b'\n')
PY
sudo setfacl -m u:10001:r /etc/mocu-auth/secrets/master_key
sudo setfacl -m u:10001:r,u:1000:r /etc/mocu-auth/secrets/admin_client
sudo setfacl -m u:1000:r /etc/mocu-auth/secrets/chatgpt_client /etc/mocu-auth/secrets/provider_db /etc/mocu-auth/secrets/initial_user
```

## 4. Bestehendes TLS-Zertifikat einbinden

Die tatsächlichen Fullchain-/Key-Pfade aus dem bestehenden nginx-vHost einsetzen.
Die Quelldateien bleiben unverändert. Die inneren Kopien müssen künftig im
Zertifikatserneuerungsablauf aktualisiert und der innere Proxy neu gestartet werden.
Keine Symlinks außerhalb des gemounteten TLS-Verzeichnisses verwenden.

```bash
set -e
read -r -p 'Pfad zur bestehenden TLS-Fullchain: ' MOCU_TLS_CERT
read -r -p 'Pfad zum bestehenden privaten TLS-Key: ' MOCU_TLS_KEY
test -n "$MOCU_TLS_CERT" && test -n "$MOCU_TLS_KEY"
sudo test -f "$MOCU_TLS_CERT" && sudo test -f "$MOCU_TLS_KEY"
sudo test ! -e /etc/mocu-auth/tls/cert.pem
sudo test ! -e /etc/mocu-auth/tls/key.pem
sudo test ! -L /etc/mocu-auth/tls/cert.pem
sudo test ! -L /etc/mocu-auth/tls/key.pem
sudo install -m 0644 "$MOCU_TLS_CERT" /etc/mocu-auth/tls/cert.pem
sudo install -m 0400 "$MOCU_TLS_KEY" /etc/mocu-auth/tls/key.pem
sudo setfacl -m u:101:rx /etc/mocu-auth/tls
sudo setfacl -m u:101:r /etc/mocu-auth/tls/key.pem
```

## 5. Konfiguration erzeugen und internen Stack starten

Domain, Callback und dieselbe Subject-UUID wie in Schritt 2 einsetzen:

```bash
set -e
sudo .venv/bin/python scripts/prepare_auth.py --output /etc/mocu-auth/config \
  --origin https://admin.example.at/imap \
  --issuer https://admin.example.at/imap/oidc/realms/mocu \
  --chatgpt-redirect 'EXAKTE-HTTPS-CALLBACK-URI-AUS-CHATGPT' \
  --initial-user operator --initial-subject 'UUID-AUS-SCHRITT-2'
sudo chmod 0644 /etc/mocu-auth/config/nginx.conf /etc/mocu-auth/config/realm.json
sudo .venv/bin/python scripts/preflight_auth.py --env-file /etc/mocu-auth/public.env
sudo docker compose --env-file /etc/mocu-auth/public.env -f compose.auth.yaml build
sudo docker compose --env-file /etc/mocu-auth/public.env -f compose.auth.yaml \
  -f deploy/auth/compose.bootstrap.yaml up -d
sudo docker compose --env-file /etc/mocu-auth/public.env -f compose.auth.yaml exec -T proxy nginx -t
```

Nach erfolgreichem ersten Realm-Import einmal ohne Bootstrap-Override erstellen:

```bash
sudo docker compose --env-file /etc/mocu-auth/public.env -f compose.auth.yaml up -d
```

Das Initialpasswort ist danach im laufenden Provider gespeichert. Die separate
Bootstrap-Datei sicher verwahren; für weitere Benutzer die private Providerverwaltung
verwenden. Keine Providerdatenbank oder Volumes für einen erneuten Import löschen.

## 6. nginx um zwei Locations ergänzen

```bash
set -e
sudo install -d -m 0755 /etc/nginx/snippets
sudo test ! -e /etc/nginx/snippets/mocu-imap.conf
sudo test ! -L /etc/nginx/snippets/mocu-imap.conf
sudo install -m 0644 deploy/auth/nginx-subpath.frontend.conf.example /etc/nginx/snippets/mocu-imap.conf
sudoedit /etc/nginx/snippets/mocu-imap.conf
```

Im Snippet alle `admin.example.at` durch die eigene Domain ersetzen. Im vorhandenen
HTTPS-`server`-Block dieser Domain genau diese Zeile ergänzen:

```nginx
include /etc/nginx/snippets/mocu-imap.conf;
```

PHP-/Root-Routen und bestehende TLS-Einstellungen beibehalten. Zusätzliche
PHP-Login-Redirects dürfen die neuen MCP-/OIDC-Pfade nicht abfangen. Anschließend:

```bash
sudo nginx -t && sudo systemctl reload nginx
sudo .venv/bin/python scripts/preflight_auth.py --env-file /etc/mocu-auth/public.env --online
```

## 7. ChatGPT und zwei Testpostfächer

MCP-URL: `https://admin.example.at/imap/mcp`, OAuth-Client-ID: `mocu-chatgpt`.
Das Client-Secret aus `/etc/mocu-auth/secrets/chatgpt_client` ausschließlich im
Secret-Eingabefeld der Verbindung hinterlegen, nicht in Chatnachrichten oder Logs.
Exakte Redirect-URI mit der registrierten URI vergleichen. Die dokumentierten
Client-Optionen stehen in der [OpenAI-Anleitung](https://developers.openai.com/plugins/build/plugins).

`https://admin.example.at/imap/` führt zur Operator-Anmeldung. In ChatGPT als
berechtigter Admin `begin_account_setup()` aufrufen und den Einmallink mit demselben
Operator öffnen. Das GMX-App-Passwort erst dort im HTTPS-Formular eingeben.

Mit zwei separaten Testpostfächern Rechnungen von `2025-01-01` bis `2025-12-31`
suchen, eine PDF-Ressource abrufen, unveränderte IMAP-Flags sowie Refresh,
Logout und Zugriffsentzug prüfen. Die eigentliche Rechnungs-/Buchhaltungstabelle
erstellt ChatGPT. Alle freigeschalteten Reader sehen alle aktivierten Konten.
Die Live-Abnahme und Freigabe werden im [Abnahmebericht](AUTH_ACCEPTANCE.md)
getrennt von den automatisierten Tests dokumentiert.
