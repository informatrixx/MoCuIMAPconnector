# Öffentlicher OAuth-Zugang (Review-Profil, kein Release)

Stand 2026-10-21. IMAP bleibt Benutzername/App-Passwort über IMAPS/STARTTLS.
OAuth schützt ausschließlich den Connector. **Alle erlaubten Reader sehen alle
aktivierten Mailkonten dieser Installation. Keine Mandantentrennung.**

## Vertrag und Vertrauensgrenze

- Exakter Identifier: `MCP_RESOURCE=https://imap-mcp.example.at/mcp`.
  Exakter Issuer: `OIDC_ISSUER=https://auth.example.at/realms/mocu`.
  Beide Domains sind Platzhalter, keine live bereitgestellten Dienste.
- Lesend: erlaubtes `(issuer, sub)` und Scope `mocu:read`; administrativ zusätzlich
  `mocu:admin` und Mitgliedschaft in `ADMIN_SUBJECTS`. Scopes allein geben keine Adminrechte.
- Zwei vorregistrierte vertrauliche Clients: `mocu-chatgpt`, `mocu-admin-web`,
  `client_secret_basic`, Authorization Code + PKCE S256. Kein Implicit/Password Grant,
  kein CIMD, keine öffentliche dynamische Registrierung. Exakte ChatGPT-Callback-URI
  aus der jeweiligen Verbindung übernehmen; Admin-Callback separat `/auth/callback`.
- `/mcp` (alle HTTP-/MCP-Methoden und Ressourcen) verlangt Bearer; Cookies zählen nicht.
  Fehlende Authentifizierung ergibt 401 + `WWW-Authenticate` mit `resource_metadata`.
  Reader-Admin-Verstöße geben einen Toolfehler ohne erneute Anmeldung; fehlende Scopes
  ergeben strukturierte `_meta["mcp/www_authenticate"]`-Challenges.
  SDK 2.0 veröffentlicht OAuth-`securitySchemes` im dokumentierten `_meta`-Mirror.
- nginx nutzt intern `/_verify_bearer` → Gateway `/verify/bearer` und
  `/_verify_session` → `/verify/session`, ohne Body. Nur der exakte Proxy-Peer darf
  diese Verifier benutzen. Clientheader werden nicht weitergereicht; explizite
  Transportheader werden neu gesetzt. nginx setzt ausschließlich Verifierwerte für
  `X-Mocu-Issuer`, `X-Mocu-Subject`, `X-Mocu-Role`, `X-Mocu-Scopes`, `X-Mocu-Auth-Type`.
  Connector prüft Peer, Issuer, Vollständigkeit, Duplikate, Auth-Art und Handlerrechte.
  Kein Vertrauen in X-Forwarded-For, kein Bearer-Forwarding zum Connector.
  Beim Setup erhält der Connector nur sein CSRF-Cookie, nicht das Gateway-Session-Cookie.
- `/.well-known/oauth-protected-resource/mcp` ist öffentlich. Health/Readiness und
  Connector/Gateway/DB haben keine öffentlichen Ports. Ausgehendes IMAP bleibt möglich.

## Provider und Versionspins

Keycloak **26.8.1**, nginx **1.30.6**, PostgreSQL **17.11**: immutable Digests in
`compose.auth.yaml` bzw. `deploy/auth/Keycloak.Dockerfile`. Runtime-Dependencies in
`requirements.lock`; Browser-Test Playwright 1.64.0. Kein `start-dev` im Profil;
Keycloak verwendet PostgreSQL mit persistentem Volume, Mailkonten weiterhin SQLite.
Keycloak `resource-indicators` ist **experimentell**. Das Profil konfiguriert
`mocu-resource.attributes.resource_url` und einen Audience-Mapper im ChatGPT-Client.
Ein expliziter `oidc-sub-mapper` stellt das erforderliche Subject auch im Access-Token
bereit; nicht auf implizite Default-Client-Scopes verlassen.
Der Integrationstest verlangt echte Ressourcenbindung bei Code-Austausch und Refresh;
Audience-Prüfung darf niemals abgeschaltet werden. Kein CIMD-Feature aktivieren.

Ein anderer OIDC-Provider ist über `OIDC_ISSUER` und die Clientdaten konfigurierbar.
Erforderlich: RS256-JWT-Access-Tokens, feste Audience, eigener Access-Token-Discriminator
(`ACCESS_TOKEN_TYPE_CLAIM=typ`, `ACCESS_TOKEN_TYPE_VALUE=Bearer` für Keycloak), PKCE,
OIDC-Nonce, `client_secret_basic`. JWKS/Authorization/Token-Endpunkte müssen denselben
HTTPS-Origin wie der konfigurierte Issuer verwenden; externe Discovery-Endpunkte
werden bewusst abgewiesen. Ein anderer Provider braucht dieselbe eigene E2E-Abnahme.

## Sitzungen und Widerruf

Gateway ist ein einzelner Prozess. Transaktionen und Sessions sind ausschließlich
im begrenzten RAM, hinter zufälligen 256-Bit-IDs; kein gemeinsamer IMAP-Schlüssel,
keine signierten Cookie-Nutzdaten, keine Browser-Tokenablage, keine Gateway-Maildatenbank.
Ein Gateway-Neustart invalidiert alle Sessions. Keine Replikation ohne neues Sessiondesign.
`__Host-mocu-session`: Secure, HttpOnly, Path=/, SameSite=Lax, keine Domain.
Transaktion 180 Sekunden, browsergebunden, atomar einmalig; PKCE/Nonce durch Authlib.
Rückkehrpfad nur serverseitig, nicht in Provider-URLs/state. POST wird nie wiederholt.
Formularseiten verwenden `Referrer-Policy: strict-origin`: nur Origin, niemals Pfad
oder Query im Referrer. `no-referrer` führte im echten Chromium-Formular zu
`Origin: null`; dieser wird weiterhin abgewiesen statt die Origin-Prüfung abzuschalten.

`SESSION_IDLE_SECONDS=180`, `SESSION_ABSOLUTE_SECONDS=300` (maximal 300): spätestens
nach fünf Minuten erneuter OIDC-Login, kein Session-Refresh im Hintergrund. Gateway-
Allowlist-Änderungen durch Neustart anwenden (alle Sessions weg). Providerdeaktivierung
beendet bereits ausgestellte Sessions/Tokens nicht sofort. Referenz-Access-Tokens
leben 300 Sekunden. Provider-SSO-Session bei Sperrung ebenfalls widerrufen.
Keine Behauptung sofortiger JWT-Revocation.

`JWKS_CACHE_SECONDS=300`, max. 600; unbekanntes kid löst höchstens alle
`JWKS_REFRESH_SECONDS=30` einen Fetch aus. Gültige gecachte Keys gelten bis Cacheablauf;
danach Fehler statt Fail-open. HTTP Connect/Read 3/5 Sekunden, 256 KiB-Antwortlimit,
10-Sekunden-Prüfbudget zwischen Chunks, max. 32 Keys. Token-`jku`/`x5u` werden ignoriert.
Keine Access-/Fehler-URL-Logs in nginx, keine Gateway-HTTP-Debuglogs. Statusbasierte
Health-Probes ersetzen URL-Logs. Kein Shell-Tracing oder Request-/Formularlogging aktivieren.

## Betreiberablauf auf Debian

Voraussetzungen: Docker Engine/Compose, Python >=3.12, zwei eigene DNS-Namen,
gültige TLS-Kette mit beiden Namen (oder eigenes nginx-Zertifikatsrouting), sichere
Provider-Benutzerverwaltung. Vorher Backup der SQLite-DB plus separat Master-Key;
Migration auf Schema 2 invalidiert nur ungebundene Setup-Tokens, nicht Accounts.

Im Checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.lock
pip install --no-deps -e .
sudo install -d -m 0700 /etc/mocu-auth /etc/mocu-auth/secrets /etc/mocu-auth/config
sudo install -d -m 0755 /etc/mocu-auth/tls
sudo install -m 0600 deploy/auth/public.env.example /etc/mocu-auth/public.env
sudoedit /etc/mocu-auth/public.env
```

Domains/Issuer, unbenutztes Subnetz, exakte Callback-URI und unveränderliche Subject-IDs
eintragen. Allowlist nicht aus Benutzernamen oder editierbarem Profil ableiten.
Für eine frische Referenzinstallation eine feste Subject-ID mit `uuidgen` erzeugen,
in beide Listen und `--initial-subject` übernehmen. Für vorhandene Provider die dortige
unveränderliche ID verwenden. Bis dahin geschlossen lassen. `AUTH_PROXY_IP` außerhalb
`AUTH_DYNAMIC_RANGE` reservieren. `AUTH_LISTEN_IP=127.0.0.1` beibehalten bis zur Freigabe;
für direkte öffentliche Bereitstellung später bewusst Host-IP und Port 443 eintragen.

Secrets einmalig erzeugen (keine Ausgabe, keine Überschreibung):

```bash
sudo python3 - <<'PY'
import base64, os, secrets
from pathlib import Path
root = Path('/etc/mocu-auth/secrets')
for name in ('master_key', 'provider_db', 'admin_client', 'chatgpt_client'):
    value = base64.urlsafe_b64encode(secrets.token_bytes(32)) if name == 'master_key' else secrets.token_urlsafe(48).encode()
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, 'wb') as file:
        file.write(value + b'\n')
PY
```

Bei bestehender Installation **vorhandenen Master-Key verwenden**, keinen neuen
für vorhandene Accounts erzeugen! Gezielte Leserechte mit ACLs setzen (Paket `acl`):

```bash
sudo setfacl -m u:10001:r /etc/mocu-auth/secrets/master_key
sudo setfacl -m u:10001:r,u:1000:r /etc/mocu-auth/secrets/admin_client
sudo setfacl -m u:1000:r /etc/mocu-auth/secrets/chatgpt_client
sudo setfacl -m u:1000:r /etc/mocu-auth/secrets/provider_db
```

Postgres-Entrypoint liest DB-Secret als root. Keine Secrets in Compose-Environment,
CLI-Argumenten, Chat oder Repository. Keycloak liest seine drei gemounteten Secrets
im Entrypoint, exportiert sie nur intern und importiert die Realm-Platzhalter.
Gateway erhält nur Admin-Client-Secret, Connector nur Master-Key.

TLS-Kette als `/etc/mocu-auth/tls/cert.pem`, Key als `key.pem` bereitstellen;
bestehende Zertifikate nicht überschreiben. Key nur für nginx UID 101 lesbar machen.
Die Datei `AUTH_CA_FILE` enthält CA-Trust (öffentliches Debian-Bundle oder eigene CA),
niemals TLS-Verifikation deaktivieren. Interne Netzwerkaliases leiten beide Namen
zum Proxy; URLs/Issuer bleiben überall identisch.

```bash
# Tatsächliche Werte aus public.env einsetzen, keine Platzhalter übernehmen:
sudo .venv/bin/python scripts/prepare_auth.py --output /etc/mocu-auth/config \
  --origin https://imap-mcp.example.at --issuer https://auth.example.at/realms/mocu \
  --chatgpt-redirect 'https://EXAKTE-CALLBACK-URI-AUS-DER-VERBINDUNG' \
  --initial-user operator --initial-subject 'VORHER-ERZEUGTE-FESTE-SUBJECT-ID'
sudo chmod 0644 /etc/mocu-auth/config/nginx.conf /etc/mocu-auth/config/realm.json
sudo .venv/bin/python scripts/preflight_auth.py --env-file /etc/mocu-auth/public.env
sudo docker compose --env-file /etc/mocu-auth/public.env -f compose.auth.yaml build
```

Bei einer **neuen, leeren Providerdatenbank** kann das Referenzprofil einen gewöhnlichen
Loginbenutzer importieren. Er bekommt keinerlei Keycloak-Adminrolle; Connector-Adminrechte
stammen ausschließlich aus der Subject-Allowlist. Passwort verdeckt in separate Datei
eingeben (nicht das IMAP-Passwort, kein Standardpasswort):

```bash
sudo python3 - <<'PY'
import getpass, os
password = getpass.getpass('Neues Provider-Loginpasswort: ')
if len(password) < 16:
    raise SystemExit('Mindestens 16 Zeichen erforderlich')
fd = os.open('/etc/mocu-auth/secrets/initial_user', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
with os.fdopen(fd, 'w') as stream:
    stream.write(password + '\n')
PY
sudo setfacl -m u:1000:r /etc/mocu-auth/secrets/initial_user
sudo docker compose --env-file /etc/mocu-auth/public.env -f compose.auth.yaml \
  -f deploy/auth/compose.bootstrap.yaml up -d
sudo docker compose --env-file /etc/mocu-auth/public.env -f compose.auth.yaml exec -T proxy nginx -t
```

Nach erfolgreichem Erstimport ohne Bootstrap-Override neu erstellen:
`sudo docker compose --env-file /etc/mocu-auth/public.env -f compose.auth.yaml up -d`.
Die Importdatei enthält nur einen Environment-Platzhalter, kein Loginpasswort.
Das separate Bootstrap-Secret danach aus dem Deployment entfernen und sicher verwahren.
Für weitere Providerbenutzer oder MFA die private Providerverwaltung verwenden.
Bei vorhandener Providerdatenbank nicht erneut importieren oder Volumes löschen.

`compose.auth.yaml` ist **eigenständig**, nicht mit `compose.yaml` zusammenführen.
Provider-Bootstrap über eine private Admin-Verbindung nach offizieller
[Keycloak-Anleitung](https://www.keycloak.org/server/bootstrap-admin-recovery):
alle Keycloak-Prozesse vor `bootstrap-admin` stoppen, dieselben DB-Optionen verwenden,
Passwort verdeckt eingeben bzw. aus separater Secret-Datei laden. Keine Master-Realm-
Adminoberfläche öffentlich freischalten. Temporären Bootstrap-Admin danach entfernen;
die Connector-Benutzer selbst bekommen keine Keycloak-Administrationsrollen.
Bei vorhandener kompatibler Providerinstallation diese getrennte Bootstraparbeit entfällt.
Realm-Import gilt nur initial; spätere Client-/Benutzeränderungen über Providerverwaltung,
nicht durch Löschen des persistenten DB-Volumes.

## ChatGPT und Postfächer

In der Verbindungsverwaltung den eigenen `/mcp`-Endpoint und vorregistrierten OAuth-
Client konfigurieren. Aktuelle Oberfläche und exakte Callback-URI aus der Verbindung
übernehmen; Client-ID `mocu-chatgpt`, Methode `client_secret_basic`. Secret ausschließlich
im dafür vorgesehenen Secret-Eingabefeld, nie in einer Chatnachricht. Keine universelle
Callback-URL annehmen. [Offizielle Auth-Dokumentation](https://developers.openai.com/plugins/build/auth)
und [Provided-Client-Konfiguration](https://developers.openai.com/plugins/build/plugins).

Nach bewusstem öffentlichen Routing: `preflight_auth.py --env-file ... --online`.
Reader- und Admin-Anmeldung getrennt prüfen, Refresh nachweisen. Als Admin
`begin_account_setup()` öffnen, mit demselben Providerbenutzer anmelden, im HTTPS-
Formular zwei Testpostfächer konfigurieren. GMX-App-Passwort nur dort eingeben.
Suche/UIDVALIDITY/PDF-Ressource über beide Konten und unveränderte IMAP-Flags prüfen.
Logout unter `/auth/session`; Setup-Link ist zehn Minuten/einmalig/drei Versuche gültig.
Fremder Admin darf ihn nicht konsumieren.

## Reproduzierbare lokale Abnahme

```bash
pip install -e '.[dev]'
python -m pytest
python -m ruff check src tests scripts
python -m mypy src
python scripts/test_mcp.py
python scripts/test_auth_e2e.py
git diff --check
```

E2E baut echte Container und Chromium, verwendet synthetische Benutzer, PKCE-Code-
Austausch/Refresh und testet die reale Proxy-Grenze. Kein Password Grant. Temporäres
Testzertifikat wird von Backend-HTTP-Clients verifiziert; nur der Testbrowser akzeptiert
das selbstsignierte Zertifikat. Keine Produktionsschalter werden dafür gelockert.
Alle temporären Ressourcen sind einem zufälligen Compose-Projekt zugeordnet und
werden im `finally` entfernt; keine globalen Prunes. Docker-/Build-Fehler bleiben Fehler.
Remote CI und Live-ChatGPT/IMAP sind separate Nachweise; siehe AUTH_ACCEPTANCE.
