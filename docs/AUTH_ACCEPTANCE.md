# Auth-Abnahmeprotokoll

## Unterordner-Profil vom 2026-10-26

Der Kryptografie-Testfix wurde als `026838ff4ff5e9963691bbc9542372d32eda22ad`
über [PR #2](https://github.com/informatrixx/MoCuIMAPconnector/pull/2) nach `develop`
gemergt. Alle sechs Jobs des anschließenden
[CI-Laufs 40279722938](https://github.com/informatrixx/MoCuIMAPconnector/actions/runs/40279722938)
zu `d6f1469b93c75a2599a304f48bd7ac1eba074e30` sind **PASS**.

Auf dieser Basis ergänzt das Unterordner-Profil einen konfigurierten HTTPS-Basispfad,
z. B. `/imap`. Connector und Keycloak können denselben Host verwenden; der Provider
liegt dann unter `/imap/oidc`. Rückkehrziele, Setup-Links, Logout und OAuth-Callbacks
behalten den Präfix. Die Metadata-URL folgt RFC 9728, die CSRF-Prüfung verwendet
weiterhin ausschließlich die tatsächliche HTTP-Origin ohne Pfad. Mehrdeutige
Pfade und überlappende Provider-Routen werden abgewiesen.

Das Frontend-Beispiel ergänzt zwei Locations im bestehenden nginx-/PHP-vHost;
das Compose-Profil bleibt an Loopback gebunden. HTTPS zwischen Frontend und
innerem Proxy wird mit Zertifikatsprüfung verwendet. Die reale Betreiberumgebung
wurde noch nicht verändert. Einrichtung und Grenzen stehen in
[AUTH_DEPLOYMENT](AUTH_DEPLOYMENT.md#unterordner-auf-einem-bestehenden-nginx-php-host).

Lokal für diesen Unterordner-Diff am 2026-10-26: **199 Tests**, Ruff, mypy,
MCP-Smoke sowie vollständiger Keycloak-/nginx-/Chromium-E2E für das bisherige
Zwei-Host-Profil und das neue gemeinsame `/imap/`-Profil erfolgreich.
Zusätzlich wurde das Frontend-nginx-Beispiel zusammen mit einer bestehenden
Root-Location per echtem `nginx -t` geprüft. Keine echten Mailkonten verwendet;
Testressourcen und temporäre synthetische Secrets wurden bereinigt.

## Nachtrag 2026-10-26: sporadischen Kryptografie-Test korrigieren

Basis: `develop` nach Merge von PR #1, Commit
`8c8db2b87a5fe516a68cb29812534c7c11b2f1b6`.
Die Review-CI zu `49a279ea65fd862ac99f378daf01ca2937fb0ae3` war vollständig grün;
PR #1 wurde nach `develop` gemergt. Der anschließende
[Merge-CI-Lauf 39676556882](https://github.com/informatrixx/MoCuIMAPconnector/actions/runs/39676556882)
war **FAIL**: Docker und Auth-E2E erfolgreich, Python 3.13/latest mit einem
fehlgeschlagenen Test, zwei weitere Matrixjobs durch fail-fast abgebrochen.

Ursache: Der Manipulationstest ersetzte das erste zufällige Chiffretext-Byte durch
`x`. War es bereits `x`, blieb der gesamte Chiffretext unverändert und wurde
korrekt entschlüsselt; der Test erwartete dennoch einen Fehler. Eine feste,
ausschließlich synthetische Nonce reproduziert diesen Fall zuverlässig und ließ
den alten Test vor der Korrektur fehlschlagen.

Die Korrektur kippt garantiert ein Bit statt ein möglicherweise identisches Byte
einzusetzen. Zusätzlich werden Veränderungen von Nonce und Authentifizierungs-Tag
geprüft; Tests für fremde Account-ID und falschen Schlüssel bleiben erhalten.
Produktiver Verschlüsselungs- und Authentifizierungscode ist unverändert.

Lokale Nachweise am 2026-10-26 mit Python 3.13.5 für diesen Korrektur-Diff:

| Prüfung | Ergebnis |
|---|---|
| pytest | PASS, 184 Tests |
| Manipulationsprüfung wiederholt | PASS, 1000 zufällige und 1000 feste Regressionfälle |
| Ruff / mypy / MCP-Smoke / `git diff --check` | PASS |

Die GitHub-CI des Korrektur-PRs und des anschließenden Merge-Commits muss separat
vollständig grün sein. Die oben genannten lokalen Ergebnisse behaupten keinen
Remote-CI-Erfolg. Die tatsächlichen Läufe sind unter
[GitHub Actions](https://github.com/informatrixx/MoCuIMAPconnector/actions/workflows/ci.yml)
für den jeweiligen Commit nachvollziehbar.

Live-ChatGPT, echte IMAP-Testkonten, Rechnungen/PDFs aus 2025, unveränderte
Postfach-Flags sowie Live-Entzug und Token-Erneuerung bleiben **NOT RUN**.
Für die Live-Abnahme werden die Betreiber-Domains, TLS-/OIDC-Konfiguration und
separate Testpostfächer benötigt. Passwörter ausschließlich im HTTPS-Setup
eingeben. Der Ablauf steht in der manuellen Checkliste unten und in
[AUTH_DEPLOYMENT](AUTH_DEPLOYMENT.md). Alle freigeschalteten Reader sehen alle
aktivierten Konten; Keycloak Resource Indicators bleiben experimentell.

## Historisches Closeout-Protokoll vom 2026-10-21 (vor Commit und Push)

Die folgenden Angaben zu ausstehendem Commit, Push, Merge und Remote-CI beschreiben
den damaligen Prüfzeitpunkt. Den späteren Merge und CI-Befund dokumentiert der Nachtrag oben.

Review-Baseline: `453335ec6fcb1759c697c661c4b06205dda2b4d3`.
Geprüfter Arbeitsstand: diese Baseline plus uncommitteter Auth-Review-Closeout-Diff
(CI-Projektinstallation, Fehlerklassifizierung, Regressionstests und dieses Protokoll).
Arbeitsbranch: `feature/public-auth-e2e`. Prüfdatum: 2026-10-21.
Kein Commit, Push, Merge, Release oder produktives Deployment im Closeout-Auftrag.

## Historischer Remote-Befund – nicht der korrigierte Arbeitsstand

Der [GitHub-Lauf 39579358078](https://github.com/informatrixx/MoCuIMAPconnector/actions/runs/39579358078)
vom 2026-10-21 zu `453335ec6fcb1759c697c661c4b06205dda2b4d3` ist **FAIL**:
fünf erfolgreiche Jobs (vier Python-/Dependency-Kombinationen und Docker),
ein fehlgeschlagener Auth-E2E-Job. Jobstatus und Commit wurden erneut über GitHub geprüft.
Der Review meldete dort `ModuleNotFoundError: No module named 'mocu_imap_mcp'`.
Lokal wurde die Ursache in einer frischen venv nachvollzogen: `requirements.lock`
allein installiert die Anwendung nicht. Die ursprünglichen 165 lokalen Tests und
der damalige lokale E2E-Erfolg waren kein Beleg für die fehlende CI-Projektinstallation.

## Korrekturen und Fehlervertrag

- Der Auth-E2E-Job installiert zuerst `requirements.lock`, danach das Projekt mit
  `python -m pip install --no-deps -e .`; `pip check` und ein expliziter Import
  müssen vor dem vollständigen Integrationstest erfolgreich sein. Keine Importpfad-Umgehung.
- Ohne Bearer-Anmeldung: HTTP 401 mit `resource_metadata`, ohne `error`,
  `error_description` oder Scope-Behauptung. Ein nicht unterstütztes Auth-Schema
  bleibt abgelehnt und erhält ebenfalls nur die Discovery-Challenge.
- Ungültige, abgelaufene, falsch signierte, fremde oder ID-Tokens: HTTP 401 mit
  `error="invalid_token"`. Mehrdeutige Header bleiben abgelehnt. Verifikation bei
  Providerfehlern bleibt fail-closed und fordert keinen zusätzlichen Scope an.
- Zugelassenes Subject ohne `mocu:read`: HTTP 403 mit `insufficient_scope` und
  `scope="mocu:read"`. Nicht freigeschaltete Subjects: HTTP 403 ohne Challenge.
- Reader erhalten für Admin-Tools weiterhin einen Berechtigungsfehler ohne Reauth.
  Autorisierte Admins ohne `mocu:admin` erhalten weiterhin den MCP-Toolfehler mit
  `_meta["mcp/www_authenticate"]` und explizitem `insufficient_scope` für `mocu:admin`.
- Browserfehler enthalten keine Bearer-Challenge; Setup-POSTs ohne Sitzung bleiben
  HTTP 401 ohne Redirect oder automatische Wiederholung. Cookies ersetzen keinen Bearer-Token.
- nginx übernimmt 401-Challenges bereits durch `auth_request`; 403-Challenges kommen
  aus der bestehenden benannten Fehler-Location. Kein zusätzlicher 401-Header wurde ergänzt.
  Der echte Proxy-Test prüft Status, exakten Inhalt und genau einen Header.

Grundlagen: [RFC 6750, Abschnitte 3/3.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1)
und [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

## Lokale Nachweise

- Unit-/HTTP-Tests umfassen JWT-Signatur/Claims/Token-Art, JWKS-Ausfall/Rotation,
  Peer-/Headervertrauen, Scope-Challenges ohne Reader-Reauth-Schleife, Context-Isolation,
  Setup-Erstellerbindung und Schema-Migration mit Erhalt der verschlüsselten Accounts.
- Browser-State-Tests umfassen falschen State, Fehlercallback/Replays, Nonce,
  Return-Targets, Sessionfixierung, Idle-/Absolute-Timeout und CSRF-Logout.
- Bestehende MIME-/UID-/Cursor-/Crypto-/IMAP-Regressionsprüfungen bleiben erhalten;
  Testfixtures übergeben jetzt explizite Identitäten, keine Produktionsauth-Ausnahme.
- Container-E2E verwendet echten Keycloak 26.8.1 + PostgreSQL, nginx und Chromium.
  Der Test muss Discovery/401, Code+PKCE, Refresh, Ressourcenbindung, falschen Verifier,
  ID-Token-Ablehnung, Reader/Admin, Browser-Setup, fremden Admin und Logout bestehen.
  IMAP-Providerzugänge werden dabei nicht verwendet.

Ausgeführt am 2026-10-21 unter Linux mit Python 3.13.5, Docker Engine
26.1.5+dfsg1 und Docker Compose 2.26.1-4, für den oben benannten Arbeitsstand:

| Prüfung | Ergebnis |
|---|---|
| pytest (einschließlich bisheriger Regressionen) | PASS, 183 Tests; davon 45 Auth-Tests |
| Ruff / mypy / `git diff --check` | PASS |
| MCP-Smoke | PASS, 11 Tools / 12 Resource-Templates |
| `docker build -t mocu-imap:multi-account-review .` + `scripts/test_docker.py` | PASS; non-root, read-only, Secret-Mount, Health, Persistenz |
| Frische venv: Locked-Abhängigkeiten, `--no-deps -e .`, `pip check`, Import | PASS |
| Vollständiger `scripts/test_auth_e2e.py` aus dieser frischen venv | PASS, Exit 0; kein Test ausgelassen |
| Compose-Builds Connector / Gateway / Keycloak / Chromium-Runner | PASS |
| Konfigurations-Preflight / echtes `nginx -t` | PASS |
| Echter Code-Flow + PKCE + Refresh / negative Ressourcen- und Verifierprüfungen | PASS |
| Exakte HTTP-401/403-Challenges, keine doppelten Header, Header-Spoofing, Reader/Admin, ID-Token-Ablehnung | PASS |
| Browser-Setup, fremder Admin/Reader, Origin/CSRF, Logout | PASS |
| Gateway-Ausfall / Containerlog-Secretprüfung | PASS |

Der echte Browsertest deckte zusätzlich zwei Integrationsdetails auf: Keycloak
benötigt den expliziten Subject-Mapper für Access-Tokens; Chromium sendet mit
`no-referrer` beim Formular-POST `Origin: null`. Das Profil verwendet daher
`strict-origin` ohne Pfad-/Query-Weitergabe und behält die strikte Origin-Prüfung.
Keycloak kann eine unbekannte Ressource erst beim Token-Austausch mit `invalid_target`
abweisen; der Test prüft diese tatsächliche Grenze, nicht nur die Loginseite.
Das Setup-Formular wurde mit einem synthetischen, absichtlich verbotenen IMAP-Port
über den Browser gepostet: CSRF/Origin akzeptiert, Netzwerkregel unverändert ablehnend.
Erfolgreiche reale Mailbox-Einrichtung bleibt Teil der separaten Live-Abnahme.

Die neuen Auth-Regressionen wurden zuerst gegen die unveränderte Implementierung
ausgeführt: 17 erwartete Fehler belegten den bisherigen falschen Headervertrag.
Nach der Korrektur sind alle Tests grün. Es wurden ausschließlich synthetische
Schlüssel, Identitäten und Passwörter verwendet; keine echten Mailkonten.
Die zufällig benannten Testcontainer, Volumes und temporären Secret-Dateien wurden
durch die vorhandenen isolierten Testroutinen entfernt; keine globalen Docker-Prunes.

Die bestehende Python-3.12/3.13-Minimum/Latest-CI bleibt erhalten.
Für diesen korrigierten Arbeitsstand wurde noch keine Remote-CI ausgeführt;
lokales PASS ersetzt diesen Nachweis nicht.

## Getrennte externe Abnahme

| Nachweis | Status | Voraussetzung |
|---|---|---|
| GitHub-CI für den korrigierten Commit | NOT RUN | Commit und gesondert autorisierter Push, anschließend alle Jobs dieses Commits grün |
| Echte ChatGPT-Anmeldung und Token-Erneuerung | NOT RUN | Betreiberverbindung, Clients, echte Redirects |
| Zwei echte Testpostfächer, Suche, UIDVALIDITY, PDF | NOT RUN | separate Testpostfächer, Passwörter nur im Browser |
| Unveränderte IMAP-Flags vor/nach Live-Zugriff | NOT RUN | Betreiber-Testkonten |
| Live-Entzug/Deaktivierung/Sessionfristen | NOT RUN | Provider- und ChatGPT-Zugang |
| Öffentliche Produktionsfreigabe | NO | erfolgreiche Live-Abnahme und bewusste Freigabe der experimentellen Features |

## Manuelle Checkliste

1. Unangemeldet `/mcp`: 401 mit Discovery-Challenge, keine Accountdaten; Cookies ersetzen keine Bearer-Tokens.
2. ChatGPT mit exakt registriertem Callback verbinden, nach Ablauf erneuerten Access-Token nachweisen.
3. Reader liest aktive Accounts; Reader kann lokale Kontokonfiguration nicht ändern.
4. Admin startet Setup; nur derselbe Issuer/Subject darf den Einmallink verwenden.
5. Zwei Testpostfächer über HTTPS-Formular verbinden; Passwort nie im Chat eingeben.
6. Pro Konto Header, Body, Attachment-Metadaten und PDF über UIDVALIDITY-Referenz abrufen;
   Mailbox-Flags vor/nach vergleichen. Keine Mailänderungen zulassen.
7. Account deaktivieren, Session abmelden, Providerbenutzer sperren; dokumentierte Maximalfristen prüfen.
8. Keine geheimen Werte in Browser-Redirects, Proxy/Gateway/Backend-Logs oder Toolfehlern.

Implementierung lokal fertig: **ja**. Merge-Freigabe: **Remote-CI ausstehend**.
Keycloak Resource Indicators bleiben experimentell. Produktionsfreigabe: **nein**;
separate Live-Abnahme und Betreiberfreigabe bleiben erforderlich.
