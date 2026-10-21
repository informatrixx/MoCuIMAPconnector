# Auth-Abnahmeprotokoll

Baseline: `26abc7d112ff1ae44f42c6b11a0e6cd7315c2ee1`.
Arbeitsbranch: `feature/public-auth-e2e`. Stand: 2026-10-21.
Kein Push, Merge, Release oder produktives Deployment in diesem Auftrag.

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

Ausgeführt am 2026-10-21, lokal mit Python 3.13.5:

| Prüfung | Ergebnis |
|---|---|
| pytest (einschließlich bisheriger Regressionen) | PASS, 165 Tests |
| Ruff / mypy / `git diff --check` | PASS |
| MCP-Smoke | PASS, 11 Tools / 12 Resource-Templates |
| Connector-Image + bisheriger Docker-Runtime-Smoke | PASS |
| Compose-Builds Connector / Gateway / Keycloak / Chromium-Runner | PASS |
| Konfigurations-Preflight / echtes `nginx -t` | PASS |
| Echter Code-Flow + PKCE + Refresh / negative Ressourcen- und Verifierprüfungen | PASS |
| HTTP-Scopes, Header-Spoofing, Reader/Admin, ID-Token-Ablehnung | PASS |
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

Die bestehende Python-3.12/3.13-Minimum/Latest-CI bleibt erhalten; der Auth-E2E-Job
ist ergänzt. In diesem Auftrag wurde diese Remote-Matrix nicht neu ausgeführt.

## Getrennte externe Abnahme

| Nachweis | Status | Voraussetzung |
|---|---|---|
| Neuer GitHub-CI-Lauf | NOT RUN | gesondert autorisierter Push |
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

Keycloak Resource Indicators bleiben experimentell. Merge-Reife ist keine Produktionsfreigabe.
