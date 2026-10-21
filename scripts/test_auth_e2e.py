"""Disposable real nginx + Keycloak/Postgres + gateway + MCP browser acceptance.

No production accounts, no public port, no mocked OAuth and no password grant.
Only resources bearing this run's random Compose project name are removed.
"""
from __future__ import annotations

import base64
import datetime
import json
import os
import re
import secrets
import signal
import subprocess
import tempfile
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from preflight_auth import check
from prepare_auth import render

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 300) -> str:
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Never echo container output: it may contain credentials or OAuth URLs.
        if "logs" not in command:
            diagnostic = re.sub(r"https?://\S+|synthetic-\S+", "[redacted]", result.stderr)
            print(diagnostic[-3000:], flush=True)
        if command[-1] == "runner":
            for line in result.stdout.splitlines():
                if line.startswith("Auth E2E:"):
                    print(line, flush=True)
        raise RuntimeError(f"Command failed ({command[0]} {command[1]}), exit {result.returncode}")
    return result.stdout


def tls(directory: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MoCu synthetic E2E")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("imap-mcp.example.at"),
                                                    x509.DNSName("auth.example.at")]), critical=False)
        .sign(key, hashes.SHA256()))
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def main() -> None:
    def interrupted(signum: int, frame: object) -> None:
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    project = "mocu-auth-test-" + secrets.token_hex(5)
    print("Auth E2E: preparing isolated synthetic stack", flush=True)
    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        path = Path(temporary)
        config, secret_dir, tls_dir = (path / name for name in ("config", "secrets", "tls"))
        secret_dir.mkdir(mode=0o700)
        tls_dir.mkdir()
        for name in ("provider_db", "chatgpt_client", "admin_client", "test_password"):
            (secret_dir / name).write_text("synthetic-" + secrets.token_urlsafe(32) + "\n")
        (secret_dir / "master_key").write_bytes(base64.urlsafe_b64encode(secrets.token_bytes(32)))
        tls(tls_dir)
        render(config, "https://imap-mcp.example.at", "https://auth.example.at/realms/mocu",
               "https://imap-mcp.example.at/test-callback")
        realm_path = config / "realm.json"
        data = json.loads(realm_path.read_text())
        users = ("synthetic-admin", "synthetic-reader", "synthetic-other-admin")
        subjects = {name: str(uuid.uuid5(uuid.NAMESPACE_DNS, name)) for name in users}
        data["users"] = [{"id": subjects[name], "username": name, "enabled": True, "firstName": "Synthetic",
            "lastName": "Fixture", "email": name + "@example.invalid", "emailVerified": True,
            "credentials": [{"type": "password", "temporary": False,
                             "value": (secret_dir / "test_password").read_text().strip()}]}
            for name in users]
        realm_path.write_text(json.dumps(data))
        # These random test-only files must be readable by distinct non-root container UIDs.
        # Their parent is mode 0700 on the host and only explicit files are mounted.
        for file in [*secret_dir.iterdir(), *tls_dir.iterdir(), *config.iterdir()]:
            file.chmod(0o644)
        tls_dir.chmod(0o755)
        # The runner receives only synthetic client credentials, never the master key or database password.
        override = path / "test.yaml"
        override.write_text(json.dumps({"services": {"runner": {
            "build": {"context": str(ROOT), "dockerfile": "deploy/auth/Test.Dockerfile"},
            "networks": ["auth"], "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
            "volumes": [f"{secret_dir / 'test_password'}:/test/password:ro",
                        f"{secret_dir / 'chatgpt_client'}:/test/client:ro",
                        f"{tls_dir / 'cert.pem'}:/test/ca.pem:ro"]}}}))
        env = {**os.environ, "AUTH_CONFIG_DIR": str(config), "AUTH_SECRETS_DIR": str(secret_dir),
               "AUTH_TLS_DIR": str(tls_dir), "AUTH_CA_FILE": str(tls_dir / "cert.pem"),
               "AUTH_PROXY_IP": "172.29.187.2", "AUTH_SUBNET": "172.29.187.0/24",
               "AUTH_DYNAMIC_RANGE": "172.29.187.128/25",
               "AUTH_HOST": "auth.example.at", "MCP_HOST": "imap-mcp.example.at",
               "OIDC_ISSUER": "https://auth.example.at/realms/mocu", "PUBLIC_BASE_URL": "https://imap-mcp.example.at",
               "ALLOWED_SUBJECTS": json.dumps(list(subjects.values())),
               "ADMIN_SUBJECTS": json.dumps([subjects["synthetic-admin"], subjects["synthetic-other-admin"]]),
               "AUTH_LISTEN_IP": "127.0.0.1", "AUTH_HTTPS_PORT": "0"}
        compose = ["docker", "compose", "--project-name", project, "-f", "compose.auth.yaml", "-f", str(override)]
        try:
            env_file = path / "profile.env"
            keys = ("AUTH_CONFIG_DIR", "AUTH_SECRETS_DIR", "AUTH_TLS_DIR", "AUTH_CA_FILE", "AUTH_PROXY_IP",
                    "AUTH_SUBNET", "AUTH_DYNAMIC_RANGE", "AUTH_HOST", "MCP_HOST", "OIDC_ISSUER", "PUBLIC_BASE_URL",
                    "ALLOWED_SUBJECTS", "ADMIN_SUBJECTS", "AUTH_LISTEN_IP", "AUTH_HTTPS_PORT")
            env_file.write_text("\n".join(f"{key}={env[key]}" for key in keys) + "\n")
            check(env_file)
            print("Auth E2E: configuration preflight PASS", flush=True)
            run([*compose, "build", "mocu-imap", "keycloak"], env=env, timeout=600)
            run([*compose, "build", "runner"], env=env, timeout=900)
            print("Auth E2E: builds PASS; starting provider and proxy", flush=True)
            run([*compose, "up", "-d", "proxy"], env=env)
            run([*compose, "exec", "-T", "proxy", "nginx", "-t"], env=env)
            run([*compose, "exec", "-T", "gateway", "python", "-c",
                "import os,pathlib; assert os.getuid()==10001; "
                "assert not pathlib.Path('/run/secrets/mocu_master_key').exists(); "
                "assert not pathlib.Path('/data/mocu-imap.sqlite3').exists()"], env=env)
            output = run([*compose, "run", "--rm", "-T", "runner"], env=env, timeout=240)
            print(output.strip(), flush=True)
            run([*compose, "stop", "gateway"], env=env)
            print(run([*compose, "run", "--rm", "-T", "runner", "--outage"], env=env, timeout=30).strip(), flush=True)
            logs = run([*compose, "logs", "--no-color"], env=env)
            for file in secret_dir.iterdir():
                if file.read_text().strip() in logs:
                    raise RuntimeError("Secret marker detected in container logs")
            if re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.|/setup/[A-Za-z0-9_-]{43}|/auth/callback\?"
                         r"|(?i:authorization:|cookie:)", logs):
                raise RuntimeError("Credential-bearing URL/header detected in container logs")
            print("Auth E2E: container logs secret scan PASS", flush=True)
        except Exception:
            logs = run([*compose, "logs", "--no-color", "proxy", "keycloak"], env=env)
            for line in logs.splitlines():
                if any(marker in line for marker in ("[emerg]", "ERROR:", "ERROR ")):
                    print(re.sub(r"https?://\S+|synthetic-\S+", "[redacted]", line)[:500], flush=True)
            raise
        finally:
            # Exact randomly named test project; never prune or touch other deployments.
            run([*compose, "down", "--volumes", "--remove-orphans", "--timeout", "10"], env=env, timeout=90)


if __name__ == "__main__":
    main()
