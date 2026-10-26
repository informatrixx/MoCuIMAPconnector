"""Fail-closed public-profile preflight; prints no configuration values or secrets."""
from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
from pathlib import Path

import requests
from dotenv import dotenv_values

from mocu_imap_mcp.auth_gateway.config import GatewaySettings
from mocu_imap_mcp.credentials import CredentialVault
from mocu_imap_mcp.public_urls import metadata_url


def check(env_file: Path, online: bool = False) -> None:
    root = Path(__file__).resolve().parents[1]
    env = dotenv_values(env_file)
    if any(not value or "REPLACE" in value or "replace-with" in value for value in env.values()):
        raise ValueError("Incomplete configuration")
    secrets = Path(str(env["AUTH_SECRETS_DIR"])).resolve()
    config = Path(str(env["AUTH_CONFIG_DIR"])).resolve()
    tls = Path(str(env["AUTH_TLS_DIR"])).resolve()
    for directory in (secrets, config, tls):
        if directory.is_relative_to(root) or not directory.is_dir():
            raise ValueError("Deployment files must be outside checkout")
    if secrets.stat().st_mode & 0o077:
        raise ValueError("Secret directory must be owner-only")
    for name in ("provider_db", "admin_client", "chatgpt_client"):
        if len((secrets / name).read_text().strip()) < 32:
            raise ValueError("Secret too short")
    CredentialVault.from_file(secrets / "master_key")
    settings = GatewaySettings(oidc_issuer=env["OIDC_ISSUER"], mcp_resource=str(env["PUBLIC_BASE_URL"]) + "/mcp",
        admin_oidc_client_secret_file=secrets / "admin_client", allowed_subjects=json.loads(env["ALLOWED_SUBJECTS"]),
        admin_subjects=json.loads(env["ADMIN_SUBJECTS"]))
    if env.get("OIDC_BASE_URL", "") + "/realms/mocu" != settings.oidc_issuer:
        raise ValueError("Issuer base URL does not match configured issuer")
    subnet = ipaddress.ip_network(env["AUTH_SUBNET"])
    dynamic = ipaddress.ip_network(env["AUTH_DYNAMIC_RANGE"])
    proxy = ipaddress.ip_address(env["AUTH_PROXY_IP"])
    if proxy not in subnet or proxy in dynamic or not dynamic.subnet_of(subnet):
        raise ValueError("Invalid static proxy reservation")
    for file in (config / "nginx.conf", config / "realm.json", tls / "cert.pem", tls / "key.pem"):
        if not file.is_file():
            raise ValueError("Missing generated configuration or TLS file")
    result = subprocess.run(["docker", "compose", "--env-file", str(env_file.resolve()), "-f", "compose.auth.yaml",
                             "config", "--quiet"], cwd=root, capture_output=True, timeout=20)
    if result.returncode:
        raise ValueError("Compose validation failed")
    if online:
        with requests.Session() as client:
            client.trust_env = False
            client.verify = str(env["AUTH_CA_FILE"])
            response = client.get(metadata_url(settings.mcp_resource), timeout=5)
            response.raise_for_status()
            metadata = response.json()
            if (metadata["resource"] != settings.mcp_resource or
                    metadata["authorization_servers"] != [settings.oidc_issuer]):
                raise ValueError("Wrong resource metadata")
            response = client.post(settings.mcp_resource, json={}, timeout=5)
            if response.status_code != 401 or "resource_metadata=" not in response.headers.get("WWW-Authenticate", ""):
                raise ValueError("Missing unauthenticated challenge")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()
    try:
        check(args.env_file, args.online)
    except Exception:
        print("Auth preflight: FAIL (configuration, secrets, provider or HTTP boundary)")
        raise SystemExit(1) from None
    print("Auth preflight: PASS")
