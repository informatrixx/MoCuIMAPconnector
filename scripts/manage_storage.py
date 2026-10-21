"""Offline storage operations; never accepts credentials or keys as arguments."""
from __future__ import annotations

import argparse
from pathlib import Path

from mocu_imap_mcp.credentials import CredentialVault
from mocu_imap_mcp.runtime import Runtime, load_runtime_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Stop service before backup/rotation")
    parser.add_argument("operation", choices=["backup", "rotate"])
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--new-key-file", type=Path)
    parser.add_argument("--service-stopped", action="store_true", required=True)
    args = parser.parse_args()
    try:
        runtime = Runtime(load_runtime_settings())
        runtime.store.backup(args.backup)
        if args.operation == "rotate":
            if args.new_key_file is None:
                parser.error("--new-key-file erforderlich")
            runtime.store.rotate(CredentialVault.from_file(args.new_key_file))
    except Exception:
        print("Storage operation: FAILED; retain backup and existing keys")
        raise SystemExit(1) from None
    print("Storage operation: OK")


if __name__ == "__main__":
    main()
