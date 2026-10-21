from __future__ import annotations

import argparse
import logging

from mocu_imap_mcp.runtime import Runtime, load_runtime_settings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("account_id")
    parser.add_argument("--list-mailboxes", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.CRITICAL, format="%(message)s")
    try:
        runtime = Runtime(load_runtime_settings())
        with runtime.client(args.account_id) as client:
            mailboxes = client.list_mailboxes()
    except Exception:
        print("IMAP connection: FAILED")
        raise SystemExit(1) from None
    print("IMAP connection: OK")
    print(f"Mailboxes: {len(mailboxes)}")
    if args.list_mailboxes:
        for mailbox in mailboxes:
            print(f"{mailbox.name}\t{ 'selectable' if mailbox.selectable else 'no-select' }")


if __name__ == "__main__":
    main()
