from __future__ import annotations

import argparse
import logging

from mocu_imap_mcp.config import get_settings
from mocu_imap_mcp.imap_client import ImapClient


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list-mailboxes", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    settings = get_settings()

    with ImapClient(settings) as client:
        mailboxes = client.list_mailboxes()
    print("IMAP connection: OK")
    print(f"Mailboxes: {len(mailboxes)}")
    if args.list_mailboxes:
        for mailbox in mailboxes:
            print(f"{mailbox.name}\t{ 'selectable' if mailbox.selectable else 'no-select' }")


if __name__ == "__main__":
    main()
