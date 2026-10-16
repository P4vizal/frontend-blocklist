#!/usr/bin/env python3
"""Schedule the AdGuard DNS rule for apps.apple.com."""

import argparse
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
APPLE_FILE = REPOSITORY_ROOT / "apple.txt"

# AdGuard DNS adblock-style rule: blocks this hostname and its subdomains.
ENTRY = "||apps.apple.com^"
# Remove the old domains-only form too, so an upgrade cannot leave a duplicate.
LEGACY_ENTRY = "apps.apple.com"
TIME_ZONE = ZoneInfo("Europe/Madrid")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Remove the apps.apple.com rule on Sundays from 00:00 to 23:00 "
            "Madrid time, and keep it present at other times."
        )
    )
    parser.add_argument(
        "--action",
        choices=("auto", "add", "remove"),
        default="auto",
        help="Force add/remove for testing, or use the Madrid-time schedule (default).",
    )
    action = parser.parse_args().action

    if action == "auto":
        now = datetime.now(TIME_ZONE)
        should_include_entry = not (now.weekday() == 6 and now.hour < 23)
    else:
        should_include_entry = action == "add"

    original_content = (
        APPLE_FILE.read_text(encoding="utf-8")
        if APPLE_FILE.exists()
        else ""
    )
    lines = original_content.splitlines()

    # Manage only this rule and its old plain-domain form; keep every other line.
    managed_entries = {ENTRY, LEGACY_ENTRY}
    lines_without_entry = [
        line for line in lines if line.strip() not in managed_entries
    ]

    if should_include_entry:
        lines = lines_without_entry + [ENTRY]
    else:
        lines = lines_without_entry

    new_content = "\n".join(lines)
    if new_content:
        new_content += "\n"

    if new_content != original_content:
        APPLE_FILE.write_text(new_content, encoding="utf-8")
        state = "present" if should_include_entry else "absent"
        print(f"Updated apple.txt: {ENTRY} is now {state}.")
    else:
        state = "present" if should_include_entry else "absent"
        print(f"No change needed: {ENTRY} is already {state}.")


if __name__ == "__main__":
    main()
