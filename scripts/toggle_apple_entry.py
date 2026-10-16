#!/usr/bin/env python3
"""Keep apps.apple.com out of apple.txt on Sundays from 00:00 to 23:00 Madrid time."""

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
APPLE_FILE = REPOSITORY_ROOT / "apple.txt"
ENTRY = "apps.apple.com"
TIME_ZONE = ZoneInfo("Europe/Madrid")


def main() -> None:
    now = datetime.now(TIME_ZONE)

    # The entry is absent on Sunday from 00:00 up to (but not including) 23:00.
    should_include_entry = not (now.weekday() == 6 and now.hour < 23)

    original_content = (
        APPLE_FILE.read_text(encoding="utf-8")
        if APPLE_FILE.exists()
        else ""
    )
    lines = original_content.splitlines()

    # Only manage the exact target entry; preserve all other lines in apple.txt.
    lines_without_entry = [line for line in lines if line.strip() != ENTRY]

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
        print(f"No change needed in apple.txt for {ENTRY}.")


if __name__ == "__main__":
    main()
