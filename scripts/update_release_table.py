#!/usr/bin/env python3
"""Regenerate the README download table after publishing a release."""

import datetime
import pathlib
import sys

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"
START = "<!-- BUILD_TABLE_START -->"
END = "<!-- BUILD_TABLE_END -->"

ASSETS = [
    ("jftp_win_x64.zip", "Windows x64"),
    ("jftp_linux_x64.tar.gz", "Linux x64"),
]


def main() -> None:
    repo = sys.argv[1]
    built_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = "\n".join(
        f"| [{name}](https://github.com/{repo}/releases/latest/download/{name}) | {platform} | {built_at} |"
        for name, platform in ASSETS
    )
    table = (
        f"{START}\n"
        "| Package | Platform | Built |\n"
        "| --- | --- | --- |\n"
        f"{rows}\n"
        f"{END}"
    )

    text = README.read_text(encoding="utf-8")
    start = text.index(START)
    end = text.index(END, start) + len(END)
    README.write_text(text[:start] + table + text[end:], encoding="utf-8")


if __name__ == "__main__":
    main()
