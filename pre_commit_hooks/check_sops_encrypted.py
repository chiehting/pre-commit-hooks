#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import re
from pathlib import Path

SILENT = False

LOAD_PATTERN = {
    "yaml": re.compile(r"^sops:"),
    "yml":  re.compile(r"^sops:"),
    "json": re.compile(r"^\s*['\"]sops"),
    "env":  re.compile(r"^sops_mac="),
}

EXT_MAP = {
    ".yaml": "yaml",
    ".yml":  "yaml",
    ".json": "json",
    ".env":  "env",
}

def output(msg: str) -> None:
    if not SILENT:
        print(f"Error: {msg}")

def detect_file_type(path: Path) -> str | None:
    return EXT_MAP.get(path.suffix.lower())

def check_sops_in_file(file: Path, pattern: re.Pattern) -> int:
    try:
        with file.open() as f:
            if any(pattern.match(line) for line in f):
                return 0
        output(f"File not encrypted at {file}")
        return 1
    except FileNotFoundError:
        output(f"File not found at {file}")
        return 1
    except Exception as e:
        output(f"reading file: {e}")
        return 1

def main(argv=None) -> int:
    global SILENT
    parser = argparse.ArgumentParser()
    parser.add_argument('--silent', action='store_true', help='Do not print')
    parser.add_argument('filenames', nargs='*', help='Filenames to check.')
    args = parser.parse_args(argv)
    SILENT = args.silent
    ret = 0
    for fname in args.filenames:
        file = Path(fname)
        file_type = detect_file_type(file)
        if not file_type:
            output(f"unknown file: {file}")
            ret = 1
            continue
        pattern = LOAD_PATTERN[file_type]
        ret |= check_sops_in_file(file, pattern)
    return ret

if __name__ == "__main__":
    sys.exit(main())