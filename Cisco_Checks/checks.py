#!/usr/bin/env python3
"""Cisco IOS-XE PRE/POST command collection tool.

Version: 2.0.0
Python: 3.10+
Dependencies: netmiko, rich

This release intentionally does not generate diffs or parse JSON.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Literal

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TaskProgressColumn

VERSION = "2.0.0"
DEVICE_TYPE = "cisco_xe"
DEFAULT_WORKERS = 20
DEFAULT_COMMAND_FILE = "cmd.txt"
CONNECTION_TIMEOUT = 20
AUTH_TIMEOUT = 30
BANNER_TIMEOUT = 30
COMMAND_READ_TIMEOUT = 120
BANNER = "CISCO PRE / POST CHECKS"
FILE_HEADER = "=" * 70
COMMAND_SEPARATOR = "#" * 70
console = Console()


# ---------------------------------------------------------------------------
# DATA MODEL
# ---------------------------------------------------------------------------
@dataclass
class DeviceResult:
    target: str
    hostname: str = ""
    status: Literal["Success", "Failed"] = "Failed"
    reason: str = ""
    file_path: Path | None = None
    command_failures: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CLI AND INTERACTIVE PROMPTS
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Cisco_Pre_Post_Checks.py",
        add_help=False,  # -h is intentionally reserved for --host
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Cisco IOS-XE PRE/POST command collection via SSH.\n"
            "Missing arguments are requested interactively.\n"
            "PRE/POST collection only: no diffs or JSON comparisons."
        ),
        epilog=(
            "EXAMPLES:\n"
            "  Interactive:\n"
            "    python Cisco_Pre_Post_Checks.py\n\n"
            "  PRE check on one switch:\n"
            "    python Cisco_Pre_Post_Checks.py --pre -h SW01 -u admin\n\n"
            "  POST check using hosts.txt:\n"
            "    python Cisco_Pre_Post_Checks.py --post -hf hosts.txt -u admin\n\n"
            "  Custom commands and output folder:\n"
            "    python Cisco_Pre_Post_Checks.py --pre -hf hosts.txt -cf cmd.txt -o Upgrade_Cat9k -u admin\n\n"
            "  Explicit credentials and concurrency:\n"
            "    python Cisco_Pre_Post_Checks.py --post -h SW01 -cf cmd.txt -u admin -p secret -w 20\n\n"
            "  HELP: --help (note: -h means --host, not help)\n"
            "  DEFAULT OUTPUT: DD-MMM-YYYY/Pre_Checks or Post_Checks\n"
            "  LOGS: DD-MMM-YYYY/Logs/"
        ),
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--pre", action="store_true", help="Collect PRE-CHECK outputs")
    modes.add_argument("--post", action="store_true", help="Collect POST-CHECK outputs")
    hosts = parser.add_mutually_exclusive_group()
    hosts.add_argument("-h", "--host", metavar="HOST", help="Single device hostname or IP")
    hosts.add_argument("-hf", "--host_file", metavar="FILE", help="File with one host per line")
    parser.add_argument("-cf", "--cmd", metavar="FILE", help="Commands file (prompt; default: cmd.txt)")
    parser.add_argument("-u", "--username", metavar="USER", help="SSH username")
    parser.add_argument("-p", "--password", metavar="PASS", help="SSH password (prefer secure prompt)")
