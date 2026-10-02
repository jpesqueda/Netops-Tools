#!/usr/bin/env python3
"""
CiscoImageValidator.py
======================

Project
-------
Cisco Image Validator

Version
-------
1.2.0

Author
------
Peskicorp

Purpose
-------
CiscoImageValidator is a read-only pre-upgrade validation utility for Cisco
Catalyst 9000 switches running Cisco IOS-XE.

The tool validates:

    1. SSH connectivity.
    2. Catalyst model.
    3. Current IOS-XE version.
    4. Presence of the target image in bootflash.
    5. MD5 integrity of the target image.
    6. Available bootflash free space.
    7. Overall PASS / FAIL / ERROR state.

Version 1.2.0 Modes and Output Behavior
---------------------------------------
CiscoImageValidator supports two validation modes:

    1. Full image validation (default / pre-upgrade)
    2. Version-only validation (post-upgrade)

Full validation performs:

    show version
    dir bootflash:
    verify /md5 bootflash:<IMAGE>
    bootflash free-space validation

Version-only validation performs only:

    show version
    compare running IOS-XE version with the target version

Generated files are stored inside an output directory.

If -o/--output is omitted, the script creates a date-based folder:

    01-OCT-2026/
        Devices_Verified.csv
        CiscoImageValidator.log

If -o/--output is provided, its value is used as the folder name:

    python CiscoImageValidator.py -ho hosts.txt -c image.yaml -u admin -o CHG12345

Result:

    CHG12345/
        Devices_Verified.csv
        CiscoImageValidator.log

Version-only example:

    python CiscoImageValidator.py \
        -ho hosts.txt \
        -c version_only.yaml \
        -u admin \
        --version-only

Version-only result:

    01-OCT-2026/
        Version_Validation.csv
        CiscoImageValidator.log

Architecture
------------
    hosts.txt
        |
        v
    ThreadPoolExecutor
        |
        +--> Worker -> Switch 1
        +--> Worker -> Switch 2
        +--> Worker -> Switch N
        |
        v
    DeviceResult objects
        |
        v
    Main thread
        |
        +--> Output directory
                |
                +--> Devices_Verified.csv
                +--> CiscoImageValidator.log

Each worker validates exactly one device.

Workers never write directly to the CSV report. The main thread collects all
DeviceResult objects and writes the final report in the original hosts.txt
order.

Safety
------
This tool is strictly READ-ONLY.

Approved device commands:

    show version
    dir bootflash:
    verify /md5 bootflash:<IMAGE>

The script does NOT perform:

    copy
    delete
    erase
    install
    reload
    write memory
    configure terminal
    request platform
    install add
    install activate
    install commit
    install remove

Requirements
------------
Python 3.10+

Install dependencies:

    pip install netmiko pyyaml rich

Input Files
-----------
    hosts.txt
    image.yaml

Generated Files
---------------
Full validation:
    <OUTPUT_FOLDER>/Devices_Verified.csv
    <OUTPUT_FOLDER>/CiscoImageValidator.log

Version-only validation:
    <OUTPUT_FOLDER>/Version_Validation.csv
    <OUTPUT_FOLDER>/CiscoImageValidator.log

Maintenance Rules
-----------------
- Keep device validation inside validate_device().
- Keep concurrency orchestration inside run_parallel_validation().
- Keep CSV generation in the main thread.
- Never log credentials.
- Never hardcode image/version/hash values in Python.
- Preserve PASS / FAIL / ERROR semantics.
- Review send_read_only_command() before adding any new device command.
- Update __version__ for every released behavioral change.
- Update CHANGELOG.md for every released version.

Author
------
Peskicorp
"""

# =============================================================================
# SECTION 1 - IMPORTS
# =============================================================================
# Standard-library imports are intentionally kept separate from third-party
# modules so dependencies are easy for maintainers to identify.

from __future__ import annotations

import argparse
import csv
import getpass
import logging
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadTimeout,
)
from rich import box
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table


# =============================================================================
# SECTION 2 - APPLICATION METADATA AND CONSTANTS
# =============================================================================
# Release metadata is intentionally centralized so --help, logs, banners, and
# documentation can refer to one authoritative version value.

__version__ = "1.2.0"
__author__ = "Peskicorp"

DEFAULT_REPORT_NAME = "Devices_Verified.csv"
VERSION_REPORT_NAME = "Version_Validation.csv"
DEFAULT_LOG_NAME = "CiscoImageValidator.log"
DEFAULT_WORKERS = 20
DEFAULT_TIMEOUT = 30
MIN_MD5_TIMEOUT = 600

SUPPORTED_FAMILIES = (
    "C9200",
    "C9200L",
    "C9300",
    "C9300L",
    "C9400",
    "C9500",
    "C9600",
)

CSV_FIELDS = [
    "Host",
    "Model",
    "Running_Version",
    "New_Version",
    "Image",
    "Image_Found",
    "Expected_MD5",
    "Calculated_MD5",
    "MD5_Check",
    "Image_Size_Bytes",
    "Required_Space_Bytes",
    "Free_Space_Bytes",
    "Space_Check",
    "Status",
    "Reason",
]

VERSION_CSV_FIELDS = [
    "Host",
    "Model",
    "Running_Version",
    "Target_Version",
    "Version_Check",
    "Status",
    "Reason",
]


# =============================================================================
# SECTION 3 - DATA MODELS
# =============================================================================
# These dataclasses define the structured contract between configuration,
# worker threads, and final reporting.

@dataclass(frozen=True)
class ImageConfig:
    """Target IOS-XE image settings loaded from YAML."""

    version: str
    image: str
    md5sum: str
    image_size: int

    @property
    def required_space(self) -> int:
        """Return required free space in bytes (image size x 2)."""
        return self.image_size * 2


@dataclass(frozen=True)
class Credentials:
    """SSH credentials shared read-only by worker threads."""

    username: str
    password: str


@dataclass
class DeviceResult:
    """Structured validation result returned by one worker."""

    inventory_index: int
    host: str
    model: str = "-"
    running_version: str = "-"
    new_version: str = "-"
    version_check: str = "-"
    image: str = "-"
    image_found: str = "UNKNOWN"
    expected_md5: str = ""
    calculated_md5: str = ""
    md5_check: str = "-"
    image_size_bytes: int = 0
    required_space_bytes: int = 0
    free_space_bytes: int | None = None
    space_check: str = "-"
    status: str = "ERROR"
    reason: str = "Validation did not complete"

    def to_csv_row(self) -> dict[str, str | int]:
        """Return CSV field names and values in the required schema."""
        return {
            "Host": self.host,
            "Model": self.model,
            "Running_Version": self.running_version,
            "New_Version": self.new_version,
            "Image": self.image,
            "Image_Found": self.image_found,
            "Expected_MD5": self.expected_md5,
            "Calculated_MD5": self.calculated_md5,
            "MD5_Check": self.md5_check,
            "Image_Size_Bytes": self.image_size_bytes,
            "Required_Space_Bytes": self.required_space_bytes,
            "Free_Space_Bytes": (
                self.free_space_bytes
                if self.free_space_bytes is not None
                else ""
            ),
            "Space_Check": self.space_check,
            "Status": self.status,
            "Reason": self.reason,
        }

    def to_version_csv_row(self) -> dict[str, str]:
        """Return the reduced post-upgrade version-validation CSV row."""
        return {
            "Host": self.host,
            "Model": self.model,
            "Running_Version": self.running_version,
            "Target_Version": self.new_version,
            "Version_Check": self.version_check,
            "Status": self.status,
            "Reason": self.reason,
        }


# =============================================================================
# SECTION 4 - COMMAND-LINE INTERFACE
# =============================================================================
# CLI parsing stays isolated here so command options can be changed without
# touching device validation logic.

def parse_arguments() -> argparse.Namespace:
    """Build and parse command-line arguments."""
    description = (
        f"CiscoImageValidator v{__version__} - Read-only Cisco Catalyst 9000 IOS-XE image validator. "
        "Supports full pre-upgrade image validation and post-upgrade "
        "version-only validation in parallel without modifying devices."
    )
    epilog = r"""
Examples:
  python CiscoImageValidator.py --hosts hosts.txt --config image.yaml --username admin
  python CiscoImageValidator.py -ho hosts.txt -c image.yaml -u admin
  python CiscoImageValidator.py -ho hosts.txt -c image.yaml -u admin -p PASSWORD
  python CiscoImageValidator.py -ho hosts.txt -c image.yaml -u admin --workers 10
  python CiscoImageValidator.py -ho hosts.txt -c image.yaml -u admin --workers 30
  python CiscoImageValidator.py -ho hosts.txt -c image.yaml -u admin -o CHG12345
  python CiscoImageValidator.py -ho hosts.txt -c image.yaml -u admin --timeout 45 --verbose
  python CiscoImageValidator.py -ho hosts.txt -c version_only.yaml -u admin --version-only
  python CiscoImageValidator.py -ho hosts.txt -c version_only.yaml -u admin -vo -o POST_CHG12345

Notes:
  * Default workers: 20
  * If -o/--output is omitted, a DD-MMM-YYYY folder is created.
  * -o/--output defines the output folder name.
  * Full mode report: Devices_Verified.csv
  * Version-only report: Version_Validation.csv
  * -vo/--version-only performs post-upgrade IOS-XE version validation only.
  * In version-only mode, YAML only requires cisco_iosxe.version.
  * --timeout is the base SSH/show-command timeout in seconds.
  * MD5 verification gets an extended timeout of at least 600 seconds.
  * If --password is omitted, the password is requested securely with getpass.
  * Passwords are never printed or written to the log.
"""
    parser = argparse.ArgumentParser(
        description=description,
        epilog=textwrap_dedent(epilog),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-ho",
        "--hosts",
        required=True,
        help="Path to hosts.txt (one hostname/IP per line).",
    )
    parser.add_argument(
        "-c",
        "--config",
        required=True,
        help="Path to image.yaml or a version-only YAML configuration.",
    )
    parser.add_argument(
        "-u",
        "--username",
        required=True,
        help="SSH username.",
    )
    parser.add_argument(
        "-p",
        "--password",
        help="SSH password. If omitted, prompt securely.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FOLDER",
        help=(
            "Output folder name. If omitted, the current date is used in "
            "DD-MMM-YYYY format, for example 01-OCT-2026."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Parallel worker count (default: {DEFAULT_WORKERS}).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Base SSH/command timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "-vo",
        "--version-only",
        action="store_true",
        help=(
            "Post-upgrade mode. Only run 'show version' and compare the "
            "running IOS-XE version with cisco_iosxe.version from YAML."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG detail in the log and print final device reasons.",
    )
    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")

    return args


def textwrap_dedent(value: str) -> str:
    """Dedent help text without importing another public-facing abstraction."""
    lines = value.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return ""
    indentation = min(
        (len(line) - len(line.lstrip()) for line in lines if line.strip()),
        default=0,
    )
    return "\n".join(line[indentation:] for line in lines)


# =============================================================================
# SECTION 5 - OUTPUT DIRECTORY AND LOGGING
# =============================================================================
# Folder-based output keeps each audit execution self-contained. Version 1.2.0
# also uses a dedicated Version_Validation.csv report in version-only mode.

def build_output_directory(output_name: str | None) -> Path:
    """
    Create and return the directory used for generated files.

    If output_name is None, the folder uses the local execution date in
    DD-MMM-YYYY format. Example: 01-OCT-2026.

    If output_name is provided, it is treated as a directory name or path.

    Examples:
        -o CHG12345
        -o Core_Upgrade
        -o reports/CHG12345

    The directory is created relative to the current working directory unless
    an absolute path is supplied.
    """
    if output_name:
        output_directory = Path(output_name).expanduser()
    else:
        output_directory = Path(
            datetime.now().strftime("%d-%b-%Y").upper()
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    return output_directory


def setup_logging(verbose: bool, log_path: Path) -> logging.Logger:
    """
    Configure thread-safe file logging.

    The log file lives inside the selected output directory.
    """
    logger = logging.getLogger("CiscoImageValidator")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-5s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)
    return logger


# =============================================================================
# SECTION 6 - INPUT FILE LOADING AND VALIDATION
# =============================================================================
# Inventory and YAML parsing are kept separate from SSH operations.

def load_hosts(path: str) -> list[str]:
    """
    Load the device inventory from a plain-text file.

    Inventory format:
        - One hostname or IP address per line.
        - Empty lines are ignored.
        - Lines beginning with '#' are treated as comments.

    The function intentionally performs no platform detection because V1 only
    supports Cisco IOS-XE Catalyst 9000 devices.
    """
    hosts_path = Path(path)
    if not hosts_path.is_file():
        raise FileNotFoundError(f"Hosts file not found: {path}")

    hosts: list[str] = []
    with hosts_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            hosts.append(line)

    if not hosts:
        raise ValueError("No valid hosts were found in the hosts file.")
    return hosts


def load_config(path: str, version_only: bool = False) -> ImageConfig:
    """
    Load and validate the IOS-XE target configuration.

    Full validation requires:

        cisco_iosxe:
          version: "17.12.04"
          image: "cat9k_iosxe.17.12.04.SPA.bin"
          md5sum: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          image_size: 1350000000

    Version-only validation requires only:

        cisco_iosxe:
          version: "17.12.04"

    In version-only mode, image, MD5, and image-size values are intentionally
    ignored because no bootflash or image-integrity commands are executed.
    """
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)

    if not isinstance(raw, dict) or "cisco_iosxe" not in raw:
        raise ValueError("YAML must contain a top-level 'cisco_iosxe' section.")

    section = raw["cisco_iosxe"]
    if not isinstance(section, dict):
        raise ValueError("'cisco_iosxe' must be a YAML mapping.")

    if "version" not in section:
        raise ValueError("Missing YAML key under cisco_iosxe: version")

    version = str(section["version"]).strip()
    if not version:
        raise ValueError("version cannot be empty.")

    if version_only:
        return ImageConfig(
            version=version,
            image="",
            md5sum="",
            image_size=0,
        )

    required_keys = ("image", "md5sum", "image_size")
    missing = [key for key in required_keys if key not in section]
    if missing:
        raise ValueError(
            "Missing YAML key(s) under cisco_iosxe: " + ", ".join(missing)
        )

    image = str(section["image"]).strip()
    md5sum = str(section["md5sum"]).strip().lower()

    try:
        image_size = int(section["image_size"])
    except (TypeError, ValueError) as exc:
        raise ValueError("image_size must be an integer number of bytes.") from exc

    if not image:
        raise ValueError("image cannot be empty.")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", md5sum):
        raise ValueError("md5sum must be exactly 32 hexadecimal characters.")
    if image_size <= 0:
        raise ValueError("image_size must be greater than zero.")

    return ImageConfig(
        version=version,
        image=image,
        md5sum=md5sum,
        image_size=image_size,
    )


# =============================================================================
# SECTION 7 - SSH CONNECTION AND COMMAND SAFETY
# =============================================================================
# Each worker owns its own Netmiko connection. Device commands are restricted
# by send_read_only_command() to preserve the read-only design.

def connect_device(
    host: str,
    credentials: Credentials,
    timeout: int,
) -> Any:
    """
    Open one Netmiko SSH session to a Cisco IOS-XE device.

    A separate connection is created inside each worker. Connections are never
    shared between threads.
    """
    return ConnectHandler(
        device_type="cisco_ios",
        host=host,
        username=credentials.username,
        password=credentials.password,
        conn_timeout=timeout,
        auth_timeout=timeout,
        banner_timeout=timeout,
        timeout=timeout,
        fast_cli=False,
    )


def send_read_only_command(connection: Any, command: str, timeout: int) -> str:
    """
    Execute an approved read-only command.

    The allow-list is deliberately strict to prevent accidental expansion of
    this V1 into configuration or software-management actions.
    """
    approved_exact = {"show version", "dir bootflash:"}
    approved_prefix = "verify /md5 bootflash:"

    if command not in approved_exact and not command.startswith(approved_prefix):
        raise ValueError(f"Blocked non-approved command: {command}")

    return str(connection.send_command(command, read_timeout=timeout))


# =============================================================================
# SECTION 8 - IOS-XE OUTPUT PARSING
# =============================================================================
# Parsing functions convert raw IOS-XE command output into normalized values.
# Keep these functions small so they can be unit-tested with saved CLI output.

def parse_model(show_version: str) -> str:
    """
    Extract the full hardware product ID from 'show version'.

    Multiple parsing patterns are used because IOS-XE output formatting can
    vary between Catalyst families and releases.
    """
    patterns = (
        r"(?im)^\s*Model Number\s*:\s*(\S+)",
        r"(?im)^\s*cisco\s+(C9[0-9A-Za-z-]+)\s+\(",
    )
    for pattern in patterns:
        match = re.search(pattern, show_version)
        if match:
            return match.group(1).strip().upper()
    raise ValueError("Unable to parse Catalyst model from show version.")


def parse_version(show_version: str) -> str:
    """
    Extract the currently running IOS-XE software version.

    The first pattern targets the IOS-XE-specific banner. A secondary pattern
    is retained for common alternate Cisco version formatting.
    """
    patterns = (
        r"(?im)Cisco IOS XE Software,\s*Version\s+([^\s,]+)",
        r"(?im)Cisco IOS Software.*?\bVersion\s+([^\s,]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, show_version)
        if match:
            return match.group(1).strip()
    raise ValueError("Unable to parse running IOS-XE version from show version.")


def is_supported_catalyst_model(model: str) -> bool:
    """Return True when the model belongs to a supported Catalyst 9000 family."""
    normalized = model.upper()

    # Fixed-access Catalyst families.
    if normalized.startswith(("C9200", "C9200L", "C9300", "C9300L", "C9500")):
        return True

    # Modular chassis use product IDs such as C9404R/C9407R/C9410R and
    # C9606R/C9610R rather than a literal C9400/C9600 prefix.
    if re.match(r"^C94(?:04|07|10)R(?:$|-)", normalized):
        return True
    if re.match(r"^C96(?:06|10)R(?:$|-)", normalized):
        return True

    # Retain support for generic family strings if encountered.
    return normalized.startswith(("C9400", "C9600"))


def get_device_facts(connection: Any, timeout: int) -> tuple[str, str]:
    """Collect and parse model and running version."""
    output = send_read_only_command(connection, "show version", timeout)
    model = parse_model(output)
    version = parse_version(output)
    return model, version


def parse_free_space(dir_output: str) -> int:
    """
    Extract exact available bootflash capacity from 'dir bootflash:'.

    The return value is always expressed in bytes so comparisons and CSV
    reporting remain precise.
    """
    patterns = (
        r"\(([\d,]+)\s+bytes\s+free\)",
        r"([\d,]+)\s+bytes\s+free",
    )
    for pattern in patterns:
        matches = re.findall(pattern, dir_output, flags=re.IGNORECASE)
        if matches:
            return int(matches[-1].replace(",", ""))
    raise ValueError("Unable to parse bootflash free space.")


def check_image_exists(dir_output: str, image_name: str) -> bool:
    """Check whether the exact target filename appears in bootflash listing."""
    target = image_name.strip()
    for line in dir_output.splitlines():
        tokens = line.split()
        if target in tokens:
            return True

    # IOS-XE directory output can include unusual spacing or metadata.
    exact_pattern = re.compile(
        rf"(?<![A-Za-z0-9_.-]){re.escape(target)}(?![A-Za-z0-9_.-])"
    )
    return bool(exact_pattern.search(dir_output))


def get_bootflash_info(
    connection: Any,
    image_name: str,
    timeout: int,
) -> tuple[bool, int]:
    """Return target image presence and free bootflash bytes."""
    output = send_read_only_command(connection, "dir bootflash:", timeout)
    return check_image_exists(output, image_name), parse_free_space(output)


def parse_calculated_md5(output: str) -> str:
    """Extract a calculated 32-character MD5 hash from Cisco CLI output."""
    hashes = re.findall(r"(?i)\b[0-9a-f]{32}\b", output)
    if not hashes:
        raise ValueError("Unable to parse calculated MD5 from device output.")
    return hashes[-1].lower()


def calculate_md5(
    connection: Any,
    image_name: str,
    timeout: int,
) -> str:
    """
    Execute IOS-XE file integrity verification.

    MD5 verification can take significantly longer than ordinary show
    commands, especially on large software images. The caller therefore
    provides an extended read timeout.
    """
    command = f"verify /md5 bootflash:{image_name}"
    output = send_read_only_command(connection, command, timeout)
    return parse_calculated_md5(output)


# =============================================================================
# SECTION 9 - VALIDATION HELPERS
# =============================================================================
# These functions contain deterministic validation logic without SSH access.

def normalize_iosxe_version(value: str) -> str:
    """
    Normalize IOS-XE version strings for reliable comparison.

    Numeric components have leading zeroes removed while suffixes are
    preserved.

    Examples:
        17.12.04  -> 17.12.4
        17.12.4   -> 17.12.4
        17.09.04a -> 17.9.4a
    """
    normalized_parts: list[str] = []

    for part in value.strip().lower().split("."):
        match = re.fullmatch(r"(\d+)(.*)", part)
        if not match:
            normalized_parts.append(part)
            continue

        number = str(int(match.group(1)))
        suffix = match.group(2)
        normalized_parts.append(number + suffix)

    return ".".join(normalized_parts)


def validate_version(running_version: str, target_version: str) -> str:
    """Compare normalized running and target IOS-XE versions."""
    running = normalize_iosxe_version(running_version)
    target = normalize_iosxe_version(target_version)
    return "PASS" if running == target else "FAIL"


def validate_md5(expected_md5: str, calculated_md5: str) -> str:
    """Compare normalized expected and calculated MD5 values."""
    expected = expected_md5.strip().lower()
    calculated = calculated_md5.strip().lower()
    return "PASS" if expected == calculated else "FAIL"


def validate_space(free_bytes: int, required_bytes: int) -> str:
    """Return PASS when actual free bytes satisfy required free space."""
    return "PASS" if free_bytes >= required_bytes else "FAIL"


def compact_exception(exc: BaseException) -> str:
    """Return a single-line exception description suitable for reports/logs."""
    message = " ".join(str(exc).split())
    return message[:500] if message else exc.__class__.__name__


def build_error_result(
    inventory_index: int,
    host: str,
    image_config: ImageConfig,
    reason: str,
) -> DeviceResult:
    """Build a standard ERROR result."""
    return DeviceResult(
        inventory_index=inventory_index,
        host=host,
        new_version=image_config.version,
        image=image_config.image,
        expected_md5=image_config.md5sum,
        image_size_bytes=image_config.image_size,
        required_space_bytes=image_config.required_space,
        status="ERROR",
        reason=reason,
    )


# =============================================================================
# SECTION 10 - SINGLE-DEVICE WORKER
# =============================================================================
# validate_device() is the worker boundary. It validates exactly one switch,
# isolates failures, closes its connection, and returns one DeviceResult.

def validate_version_only(
    inventory_index: int,
    host: str,
    image_config: ImageConfig,
    credentials: Credentials,
    timeout: int,
    logger: logging.Logger,
) -> DeviceResult:
    """
    Perform post-upgrade IOS-XE version validation for exactly one switch.

    The only device command executed by this worker is:

        show version

    It does not perform image-presence, MD5, or bootflash-space validation.
    """
    result = DeviceResult(
        inventory_index=inventory_index,
        host=host,
        new_version=image_config.version,
    )
    connection = None

    logger.info("[%s] Version-only connection attempt", host)

    try:
        connection = connect_device(host, credentials, timeout)
        logger.info("[%s] SSH connection established", host)

        try:
            show_version = send_read_only_command(
                connection,
                "show version",
                timeout,
            )
        except ReadTimeout as exc:
            reason = "show version command timeout"
            logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
            result.status = "ERROR"
            result.version_check = "ERROR"
            result.reason = reason
            return result
        except Exception as exc:
            reason = f"show version command failed: {compact_exception(exc)}"
            logger.error("[%s] %s", host, reason)
            result.status = "ERROR"
            result.version_check = "ERROR"
            result.reason = reason
            return result

        try:
            result.running_version = parse_version(show_version)
        except ValueError as exc:
            result.status = "ERROR"
            result.version_check = "ERROR"
            result.reason = str(exc)
            logger.error("[%s] %s", host, exc)
            return result

        # Model is informational in post-upgrade mode. Version is the only
        # validation criterion after successful SSH connectivity.
        try:
            result.model = parse_model(show_version)
        except ValueError as exc:
            logger.warning("[%s] Model parsing warning: %s", host, exc)

        result.version_check = validate_version(
            result.running_version,
            image_config.version,
        )

        if result.version_check == "PASS":
            result.status = "PASS"
            result.reason = "Running version matches target version"
        else:
            result.status = "FAIL"
            result.reason = (
                f"Running version {result.running_version} does not match "
                f"target version {image_config.version}"
            )

        logger.info(
            "[%s] Version-only validation running=%s target=%s status=%s",
            host,
            result.running_version,
            image_config.version,
            result.status,
        )
        return result

    except NetmikoAuthenticationException as exc:
        reason = "Authentication failed"
        logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
        result.status = "ERROR"
        result.version_check = "ERROR"
        result.reason = reason
        return result

    except NetmikoTimeoutException as exc:
        reason = "SSH connection timeout"
        logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
        result.status = "ERROR"
        result.version_check = "ERROR"
        result.reason = reason
        return result

    except socket.gaierror as exc:
        reason = "DNS resolution failed"
        logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
        result.status = "ERROR"
        result.version_check = "ERROR"
        result.reason = reason
        return result

    except OSError as exc:
        reason = f"SSH/network failure: {compact_exception(exc)}"
        logger.error("[%s] %s", host, reason)
        result.status = "ERROR"
        result.version_check = "ERROR"
        result.reason = reason
        return result

    except Exception as exc:
        reason = f"Unexpected version validation error: {compact_exception(exc)}"
        logger.exception("[%s] %s", host, reason)
        result.status = "ERROR"
        result.version_check = "ERROR"
        result.reason = reason
        return result

    finally:
        if connection is not None:
            try:
                connection.disconnect()
                logger.debug("[%s] SSH connection closed", host)
            except Exception as exc:
                logger.warning(
                    "[%s] Error while closing SSH connection: %s",
                    host,
                    compact_exception(exc),
                )


def validate_device(
    inventory_index: int,
    host: str,
    image_config: ImageConfig,
    credentials: Credentials,
    timeout: int,
    logger: logging.Logger,
) -> DeviceResult:
    """
    Validate exactly one switch.

    This function is the worker execution boundary.

    Thread-safety rules:
        - A worker owns its SSH connection.
        - A worker does not print device-specific progress.
        - A worker does not write the CSV report.
        - A worker only returns one DeviceResult object.
        - Logging uses Python's thread-safe logging implementation.

    Status semantics:
        PASS:
            All validation checks succeeded.

        FAIL:
            The device was reachable, but one or more upgrade-readiness
            checks failed.

        ERROR:
            Validation could not be completed reliably because of connection,
            command execution, timeout, or critical parsing problems.
    """
    result = DeviceResult(
        inventory_index=inventory_index,
        host=host,
        new_version=image_config.version,
        image=image_config.image,
        expected_md5=image_config.md5sum,
        image_size_bytes=image_config.image_size,
        required_space_bytes=image_config.required_space,
    )

    connection = None
    critical_errors: list[str] = []
    validation_failures: list[str] = []

    logger.info("[%s] Connection attempt", host)

    try:
        connection = connect_device(host, credentials, timeout)
        logger.info("[%s] SSH connection established", host)

        # 1) Device facts.
        try:
            show_version = send_read_only_command(
                connection,
                "show version",
                timeout,
            )
        except ReadTimeout as exc:
            reason = "show version command timeout"
            logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
            result.reason = reason
            result.status = "ERROR"
            return result
        except Exception as exc:
            reason = f"show version command failed: {compact_exception(exc)}"
            logger.error("[%s] %s", host, reason)
            result.reason = reason
            result.status = "ERROR"
            return result

        try:
            result.model = parse_model(show_version)
        except ValueError as exc:
            critical_errors.append(str(exc))
            logger.error("[%s] %s", host, exc)

        try:
            result.running_version = parse_version(show_version)
        except ValueError as exc:
            critical_errors.append(str(exc))
            logger.error("[%s] %s", host, exc)

        if result.model != "-":
            if is_supported_catalyst_model(result.model):
                logger.info(
                    "[%s] Detected model=%s version=%s",
                    host,
                    result.model,
                    result.running_version,
                )
            else:
                message = f"Unsupported model for V1: {result.model}"
                critical_errors.append(message)
                logger.error("[%s] %s", host, message)

        # 2) bootflash image presence and free space.
        try:
            dir_output = send_read_only_command(
                connection,
                "dir bootflash:",
                timeout,
            )
        except ReadTimeout as exc:
            reason = "bootflash directory command timeout"
            logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
            critical_errors.append(reason)
            result.reason = "; ".join(critical_errors)
            result.status = "ERROR"
            return result
        except Exception as exc:
            reason = f"bootflash directory command failed: {compact_exception(exc)}"
            logger.error("[%s] %s", host, reason)
            critical_errors.append(reason)
            result.reason = "; ".join(critical_errors)
            result.status = "ERROR"
            return result

        result.image_found = (
            "YES"
            if check_image_exists(dir_output, image_config.image)
            else "NO"
        )
        logger.info(
            "[%s] Target image %s",
            host,
            "found" if result.image_found == "YES" else "not found",
        )

        try:
            result.free_space_bytes = parse_free_space(dir_output)
            result.space_check = validate_space(
                result.free_space_bytes,
                image_config.required_space,
            )
            logger.info(
                "[%s] Free bootflash space=%d bytes required=%d bytes result=%s",
                host,
                result.free_space_bytes,
                image_config.required_space,
                result.space_check,
            )
            if result.space_check == "FAIL":
                validation_failures.append("Insufficient bootflash space")
                logger.warning("[%s] Insufficient bootflash space", host)
        except ValueError as exc:
            result.space_check = "ERROR"
            critical_errors.append(str(exc))
            logger.error("[%s] %s", host, exc)

        # 3) MD5 only when the target image exists.
        if result.image_found == "NO":
            result.md5_check = "NOT FOUND"
            validation_failures.append("Target image not found in bootflash")
        else:
            md5_timeout = max(MIN_MD5_TIMEOUT, timeout * 10)
            logger.info(
                "[%s] Starting MD5 verification with read_timeout=%d seconds",
                host,
                md5_timeout,
            )
            try:
                result.calculated_md5 = calculate_md5(
                    connection,
                    image_config.image,
                    md5_timeout,
                )
                logger.info(
                    "[%s] Calculated MD5=%s",
                    host,
                    result.calculated_md5,
                )
                result.md5_check = validate_md5(
                    image_config.md5sum,
                    result.calculated_md5,
                )
                if result.md5_check == "FAIL":
                    validation_failures.append("MD5 mismatch")
                    logger.warning("[%s] MD5 mismatch", host)
            except ReadTimeout as exc:
                result.md5_check = "ERROR"
                reason = "MD5 verification command timeout"
                critical_errors.append(reason)
                logger.error(
                    "[%s] %s: %s",
                    host,
                    reason,
                    compact_exception(exc),
                )
            except ValueError as exc:
                result.md5_check = "ERROR"
                critical_errors.append(str(exc))
                logger.error("[%s] %s", host, exc)
            except Exception as exc:
                result.md5_check = "ERROR"
                reason = f"MD5 verification failed: {compact_exception(exc)}"
                critical_errors.append(reason)
                logger.error("[%s] %s", host, reason)

        # 4) Final status.
        all_reasons = critical_errors + validation_failures
        if critical_errors:
            result.status = "ERROR"
            result.reason = "; ".join(all_reasons)
        elif validation_failures:
            result.status = "FAIL"
            result.reason = "; ".join(validation_failures)
        else:
            result.status = "PASS"
            result.reason = "Image verification successful"

        logger.info(
            "[%s] Validation completed status=%s reason=%s",
            host,
            result.status,
            result.reason,
        )
        return result

    except NetmikoAuthenticationException as exc:
        reason = "Authentication failed"
        logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
        result.status = "ERROR"
        result.reason = reason
        return result

    except NetmikoTimeoutException as exc:
        reason = "SSH connection timeout"
        logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
        result.status = "ERROR"
        result.reason = reason
        return result

    except socket.gaierror as exc:
        reason = "DNS resolution failed"
        logger.error("[%s] %s: %s", host, reason, compact_exception(exc))
        result.status = "ERROR"
        result.reason = reason
        return result

    except OSError as exc:
        reason = f"SSH/network failure: {compact_exception(exc)}"
        logger.error("[%s] %s", host, reason)
        result.status = "ERROR"
        result.reason = reason
        return result

    except Exception as exc:
        reason = f"Unexpected validation error: {compact_exception(exc)}"
        logger.exception("[%s] %s", host, reason)
        result.status = "ERROR"
        result.reason = reason
        return result

    finally:
        if connection is not None:
            try:
                connection.disconnect()
                logger.debug("[%s] SSH connection closed", host)
            except Exception as exc:
                logger.warning(
                    "[%s] Error while closing SSH connection: %s",
                    host,
                    compact_exception(exc),
                )


# =============================================================================
# SECTION 11 - PARALLEL EXECUTION
# =============================================================================
# ThreadPoolExecutor handles concurrent devices. Workers never write shared
# report files; results are collected and reordered by inventory position.

def run_parallel_validation(
    hosts: list[str],
    image_config: ImageConfig,
    credentials: Credentials,
    workers: int,
    timeout: int,
    logger: logging.Logger,
    console: Console,
    version_only: bool = False,
) -> list[DeviceResult]:
    """
    Execute device validation concurrently.

    ThreadPoolExecutor schedules up to 'workers' devices at the same time.
    Futures are consumed with as_completed() so a free worker can immediately
    process the next pending device.

    Completion order is intentionally separated from report order. Results are
    stored by their original inventory index and reconstructed in hosts.txt
    order after all futures complete.
    """
    results_by_index: dict[int, DeviceResult] = {}

    mode_name = (
        "Post-upgrade version validation"
        if version_only
        else "Full image validation"
    )
    worker_function = validate_version_only if version_only else validate_device

    console.print(f"\n[bold]{mode_name}...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("Completed: {task.completed}/{task.total}"),
        console=console,
        transient=False,
    ) as progress:
        task_description = (
            "IOS-XE version audit" if version_only else "Cisco IOS-XE audit"
        )
        task_id = progress.add_task(task_description, total=len(hosts))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(
                    worker_function,
                    index,
                    host,
                    image_config,
                    credentials,
                    timeout,
                    logger,
                ): (index, host)
                for index, host in enumerate(hosts)
            }

            for future in as_completed(future_map):
                index, host = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    reason = (
                        "Unhandled worker exception: "
                        f"{compact_exception(exc)}"
                    )
                    logger.exception("[%s] %s", host, reason)
                    result = build_error_result(
                        index,
                        host,
                        image_config,
                        reason,
                    )

                results_by_index[index] = result
                progress.advance(task_id)

    return [results_by_index[index] for index in range(len(hosts))]


# =============================================================================
# SECTION 12 - REPORT GENERATION AND TERMINAL PRESENTATION
# =============================================================================
# CSV output is written only after workers finish. Terminal output is also
# rendered centrally to avoid interleaved thread output.

def write_csv(
    results: Iterable[DeviceResult],
    output_path: str,
    version_only: bool = False,
) -> None:
    """
    Write the final CSV report.

    Full mode writes Devices_Verified.csv.
    Version-only mode writes Version_Validation.csv with only version-related
    fields.

    IMPORTANT:
        This function must remain a main-thread operation. Worker threads must
        never write directly to the shared CSV file.
    """
    destination = Path(output_path)
    parent = destination.parent
    if parent != Path(".") and not parent.exists():
        raise FileNotFoundError(f"Output directory does not exist: {parent}")

    fields = VERSION_CSV_FIELDS if version_only else CSV_FIELDS

    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            row = (
                result.to_version_csv_row()
                if version_only
                else result.to_csv_row()
            )
            writer.writerow(row)


def human_bytes(value: int | None) -> str:
    """Render byte counts using decimal units for terminal display."""
    if value is None:
        return "-"

    units = ("B", "KB", "MB", "GB", "TB")
    number = float(value)
    for unit in units:
        if abs(number) < 1000.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(number)} {unit}"
            return f"{number:.2f} {unit}"
        number /= 1000.0
    return f"{value} B"


def unicode_supported() -> bool:
    """Best-effort check for status-symbol support."""
    encoding = (sys.stdout.encoding or "").lower()
    return "utf" in encoding


def terminal_check(value: str, unicode_ok: bool) -> str:
    """
    Format and color validation states for the Rich terminal table.

    Color policy:
        PASS      -> green
        FAIL      -> red
        ERROR     -> red
        NOT FOUND -> red

    Unknown or neutral values such as '-' remain uncolored.
    """
    symbols = {
        "PASS": "✓ PASS" if unicode_ok else "PASS",
        "FAIL": "✗ FAIL" if unicode_ok else "FAIL",
        "ERROR": "! ERROR" if unicode_ok else "ERROR",
        "NOT FOUND": "✗ NOT FOUND" if unicode_ok else "NOT FOUND",
    }

    rendered = symbols.get(value, value)

    if value == "PASS":
        return f"[bold green]{rendered}[/bold green]"

    if value in {"FAIL", "ERROR", "NOT FOUND"}:
        return f"[bold red]{rendered}[/bold red]"

    return rendered


def print_banner(console: Console) -> None:
    """Print a centered application banner."""
    width = 108
    console.print("=" * width)
    console.print(f"CISCO IMAGE VALIDATOR v{__version__}".center(width))
    console.print("=" * width)


def print_results(
    results: list[DeviceResult],
    console: Console,
    verbose: bool,
    version_only: bool = False,
) -> None:
    """Print the appropriate final result table after all workers finish."""
    unicode_ok = unicode_supported()
    print_banner(console)

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        pad_edge=False,
    )
    if version_only:
        table.add_column("Host", no_wrap=True)
        table.add_column("Model", no_wrap=True)
        table.add_column("Running Version", no_wrap=True)
        table.add_column("Target Version", no_wrap=True)
        table.add_column("Version Check", no_wrap=True)
        table.add_column("Status", no_wrap=True)

        for result in results:
            table.add_row(
                result.host,
                result.model,
                result.running_version,
                result.new_version,
                terminal_check(result.version_check, unicode_ok),
                terminal_check(result.status, unicode_ok),
            )
    else:
        table.add_column("Host", no_wrap=True)
        table.add_column("Model", no_wrap=True)
        table.add_column("Running Version", no_wrap=True)
        table.add_column("New Version", no_wrap=True)
        table.add_column("MD5 Check", no_wrap=True)
        table.add_column("Space Check", no_wrap=True)
        table.add_column("Free Space", justify="right", no_wrap=True)
        table.add_column("Status", no_wrap=True)

        for result in results:
            table.add_row(
                result.host,
                result.model,
                result.running_version,
                result.new_version,
                terminal_check(result.md5_check, unicode_ok),
                terminal_check(result.space_check, unicode_ok),
                human_bytes(result.free_space_bytes),
                terminal_check(result.status, unicode_ok),
            )

    console.print(table)

    if verbose:
        console.print("\n[bold]Device details[/bold]")
        for result in results:
            console.print(
                f"  {result.host}: {result.status} - {result.reason}"
            )


def print_summary(
    results: list[DeviceResult],
    image_config: ImageConfig,
    output_directory: Path,
    report_path: Path,
    log_path: Path,
    console: Console,
    version_only: bool = False,
) -> None:
    """Print the concise execution summary without device-count statistics."""
    width = 88
    console.print("\n" + "=" * width)
    console.print("SUMMARY")
    console.print("=" * width)
    console.print()
    if version_only:
        console.print("Mode                 : VERSION ONLY (POST-UPGRADE)")
        console.print(f"Target Version       : {image_config.version}")
    else:
        console.print("Mode                 : FULL IMAGE VALIDATION")
        console.print(f"Target Image         : {image_config.image}")
        console.print(f"Target Version       : {image_config.version}")
        console.print(f"Expected MD5         : {image_config.md5sum}")
        console.print(f"Image Size           : {human_bytes(image_config.image_size)}")
        console.print(
            "Required Free Space  : "
            f"{human_bytes(image_config.required_space)} (Image Size x 2)"
        )
    console.print()
    console.print(f"Output Folder        : {output_directory}")
    console.print(f"Report               : {report_path}")
    console.print(f"Log                  : {log_path}")
    console.print()
    console.print("=" * width)


# =============================================================================
# SECTION 13 - PROCESS EXIT STATUS
# =============================================================================
# Exit codes make the utility suitable for future pipeline/orchestration use.

def determine_exit_code(results: list[DeviceResult]) -> int:
    """
    Return a process exit code suitable for automation pipelines.

    0 = all devices passed
    1 = one or more validation failures, no ERROR results
    2 = one or more ERROR results
    """
    if any(result.status == "ERROR" for result in results):
        return 2
    if any(result.status == "FAIL" for result in results):
        return 1
    return 0


# =============================================================================
# SECTION 14 - APPLICATION ENTRY POINT
# =============================================================================
# main() coordinates CLI parsing, output setup, input loading, parallel
# validation, reporting, and the final process exit code.

def main() -> None:
    """Application entry point."""
    args = parse_arguments()
    console = Console()

    try:
        output_directory = build_output_directory(args.output)
    except OSError as exc:
        console.print(
            f"[bold red]ERROR:[/bold red] Could not create output directory: "
            f"{compact_exception(exc)}"
        )
        raise SystemExit(2) from exc

    report_name = (
        VERSION_REPORT_NAME if args.version_only else DEFAULT_REPORT_NAME
    )
    report_path = output_directory / report_name
    log_path = output_directory / DEFAULT_LOG_NAME
    logger = setup_logging(args.verbose, log_path)

    logger.info(
        "CiscoImageValidator v%s startup - Author: %s",
        __version__,
        __author__,
    )
    logger.info("Output directory=%s", output_directory)

    try:
        hosts = load_hosts(args.hosts)
        image_config = load_config(
            args.config,
            version_only=args.version_only,
        )
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.error("Startup validation failed: %s", compact_exception(exc))
        console.print(f"[bold red]ERROR:[/bold red] {compact_exception(exc)}")
        raise SystemExit(2) from exc

    password = args.password
    if password is None:
        password = getpass.getpass("SSH Password: ")

    credentials = Credentials(
        username=args.username,
        password=password,
    )

    logger.info("Hosts loaded=%d", len(hosts))
    logger.info("Worker count=%d", args.workers)
    logger.info(
        "Validation mode=%s",
        "VERSION_ONLY" if args.version_only else "FULL",
    )
    if not args.version_only:
        logger.info("Target image=%s", image_config.image)
    logger.info("Target version=%s", image_config.version)

    results = run_parallel_validation(
        hosts=hosts,
        image_config=image_config,
        credentials=credentials,
        workers=args.workers,
        timeout=args.timeout,
        logger=logger,
        console=console,
        version_only=args.version_only,
    )

    try:
        write_csv(
            results,
            str(report_path),
            version_only=args.version_only,
        )
    except OSError as exc:
        logger.error("Failed to write CSV: %s", compact_exception(exc))
        console.print(
            f"[bold red]ERROR:[/bold red] Could not write CSV report: "
            f"{compact_exception(exc)}"
        )
        raise SystemExit(2) from exc

    print_results(
        results,
        console,
        args.verbose,
        version_only=args.version_only,
    )
    print_summary(
        results,
        image_config,
        output_directory,
        report_path,
        log_path,
        console,
        version_only=args.version_only,
    )

    logger.info("CiscoImageValidator completion")
    raise SystemExit(determine_exit_code(results))


# =============================================================================
# SECTION 15 - SCRIPT EXECUTION GUARD
# =============================================================================

if __name__ == "__main__":
    main()
