#!/usr/bin/env python3
"""
Portdeco.py - PORT Decommission Validator, Config Generator & PRE/POST Checker

Purpose
-------
Portdeco is a production-oriented, read-only network automation utility for Cisco
IOS/IOS-XE access-switch decommission activities. The tool validates access
ports, reconciles configured and operational VLAN information, generates a local
configuration file for manual implementation, captures PRE/POST evidence,
optionally saves running-config backups, and creates one consolidated HTML
Side-by-Side PRE/POST comparison report.

Primary Workflows
-----------------
1. NORMAL VALIDATION / CONFIG GENERATION
   - Read switch/port/MAC records from CSV using tolerant English/Spanish header aliases.
   - Connect once per switch.
   - Collect read-only operational data.
   - Reconcile configured and operational Access/Voice VLANs.
   - Generate active configuration only for ports considered safe.
   - Comment unsafe configuration blocks for manual review.
   - Write Decommission_Config.txt, Port_Status.csv, and Port_decommission.log.

2. PRE-CHECKS
   - Capture raw evidence for each requested switch/port.
   - Optionally save a complete running-config backup per switch.
   - Save a machine-readable _snapshot.json used by later comparisons.

3. POST-CHECKS
   - Capture the same evidence after manual implementation.
   - Optionally save a POST running-config backup.
   - With --compare, match the POST inventory to the latest compatible PRE
     snapshot and generate one consolidated Port_Decommission_DIFF.html report.

Safety Model
------------
THIS IS A READ-ONLY DEVICE TOOL.

All commands sent to network devices pass through send_read_only_command().
That function rejects any command that does not begin with "show ". The program
contains no send_config_set(), config_mode(), write-memory, reload, or other
configuration-delivery path.

Commands such as "config t", "default interface", "shutdown", and "end" may
appear only inside locally generated configuration files. They are never sent
to a switch by this program.

Maintenance Guidelines
----------------------
- Keep VLAN reconciliation logic centralized in determine_final_vlan() and
  reconcile_vlan_information(). Do not duplicate VLAN decision logic elsewhere.
- Keep configuration-safety decisions centralized in should_comment_configuration().
- Any new device command MUST remain read-only and MUST be executed through
  send_read_only_command().
- Preserve the exact Port_Status.csv headers unless the external interface is
  intentionally versioned.
- If snapshot JSON structure changes, increment the snapshot schema and maintain
  backward-compatibility logic where practical.
- HTML output is intentionally self-contained (HTML/CSS/JavaScript in one file)
  so reports can be opened locally without a web server.

Author: Peskicorp
Python: 3.10+
Version: 2.1.0

Runtime Requirements
--------------------
    pip install netmiko rich ntc-templates
"""



# ==============================================================================
# SECTION 01 - STANDARD LIBRARY AND THIRD-PARTY DEPENDENCIES
# ==============================================================================
from __future__ import annotations

import argparse
import csv
import difflib
import getpass
import hashlib
import html
import json
import logging
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
except ImportError:  # Allows --help/--version without installed runtime dependency.
    ConnectHandler = None

    class NetmikoAuthenticationException(Exception):
        """Fallback placeholder used only when Netmiko is unavailable."""

    class NetmikoTimeoutException(Exception):
        """Fallback placeholder used only when Netmiko is unavailable."""

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text



# ==============================================================================
# SECTION 02 - GLOBAL CONSTANTS AND SAFETY ENUMERATIONS
# ==============================================================================
TOOL_NAME = "Portdeco - PORT Decommission Validator"
AUTHOR = "Peskicorp"
VERSION = "2.1.0"
DEFAULT_ACCESS_VLAN = "1"

PORT_CONNECTED = "CONNECTED"
PORT_NOT_CONNECTED = "NOT_CONNECTED"
PORT_ADMIN_DOWN = "ADMIN_DOWN"
PORT_ERR_DISABLED = "ERR_DISABLED"
PORT_NOT_FOUND = "NOT_FOUND"
PORT_ERROR = "ERROR"
PORT_UNKNOWN = "UNKNOWN"

ACCESS_OK = {"MATCH", "DEFAULT_CONFIRMED", "CONFIG_MISSING_OPERATIONAL_FOUND"}
VOICE_OK = {"MATCH", "NONE_CONFIRMED", "VOICE_CONFIG_MISSING"}

console = Console()


class DeviceConnectionError(RuntimeError):
    """Represent a switch-level SSH connection or authentication failure.

    Raising a dedicated exception lets the normal workflow abort transactionally:
    if any requested switch cannot be authenticated or reached, configuration and
    status output files are not generated for that run.
    """

    def __init__(self, switch: str, category: str, detail: str):
        self.switch = switch
        self.category = category
        self.detail = detail
        super().__init__(f"{switch}: {category}: {detail}")



# ==============================================================================
# SECTION 03 - DATA MODELS
# ==============================================================================
@dataclass(frozen=True)
class InputRecord:
    """One validated CSV input row identifying a switch, interface, and expected endpoint MAC."""
    switch: str
    port: str
    mac: str


@dataclass
class RunningConfigInfo:
    """Parsed values extracted from the current interface running configuration."""
    description: str = ""
    configured_access_vlan: str = "DEFAULT"
    configured_voice_vlan: str = "NONE"
    raw: str = ""


@dataclass
class SwitchportInfo:
    """Parsed operational switchport state collected from Cisco switchport output."""
    administrative_mode: str = "UNKNOWN"
    operational_mode: str = "UNKNOWN"
    operational_access_vlan: str = "UNKNOWN"
    operational_voice_vlan: str = "NONE"
    trunk_native_vlan: str = "UNKNOWN"
    negotiation: str = "UNKNOWN"
    raw: str = ""


@dataclass
class VlanDecision:
    """Decision for one VLAN dimension, including selected value, validation state, and safety."""
    final_vlan: str
    validation: str
    safe: bool


@dataclass
class ReconciledVlans:
    """Combined Access/Voice VLAN reconciliation result used by configuration safety logic."""
    final_access_vlan: str
    final_voice_vlan: str
    access_validation: str
    voice_validation: str
    overall_validation: str
    safe: bool


@dataclass
class PortResult:
    """Complete normal-mode result for one switch port, including generated configuration metadata."""
    switch: str
    port: str
    expected_mac: str
    detected_macs: list[str] = field(default_factory=list)
    description: str = ""
    configured_access_vlan: str = "UNKNOWN"
    operational_access_vlan: str = "UNKNOWN"
    final_access_vlan: str = "UNKNOWN"
    configured_voice_vlan: str = "UNKNOWN"
    operational_voice_vlan: str = "UNKNOWN"
    final_voice_vlan: str = "UNKNOWN"
    access_validation: str = "UNABLE_TO_VALIDATE"
    voice_validation: str = "UNABLE_TO_VALIDATE"
    vlan_validation_status: str = "UNABLE_TO_VALIDATE"
    port_status: str = PORT_UNKNOWN
    config_block: str = ""
    config_mode: str = "NONE"
    warning: str = ""
    error: str = ""


@dataclass
class CheckPortSnapshot:
    """Serializable PRE/POST evidence for one switch port used by snapshot and diff workflows."""
    switch: str
    port: str
    expected_mac: str
    timestamp: str
    port_status: str
    description: str
    access_vlan: str
    voice_vlan: str
    detected_macs: list[str]
    running_config: str
    switchport_output: str
    status_output: str
    mac_output: str
    error: str = ""




# ==============================================================================
# SECTION 04 - COMMAND-LINE INTERFACE AND LOGGING
# ==============================================================================
def parse_args() -> argparse.Namespace:
    """Build and validate the command-line interface.
    
    The parser supports two operating families: normal validation/config generation
    and PRE/POST check mode. Cross-option constraints are validated here so later
    workflow functions can assume a coherent argument set."""
    parser = argparse.ArgumentParser(
        description=(
            "Read-only Cisco port decommission validator/config generator with PRE/POST "
            "checks, running-config backups, and consolidated HTML Side-by-Side diff."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Normal validation + config generation
  python Portdeco.py -ho hosts.csv -u admin -t port_template.txt

  # Interactive PRE/POST checks
  python Portdeco.py -ho hosts.csv -u admin --checks

  # PRE checks with running-config backup
  python Portdeco.py -ho hosts.csv -u admin --checks --check-type pre --backup

  # POST checks + backup + consolidated HTML comparison
  python Portdeco.py -ho hosts.csv -u admin --checks --check-type post --backup --compare

Safety:
  Omitting --password is recommended; Portdeco prompts securely with getpass.
  Device sessions only execute commands beginning with "show ".
  SSH host-key files (known_hosts) are not used by this tool.
""",
    )

    parser.add_argument("-ho", "--hosts", required=True, help="Input CSV: Switch,Port,MAC")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (omit to prompt securely)")
    parser.add_argument("-t", "--template", help="Dynamic port template file (required outside --checks)")

    parser.add_argument("--output-config", default="Decommission_Config.txt")
    parser.add_argument("--output-status", default="Port_Status.csv")
    parser.add_argument("--log-file", default="Port_decommission.log")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=30)

    parser.add_argument("--checks", action="store_true", help="Run PRE/POST evidence collection mode")
    parser.add_argument("--check-type", choices=["pre", "post"], help="Skip menu and choose PRE or POST checks")
    parser.add_argument("--backup", action="store_true", help="Save show running-config backup per switch (requires --checks)")
    parser.add_argument("--compare", action="store_true", help="On POST checks, compare against latest PRE snapshot and generate one HTML report")
    parser.add_argument("--pre-dir", default="Pre_Checks", help="PRE snapshot root directory")
    parser.add_argument("--post-dir", default="Post_Checks", help="POST snapshot root directory")
    parser.add_argument("--comparison-dir", default="Comparisons", help="HTML comparison root directory")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    if args.backup and not args.checks:
        parser.error("--backup requires --checks")
    if args.compare and not args.checks:
        parser.error("--compare requires --checks")
    if not args.checks and not args.template:
        parser.error("--template/-t is required unless --checks is used")
    if args.compare and args.check_type == "pre":
        parser.error("--compare is intended for POST checks; use --check-type post")

    return args


def setup_logging(path: Path, level: str) -> logging.Logger:
    """Create the dedicated Portdeco file logger.
    
    The log file is opened in write mode for the current execution and intentionally
    does not propagate to the root logger, keeping console output concise."""
    logger = logging.getLogger("portdeco")
    logger.setLevel(getattr(logging, level.upper()))
    logger.handlers.clear()
    handler = logging.FileHandler(path, mode="w", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger




# ==============================================================================
# SECTION 05 - INPUT NORMALIZATION AND FILE VALIDATION
# ==============================================================================
def normalize_mac(value: str) -> str:
    """Normalize supported MAC address formats to Cisco dotted-lowercase notation.
    
    Raises ValueError when the supplied value does not contain exactly twelve
    hexadecimal digits."""
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(compact) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", compact):
        raise ValueError(f"Invalid MAC address: {value!r}")
    compact = compact.lower()
    return f"{compact[0:4]}.{compact[4:8]}.{compact[8:12]}"


def normalize_interface_name(name: str) -> str:
    """Normalize and validate common Cisco interface names safely.

    The previous implementation used a regular-expression alternation such as
    ``(?:gi|gig|gigabitethernet)``.  Because regex alternations are evaluated
    left-to-right, a full name like ``GigabitEthernet1/1/1`` matched the short
    ``gi`` prefix first and produced an invalid duplicated name such as
    ``GigabitEthernetgabitEthernet1/1/1``.

    This implementation avoids partial-prefix replacement entirely.  It splits
    the interface into an alphabetic interface type and a numeric interface ID,
    then maps the complete interface type to one canonical Cisco name.

    Accepted examples include::

        Gi1/0/1
        Gig1/0/1
        GigabitEthernet1/0/1
        Te1/0/1
        TenGigabitEthernet1/0/1
        TwentyFiveGigE1/0/1
        Fo1/0/1
        FortyGigabitEthernet1/0/1
        Hu1/0/1
        HundredGigabitEthernet1/0/1

    A malformed or unsupported interface raises ``ValueError`` instead of being
    silently passed to a Cisco show command.
    """
    raw = re.sub(r"\s+", "", (name or "").strip())
    if not raw:
        raise ValueError("Interface name cannot be empty")

    # Split the complete interface type from the numeric interface identifier.
    # Requiring the suffix to begin with a digit prevents partial-prefix matches.
    match = re.fullmatch(r"([A-Za-z][A-Za-z-]*)(\d+(?:/\d+)*(?:\.\d+)?)", raw)
    if not match:
        raise ValueError(f"Invalid Cisco interface format: {name!r}")

    interface_type, interface_id = match.groups()
    key = interface_type.lower()

    # IMPORTANT: keys represent complete interface-type tokens, not prefixes.
    aliases = {
        # Gigabit Ethernet
        "gi": "GigabitEthernet",
        "gig": "GigabitEthernet",
        "gigabit": "GigabitEthernet",
        "gigabitethernet": "GigabitEthernet",

        # Ten Gigabit Ethernet
        "te": "TenGigabitEthernet",
        "ten": "TenGigabitEthernet",
        "tengig": "TenGigabitEthernet",
        "tengigabitethernet": "TenGigabitEthernet",

        # Twenty-Five Gigabit Ethernet
        "tw": "TwentyFiveGigE",
        "twe": "TwentyFiveGigE",
        "twentyfivegige": "TwentyFiveGigE",
        "twentyfivegigabitethernet": "TwentyFiveGigE",

        # Forty Gigabit Ethernet
        "fo": "FortyGigabitEthernet",
        "fortygigabitethernet": "FortyGigabitEthernet",

        # Hundred Gigabit Ethernet
        "hu": "HundredGigabitEthernet",
        "hundredgige": "HundredGigabitEthernet",
        "hundredgigabitethernet": "HundredGigabitEthernet",

        # Common legacy/access interface types.
        "fa": "FastEthernet",
        "fastethernet": "FastEthernet",
        "eth": "Ethernet",
        "ethernet": "Ethernet",
    }

    canonical_type = aliases.get(key)
    if canonical_type is None:
        raise ValueError(f"Unsupported Cisco interface type: {interface_type!r}")

    return f"{canonical_type}{interface_id}"


def interface_short_name(name: str) -> str:
    """Return a Cisco-style short interface name used when matching show-command output."""
    replacements = [
        ("GigabitEthernet", "Gi"),
        ("TenGigabitEthernet", "Te"),
        ("TwentyFiveGigE", "Twe"),
        ("FortyGigabitEthernet", "Fo"),
        ("HundredGigabitEthernet", "Hu"),
    ]
    for long_name, short_name in replacements:
        if name.lower().startswith(long_name.lower()):
            return short_name + name[len(long_name):]
    return name


def normalize_csv_header(value: str) -> str:
    """Normalize a CSV header for tolerant, case-insensitive alias matching.

    Spaces, underscores, and hyphens are ignored. This allows operational teams
    to use common English or Spanish column names without changing the internal
    data model.
    """
    return re.sub(r"[\s_-]+", "", (value or "").strip().lower())


def read_hosts_csv(path: Path) -> list[InputRecord]:
    """Load and validate the input inventory CSV with tolerant header aliases.

    Required semantic fields are Switch, Port, and MAC, but the physical CSV
    headers are case-insensitive and may use supported aliases. Examples:

        Switch,Port,MAC
        switch,port,mac
        SWITCH,PORT,MAC
        switch,puerto,MAC
        hostname,interface,mac_address

    Supported aliases:
        Switch -> switch, hostname, host, device, equipo
        Port   -> port, puerto, interface, interfaz
        MAC    -> mac, macaddress, direccionmac, direcciónmac

    Duplicate switch/port pairs and invalid MAC/interface values are rejected
    before any network connection is attempted.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Hosts CSV not found: {path}")

    records: list[InputRecord] = []
    seen: set[tuple[str, str]] = set()

    alias_to_semantic = {
        # Switch/device column aliases.
        "switch": "Switch",
        "hostname": "Switch",
        "host": "Switch",
        "device": "Switch",
        "equipo": "Switch",

        # Interface/port column aliases.
        "port": "Port",
        "puerto": "Port",
        "interface": "Port",
        "interfaz": "Port",

        # MAC-address column aliases.
        "mac": "MAC",
        "macaddress": "MAC",
        "direccionmac": "MAC",
        "direcciónmac": "MAC",
    }

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("hosts.csv is empty or does not contain a header row")

        columns: dict[str, str] = {}
        for original_header in reader.fieldnames:
            normalized = normalize_csv_header(original_header)
            semantic = alias_to_semantic.get(normalized)
            if semantic is None:
                # Extra columns are intentionally ignored. This keeps the input
                # tolerant while preserving only the three fields the tool needs.
                continue
            if semantic in columns:
                raise ValueError(
                    f"hosts.csv contains multiple columns mapped to {semantic}: "
                    f"{columns[semantic]!r} and {original_header!r}"
                )
            columns[semantic] = original_header

        missing = [name for name in ("Switch", "Port", "MAC") if name not in columns]
        if missing:
            raise ValueError(
                "hosts.csv is missing required column(s): "
                + ", ".join(missing)
                + ". Accepted examples: Switch,Port,MAC or switch,puerto,MAC"
            )

        for line_no, row in enumerate(reader, start=2):
            switch = (row.get(columns["Switch"]) or "").strip()
            raw_port = (row.get(columns["Port"]) or "").strip()
            raw_mac = (row.get(columns["MAC"]) or "").strip()

            if not switch:
                raise ValueError(f"Line {line_no}: Switch/hostname is required")

            try:
                port = normalize_interface_name(raw_port)
            except ValueError as exc:
                raise ValueError(f"Line {line_no}: {exc}") from exc

            try:
                mac = normalize_mac(raw_mac)
            except ValueError as exc:
                raise ValueError(f"Line {line_no}: {exc}") from exc

            key = (switch.lower(), port.lower())
            if key in seen:
                raise ValueError(f"Line {line_no}: duplicate Switch/Port: {switch},{port}")
            seen.add(key)
            records.append(InputRecord(switch=switch, port=port, mac=mac))

    if not records:
        raise ValueError("hosts.csv contains no data rows")
    return records


def load_and_validate_template(path: Path) -> str:
    """Load the dynamic port template and enforce template safety requirements.
    
    The template must use dynamic Access VLAN and Voice VLAN placeholders. A static
    Access VLAN is rejected to prevent accidental hard-coded changes."""
    if not path.is_file():
        raise FileNotFoundError(f"Template not found: {path}")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError("Template is empty")
    required = {"{ACCESS_VLAN}", "{VOICE_VLAN_CONFIG}"}
    missing = sorted(v for v in required if v not in text)
    if missing:
        raise ValueError(f"Template missing required variable(s): {', '.join(missing)}")
    static_access = re.search(
        r"(?mi)^\s*switchport\s+access\s+vlan\s+(?!\{ACCESS_VLAN\}\s*$)\S+\s*$",
        text,
    )
    if static_access:
        raise ValueError("Template contains a static Access VLAN. Use: switchport access vlan {ACCESS_VLAN}")
    return text




# ==============================================================================
# SECTION 06 - CISCO OUTPUT PARSING
# ==============================================================================
def parse_interface_status(show_status: str, target_port: str) -> str:
    """Map one interface from `show interfaces status` to the internal status enum.
    
    The parser accepts both long and short interface naming and fails closed to
    UNKNOWN/NOT_FOUND when the state cannot be established safely."""
    target_long = normalize_interface_name(target_port).lower()
    target_short = interface_short_name(target_port).lower()
    for raw_line in show_status.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        first = line.split()[0]
        if normalize_interface_name(first).lower() != target_long and first.lower() != target_short:
            continue
        low = line.lower()
        if re.search(r"\berr-?disabled\b", low):
            return PORT_ERR_DISABLED
        if re.search(r"\bnotconnect\b|\bnot-connected\b", low):
            return PORT_NOT_CONNECTED
        if re.search(r"\bconnected\b", low):
            return PORT_CONNECTED
        if re.search(r"\bdisabled\b", low):
            return PORT_ADMIN_DOWN
        return PORT_UNKNOWN
    return PORT_NOT_FOUND


def extract_status_line(show_status: str, target_port: str) -> str:
    """Return the raw matching line from `show interfaces status` for evidence files."""
    target_long = normalize_interface_name(target_port).lower()
    target_short = interface_short_name(target_port).lower()
    for raw in show_status.splitlines():
        line = raw.rstrip()
        parts = line.split()
        if not parts:
            continue
        first = parts[0]
        if normalize_interface_name(first).lower() == target_long or first.lower() == target_short:
            return line
    return "PORT NOT FOUND IN show interfaces status"


def parse_running_interface_config(output: str) -> RunningConfigInfo:
    """Extract description, configured Access VLAN, and configured Voice VLAN.
    
    Missing explicit Access VLAN is represented as DEFAULT; missing Voice VLAN is
    represented as NONE. Raw output is retained for troubleshooting/evidence."""
    info = RunningConfigInfo(raw=output)
    for raw in output.splitlines():
        line = raw.strip()
        m = re.match(r"description\s+(.+)$", line, re.IGNORECASE)
        if m:
            info.description = m.group(1).strip()
            continue
        m = re.match(r"switchport\s+access\s+vlan\s+(\d+)$", line, re.IGNORECASE)
        if m:
            info.configured_access_vlan = m.group(1)
            continue
        m = re.match(r"switchport\s+voice\s+vlan\s+(\d+|none|dot1p|untagged)$", line, re.IGNORECASE)
        if m:
            value = m.group(1).upper()
            info.configured_voice_vlan = "NONE" if value == "NONE" else value
    return info


def _clean_vlan_token(value: str, *, voice: bool = False) -> str:
    """Normalize a VLAN token from Cisco operational output into a stable internal value."""
    value = (value or "").strip()
    if not value:
        return "NONE" if voice else "UNKNOWN"
    low = value.lower()
    if voice and low in {"none", "n/a", "unassigned"}:
        return "NONE"
    m = re.search(r"\b(\d+)\b", value)
    if m:
        return m.group(1)
    if voice and low in {"dot1p", "untagged"}:
        return low.upper()
    return "UNKNOWN"


def parse_switchport_output(output: str) -> SwitchportInfo:
    """Parse operational switchport fields required for VLAN validation.
    
    Only fields used by this tool are extracted; the raw output is preserved in the
    returned object for evidence and troubleshooting."""
    info = SwitchportInfo(raw=output)
    field_map = {
        "administrative mode": "administrative_mode",
        "operational mode": "operational_mode",
        "access mode vlan": "operational_access_vlan",
        "voice vlan": "operational_voice_vlan",
        "trunking native mode vlan": "trunk_native_vlan",
        "negotiation of trunking": "negotiation",
    }
    for raw in output.splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip().lower()
        if key not in field_map:
            continue
        attr = field_map[key]
        value = value.strip()
        if attr == "operational_access_vlan":
            value = _clean_vlan_token(value)
        elif attr == "operational_voice_vlan":
            value = _clean_vlan_token(value, voice=True)
        elif attr == "trunk_native_vlan":
            value = _clean_vlan_token(value)
        setattr(info, attr, value or "UNKNOWN")
    return info




# ==============================================================================
# SECTION 07 - VLAN RECONCILIATION AND SAFETY DECISIONS
# ==============================================================================
def determine_final_vlan(
    configured_vlan: str,
    operational_vlan: str,
    default_vlan: str = DEFAULT_ACCESS_VLAN,
    *,
    voice: bool = False,
) -> VlanDecision:
    """Reconcile configured and operational values for one VLAN dimension.
    
    This is the central source-of-truth function for Access or Voice VLAN selection.
    It returns the proposed final value, a validation state, and whether that VLAN
    dimension is safe for active configuration."""
    configured = (configured_vlan or "UNKNOWN").upper()
    operational = (operational_vlan or "UNKNOWN").upper()
    missing_config = "NONE" if voice else "DEFAULT"
    missing_operational = {"UNKNOWN", "", "N/A"}

    if operational in missing_operational:
        proposed = configured_vlan if configured not in {missing_config, "UNKNOWN"} else ("NONE" if voice else "UNKNOWN")
        return VlanDecision(str(proposed), "UNABLE_TO_VALIDATE", False)
    if configured == "UNKNOWN":
        return VlanDecision(operational_vlan, "UNABLE_TO_VALIDATE", False)

    if voice:
        if configured == "NONE" and operational == "NONE":
            return VlanDecision("NONE", "NONE_CONFIRMED", True)
        if configured == "NONE" and operational != "NONE":
            return VlanDecision(operational_vlan, "VOICE_CONFIG_MISSING", True)
        if configured != "NONE" and operational == "NONE":
            return VlanDecision(configured_vlan, "VOICE_VLAN_MISMATCH", False)
        if configured == operational:
            return VlanDecision(configured_vlan, "MATCH", True)
        return VlanDecision(configured_vlan, "VOICE_VLAN_MISMATCH", False)

    if configured == "DEFAULT":
        if operational == str(default_vlan):
            return VlanDecision(str(default_vlan), "DEFAULT_CONFIRMED", True)
        return VlanDecision(operational_vlan, "CONFIG_MISSING_OPERATIONAL_FOUND", True)
    if configured == operational:
        return VlanDecision(configured_vlan, "MATCH", True)
    return VlanDecision(configured_vlan, "MISMATCH", False)


def reconcile_vlan_information(
    configured_access_vlan: str,
    operational_access_vlan: str,
    configured_voice_vlan: str,
    operational_voice_vlan: str,
) -> ReconciledVlans:
    """Combine Access and Voice VLAN decisions into one port-level result.
    
    Overall validation precedence is applied here so the rest of the application
    does not need to duplicate mismatch/default/unable-to-validate rules."""
    access = determine_final_vlan(configured_access_vlan, operational_access_vlan)
    voice = determine_final_vlan(configured_voice_vlan, operational_voice_vlan, voice=True)

    if access.validation == "MISMATCH":
        overall = "MISMATCH"
    elif voice.validation == "VOICE_VLAN_MISMATCH":
        overall = "VOICE_VLAN_MISMATCH"
    elif access.validation == "UNABLE_TO_VALIDATE" or voice.validation == "UNABLE_TO_VALIDATE":
        overall = "UNABLE_TO_VALIDATE"
    elif access.validation == "CONFIG_MISSING_OPERATIONAL_FOUND":
        overall = "CONFIG_MISSING_OPERATIONAL_FOUND"
    elif access.validation == "DEFAULT_CONFIRMED":
        overall = "DEFAULT_CONFIRMED"
    elif voice.validation == "VOICE_CONFIG_MISSING":
        overall = "VOICE_CONFIG_MISSING"
    else:
        overall = "MATCH"

    return ReconciledVlans(
        final_access_vlan=access.final_vlan,
        final_voice_vlan=voice.final_vlan,
        access_validation=access.validation,
        voice_validation=voice.validation,
        overall_validation=overall,
        safe=access.safe and voice.safe,
    )


def should_comment_configuration(port_status: str, access_validation: str, voice_validation: str) -> bool:
    """Return True when a generated configuration block must be commented.
    
    Only NOT_CONNECTED or ADMIN_DOWN ports with successful Access and Voice VLAN
    validation may produce active configuration."""
    if port_status not in {PORT_NOT_CONNECTED, PORT_ADMIN_DOWN}:
        return True
    if access_validation not in ACCESS_OK:
        return True
    if voice_validation not in VOICE_OK:
        return True
    return False




# ==============================================================================
# SECTION 08 - CONFIGURATION TEMPLATE RENDERING
# ==============================================================================
def render_template(template: str, *, access_vlan: str, voice_vlan: str, switch: str, port: str) -> str:
    """Render the dynamic decommission template for one port.
    
    VOICE_VLAN_CONFIG is omitted when the final Voice VLAN is NONE. Unresolved
    placeholders and unusable Access VLAN values raise an exception."""
    if access_vlan in {"UNKNOWN", "DEFAULT", ""}:
        raise ValueError(f"Unsafe/invalid final Access VLAN: {access_vlan}")
    voice_line = "" if voice_vlan == "NONE" else f"switchport voice vlan {voice_vlan}"
    replacements = {
        "{ACCESS_VLAN}": access_vlan,
        "{VOICE_VLAN}": voice_vlan,
        "{VOICE_VLAN_CONFIG}": voice_line,
        "{SWITCH}": switch,
        "{PORT}": port,
    }
    rendered = template
    for key, value in replacements.items():
        rendered = rendered.replace(key, value)
    lines = [line.rstrip() for line in rendered.splitlines() if line.strip()]
    unresolved = re.findall(r"\{[A-Z0-9_]+\}", "\n".join(lines))
    if unresolved:
        raise ValueError(f"Unresolved template variable(s): {', '.join(sorted(set(unresolved)))}")
    return "\n".join(lines)


def comment_config_block(block: str) -> str:
    """Prefix every meaningful configuration line with `!` for manual-review safety."""
    lines: list[str] = []
    for line in block.splitlines():
        if not line or line.strip() == "!":
            lines.append("!")
        else:
            lines.append("!" + line)
    return "\n".join(lines)




# ==============================================================================
# SECTION 09 - MAC PARSING, COMMAND VALIDATION, AND SSH SAFETY
# ==============================================================================
def parse_mac_table(output: str) -> list[str]:
    """Extract and normalize unique MAC addresses from Cisco MAC-table output."""
    found: list[str] = []
    for token in re.findall(
        r"(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}|(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|\b[0-9A-Fa-f]{12}\b",
        output,
    ):
        try:
            mac = normalize_mac(token)
            if mac not in found:
                found.append(mac)
        except ValueError:
            pass
    return found


def command_error(output: str) -> bool:
    """Detect common Cisco CLI error text in command output."""
    low = (output or "").lower()
    indicators = ["% invalid input", "% incomplete command", "% ambiguous command", "invalid input detected", "not found"]
    return any(item in low for item in indicators)


def send_read_only_command(connection, command: str, *, read_timeout: int = 60) -> str:
    """Execute a command only when it begins with `show `.
    
    This function is the primary runtime safety boundary. All device commands must
    pass through this function. Never bypass it when adding new data collection."""
    if not command.strip().lower().startswith("show "):
        raise RuntimeError(f"SAFETY BLOCK: non-show command rejected: {command}")
    return connection.send_command(command, read_timeout=read_timeout)


def connection_params(switch: str, username: str, password: str, timeout: int) -> dict:
    """Build Netmiko connection parameters for a Cisco IOS/IOS-XE switch.

    Netmiko uses Paramiko as its SSH transport by default. This tool deliberately
    disables SSH host-key file validation so it does not read or require entries
    from the user's ``known_hosts`` file. Authentication still uses the supplied
    username/password credentials.
    """
    return {
        "device_type": "cisco_ios",
        "host": switch,
        "username": username,
        "password": password,
        "conn_timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
        # Do not consult ~/.ssh/known_hosts or system SSH host-key files.
        # This avoids first-connect failures for switches that are not pre-registered.
        "ssh_strict": False,
        "system_host_keys": False,
        "alt_host_keys": False,
        "fast_cli": False,
    }


def get_switchport_output(connection, port: str) -> str:
    """Collect switchport output using IOS syntax fallbacks without leaving read-only mode."""
    last = ""
    for command in (f"show interfaces {port} switchport", f"show interface {port} switchport"):
        last = send_read_only_command(connection, command)
        if last.strip() and not command_error(last):
            return last
    return last




# ==============================================================================
# SECTION 10 - CONFIGURATION BLOCK SAFETY AND WARNING GENERATION
# ==============================================================================
def build_warning(port_status: str, vlans: ReconciledVlans) -> str:
    """Translate port/VLAN safety conditions into the concise terminal warning string."""
    if port_status == PORT_ERROR:
        return "ERROR - NO ACTIVE CONFIG"
    if port_status == PORT_NOT_FOUND:
        return "PORT NOT FOUND - NO ACTIVE CONFIG"
    if vlans.access_validation == "MISMATCH":
        return "VLAN MISMATCH - CONFIG COMMENTED"
    if vlans.voice_validation == "VOICE_VLAN_MISMATCH":
        return "VOICE VLAN MISMATCH - CONFIG COMMENTED"
    if "UNABLE_TO_VALIDATE" in {vlans.access_validation, vlans.voice_validation}:
        return "VLAN VALIDATION FAILED - CONFIG COMMENTED"
    if port_status == PORT_CONNECTED:
        return "PORT CONNECTED - CONFIG COMMENTED"
    if port_status == PORT_ERR_DISABLED:
        return "PORT ERR-DISABLED - CONFIG COMMENTED"
    if port_status == PORT_UNKNOWN:
        return "PORT STATUS UNKNOWN - CONFIG COMMENTED"
    return ""


def warning_header(result: PortResult) -> list[str]:
    """Build review banners placed above commented configuration blocks."""
    lines: list[str] = []
    if result.port_status == PORT_CONNECTED:
        lines.append("!!!!PORT CONNECTED BE CAREFUL")
    if result.access_validation == "MISMATCH":
        lines.append("!!!!VLAN MISMATCH - REVIEW REQUIRED")
    if result.voice_validation == "VOICE_VLAN_MISMATCH":
        lines.append("!!!!VOICE VLAN MISMATCH - REVIEW REQUIRED")
    if "UNABLE_TO_VALIDATE" in {result.access_validation, result.voice_validation}:
        lines.append("!!!!VLAN VALIDATION FAILED - REVIEW REQUIRED")
    if result.port_status == PORT_ERR_DISABLED:
        lines.append("!!!!PORT ERR-DISABLED - REVIEW REQUIRED")
    if result.port_status == PORT_UNKNOWN:
        lines.append("!!!!PORT STATUS UNKNOWN - REVIEW REQUIRED")
    return lines


def build_config_block(result: PortResult, template: str, commented: bool) -> str:
    """Create one local configuration block from the reconciled port result.
    
    The block may contain configuration commands, but this function only returns
    text; it does not interact with a network device."""
    body = render_template(
        template,
        access_vlan=result.final_access_vlan,
        voice_vlan=result.final_voice_vlan,
        switch=result.switch,
        port=result.port,
    )
    commands = (
        f"default interface {result.port}\n"
        "!\n"
        f"interface {result.port}\n"
        + "\n".join(f" {line}" for line in body.splitlines())
        + "\nexit"
    )
    headers = warning_header(result)
    if commented:
        commented_commands = comment_config_block(commands)
        return "\n".join(headers + ([commented_commands] if commented_commands else []))
    return "\n".join(headers + [commands]) if headers else commands


def log_port_details(logger: logging.Logger, result: PortResult) -> None:
    """Write detailed per-port evidence and decision data to Port_decommission.log."""
    expected_present = result.expected_mac in result.detected_macs
    level = logging.WARNING if result.warning or result.error else logging.INFO
    lines = [
        f"Switch: {result.switch}",
        f"Port: {result.port}",
        f"Expected MAC: {result.expected_mac}",
        f"Detected MAC: {', '.join(result.detected_macs) if result.detected_macs else 'NONE'}",
        f"Expected MAC Present: {expected_present}",
        f"Configured Access VLAN: {result.configured_access_vlan}",
        f"Operational Access VLAN: {result.operational_access_vlan}",
        f"Final Access VLAN: {result.final_access_vlan}",
        f"Configured Voice VLAN: {result.configured_voice_vlan}",
        f"Operational Voice VLAN: {result.operational_voice_vlan}",
        f"Final Voice VLAN: {result.final_voice_vlan}",
        f"Access VLAN Validation: {result.access_validation}",
        f"Voice VLAN Validation: {result.voice_validation}",
        f"VLAN Validation Status: {result.vlan_validation_status}",
        f"Current Description: {result.description or 'NONE'}",
        f"Port Status: {result.port_status}",
        f"Config Mode: {result.config_mode}",
    ]
    if result.warning:
        lines.append(f"Action/Warning: {result.warning}")
    if result.error:
        lines.append(f"Error: {result.error}")
    logger.log(level, "\n" + "\n".join(lines) + "\n" + ("-" * 72))




# ==============================================================================
# SECTION 11 - NORMAL MODE SWITCH PROCESSING
# ==============================================================================
def process_switch(
    switch: str,
    records: list[InputRecord],
    *,
    username: str,
    password: str,
    timeout: int,
    template: str,
    logger: logging.Logger,
) -> list[PortResult]:
    """Process all requested ports on one switch using a single SSH connection.

    Connection establishment is treated separately from command processing. If
    authentication or SSH connection creation fails, ``DeviceConnectionError`` is
    raised to the parent workflow. The parent then aborts the run and intentionally
    does not generate Decommission_Config.txt or Port_Status.csv.

    After a successful connection, individual command/port failures remain visible
    as ERROR results so a connected device can still be audited safely.
    """
    results: list[PortResult] = []
    connection = None

    # --------------------------------------------------------------------------
    # Connection phase: fail the complete normal-mode run if a requested switch
    # cannot be authenticated or reached. Partial implementation files are unsafe.
    # --------------------------------------------------------------------------
    logger.info("Connecting to switch %s", switch)
    try:
        connection = ConnectHandler(**connection_params(switch, username, password, timeout))
    except NetmikoAuthenticationException as exc:
        logger.error("Authentication failed for %s: %s", switch, exc)
        raise DeviceConnectionError(
            switch,
            "AUTHENTICATION FAILED",
            "The switch rejected the supplied SSH credentials. Verify username, password, and AAA access.",
        ) from exc
    except NetmikoTimeoutException as exc:
        logger.error("Connection timeout for %s: %s", switch, exc)
        raise DeviceConnectionError(
            switch,
            "CONNECTION TIMEOUT",
            "The switch did not establish an SSH session before the timeout. Verify reachability, DNS/IP, SSH, and firewall path.",
        ) from exc
    except Exception as exc:
        # Some SSH/library versions may surface authentication failures through a
        # lower-level exception. Classify common credential wording professionally.
        detail_lower = str(exc).lower()
        if any(token in detail_lower for token in ("auth", "credential", "password", "permission denied")):
            category = "AUTHENTICATION FAILED"
            detail = "SSH authentication could not be completed. Verify username, password, and AAA access."
        else:
            category = "CONNECTION FAILED"
            detail = "SSH connection creation failed. Verify hostname/IP, reachability, SSH service, and network path."
        logger.exception("Connection creation failed for %s", switch)
        raise DeviceConnectionError(switch, category, detail) from exc

    try:
        show_status = send_read_only_command(connection, "show interfaces status")

        for record in records:
            result = PortResult(switch=switch, port=record.port, expected_mac=record.mac)
            try:
                result.port_status = parse_interface_status(show_status, record.port)
                if result.port_status == PORT_NOT_FOUND:
                    detail = send_read_only_command(connection, f"show interface {record.port}")
                    if detail.strip() and not command_error(detail):
                        result.port_status = PORT_UNKNOWN
                    else:
                        result.warning = "PORT NOT FOUND - NO CONFIG GENERATED"
                        result.config_mode = "NONE"
                        log_port_details(logger, result)
                        results.append(result)
                        continue

                run_output = send_read_only_command(connection, f"show running-config interface {record.port}")
                if command_error(run_output):
                    raise RuntimeError("Unable to read current interface running configuration")
                run_info = parse_running_interface_config(run_output)

                sw_output = get_switchport_output(connection, record.port)
                sw_info = (
                    SwitchportInfo(raw=sw_output)
                    if command_error(sw_output) or not sw_output.strip()
                    else parse_switchport_output(sw_output)
                )

                mac_output = send_read_only_command(connection, f"show mac address-table interface {record.port}")
                detected_macs = [] if command_error(mac_output) else parse_mac_table(mac_output)

                result.description = run_info.description
                result.configured_access_vlan = run_info.configured_access_vlan
                result.operational_access_vlan = sw_info.operational_access_vlan
                result.configured_voice_vlan = run_info.configured_voice_vlan
                result.operational_voice_vlan = sw_info.operational_voice_vlan
                result.detected_macs = detected_macs

                # Reconcile configured and operational VLAN data before any local
                # configuration text is generated. This is a mandatory safety gate.
                vlans = reconcile_vlan_information(
                    result.configured_access_vlan,
                    result.operational_access_vlan,
                    result.configured_voice_vlan,
                    result.operational_voice_vlan,
                )
                result.final_access_vlan = vlans.final_access_vlan
                result.final_voice_vlan = vlans.final_voice_vlan
                result.access_validation = vlans.access_validation
                result.voice_validation = vlans.voice_validation
                result.vlan_validation_status = vlans.overall_validation
                result.warning = build_warning(result.port_status, vlans)

                if result.final_access_vlan in {"UNKNOWN", "DEFAULT", ""}:
                    result.config_mode = "NONE"
                    result.warning = "VLAN VALIDATION FAILED - NO CONFIG GENERATED"
                else:
                    # Fail closed: anything outside explicitly safe port/VLAN states
                    # remains visible in the output file but is fully commented.
                    commented = should_comment_configuration(
                        result.port_status,
                        result.access_validation,
                        result.voice_validation,
                    )
                    result.config_block = build_config_block(result, template, commented)
                    result.config_mode = "COMMENTED" if commented else "ACTIVE"

            except Exception as exc:
                result.port_status = PORT_ERROR
                result.error = str(exc)
                result.warning = "ERROR - NO CONFIG GENERATED"
                result.config_mode = "NONE"
                logger.exception("Port processing error on %s %s", switch, record.port)

            log_port_details(logger, result)
            results.append(result)

    except Exception as exc:
        # The SSH session exists, but a switch-level command failed. Preserve the
        # condition as ERROR results instead of misreporting it as bad credentials.
        logger.exception("Switch-level command failure on %s", switch)
        results = []
        for record in records:
            result = PortResult(
                switch=switch,
                port=record.port,
                expected_mac=record.mac,
                port_status=PORT_ERROR,
                error=str(exc),
                warning="SWITCH COMMAND ERROR - NO CONFIG GENERATED",
                config_mode="NONE",
            )
            log_port_details(logger, result)
            results.append(result)
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                logger.debug("Disconnect failed for %s", switch, exc_info=True)

    return results



# ==============================================================================
# SECTION 12 - GENERATED FILES AND CONSOLE PRESENTATION
# ==============================================================================
def write_config_file(path: Path, results: Iterable[PortResult], switch_order: list[str]) -> None:
    """Write the manual implementation file grouped by switch.
    
    Each switch receives one header and one `config t`/`end` wrapper. Unsafe port
    blocks remain present but commented for manual review."""
    by_switch: dict[str, list[PortResult]] = defaultdict(list)
    for result in results:
        if result.config_block.strip():
            by_switch[result.switch].append(result)

    sections: list[str] = []
    for switch in switch_order:
        switch_results = by_switch.get(switch, [])
        if not switch_results:
            continue
        lines = [
            "!!====================================================================",
            f"!!Switch: {switch}",
            "!!====================================================================",
            "config t",
            "!",
        ]
        for result in switch_results:
            lines.append(result.config_block.rstrip())
            lines.append("!")
        lines.append("end")
        sections.append("\n".join(lines))

    content = "\n\n".join(sections)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")


def write_status_csv(path: Path, results: Iterable[PortResult]) -> None:
    """Write the intentionally minimal Port_Status.csv external report."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Switch", "Port", "Access Vlan", "Voice Vlan", "PortStatus"])
        for r in results:
            writer.writerow([r.switch, r.port, r.final_access_vlan, r.final_voice_vlan, r.port_status])


def print_main_banner() -> None:
    """Render a larger, centered normal-mode application banner."""
    banner = Text(justify="center")
    banner.append("PORT DECOMMISSION\n", style="bold bright_white")
    banner.append("VALIDATOR", style="bold bright_cyan")
    width = min(84, max(44, console.size.width - 2))
    console.print(
        Panel(
            Align.center(banner),
            width=width,
            padding=(1, 3),
            border_style="bright_blue",
        )
    )


def make_switch_table(switch: str, results: list[PortResult]) -> Table:
    """Build the concise Rich table shown for one switch in normal mode."""
    table = Table(title=f"[bold green][+] {switch}[/bold green]", show_lines=False, header_style="bold")
    table.add_column("Port", style="bold")
    table.add_column("Access Vlan")
    table.add_column("Voice Vlan")
    table.add_column("Port Status")
    table.add_column("Warning")
    for r in results:
        warning = r.warning or (f"ERROR: {r.error}" if r.error else "")
        table.add_row(r.port, r.final_access_vlan, r.final_voice_vlan, r.port_status, warning)
    return table


def print_summary(results: list[PortResult], args: argparse.Namespace) -> None:
    """Print the simplified final port-status summary and generated file names."""
    statuses = Counter(r.port_status for r in results)
    console.print("=" * 68)
    console.print("                        PORT SUMMARY")
    console.print("=" * 68)
    console.print(f"Total Ports             : {len(results)}")
    console.print()
    console.print(f"Connected               : {statuses[PORT_CONNECTED]}")
    console.print(f"Not Connected           : {statuses[PORT_NOT_CONNECTED]}")
    console.print(f"Admin Down              : {statuses[PORT_ADMIN_DOWN]}")
    console.print(f"Err-Disabled            : {statuses[PORT_ERR_DISABLED]}")
    console.print(f"Not Found               : {statuses[PORT_NOT_FOUND]}")
    console.print(f"Errors                  : {statuses[PORT_ERROR]}")
    console.print()
    console.print("Files Generated:")
    console.print(f"    {args.output_config}")
    console.print(f"    {args.output_status}")
    console.print(f"    {args.log_file}")
    console.print("=" * 68)




# ==============================================================================
# SECTION 13 - PRE/POST CHECK COLLECTION
# ==============================================================================
def choose_check_type(args: argparse.Namespace) -> str:
    """Return PRE or POST check mode from CLI input or the interactive menu."""
    if args.check_type:
        return args.check_type.upper()
    console.print(Panel.fit("[bold]PORT DECOMMISSION CHECKS[/bold]"))
    console.print("\nSelect check type:\n")
    console.print("  [1] PRE-CHECKS")
    console.print("  [2] POST-CHECKS")
    while True:
        choice = input("\nSelection: ").strip()
        if choice == "1":
            return "PRE"
        if choice == "2":
            return "POST"
        console.print("[yellow]Please select 1 or 2.[/yellow]")


def sanitize_filename(value: str) -> str:
    """Convert a switch name into a filesystem-safe filename component."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def capture_switch_checks(
    switch: str,
    records: list[InputRecord],
    *,
    username: str,
    password: str,
    timeout: int,
    check_type: str,
    backup: bool,
    run_dir: Path,
    logger: logging.Logger,
) -> tuple[list[CheckPortSnapshot], str | None, str | None]:
    """Capture raw PRE/POST evidence for all requested ports on one switch.
    
    The function writes one human-readable evidence file per switch and optionally a
    full `show running-config` backup. All network operations remain read-only."""
    # PRE and POST capture intentionally use the same commands and data model so
    # comparisons describe real state changes rather than collection differences.
    snapshots: list[CheckPortSnapshot] = []
    connection = None
    switch_file = run_dir / f"{sanitize_filename(switch)}_{check_type}.txt"
    backup_file: Path | None = None
    try:
        connection = ConnectHandler(**connection_params(switch, username, password, timeout))
        show_clock = send_read_only_command(connection, "show clock")
        try:
            uptime = send_read_only_command(connection, "show version | include uptime")
            if command_error(uptime) or not uptime.strip():
                uptime = send_read_only_command(connection, "show version")
        except Exception:
            uptime = send_read_only_command(connection, "show version")
        show_status = send_read_only_command(connection, "show interfaces status")

        evidence: list[str] = [
            "=" * 78,
            f"{check_type}-CHECKS",
            f"Switch : {switch}",
            f"Date   : {datetime.now().isoformat(timespec='seconds')}",
            "=" * 78,
            "",
            "### show clock",
            show_clock.rstrip(),
            "",
            "### show version | include uptime",
            uptime.rstrip(),
            "",
        ]

        for record in records:
            now = datetime.now().isoformat(timespec="seconds")
            try:
                run_output = send_read_only_command(connection, f"show running-config interface {record.port}")
                sw_output = get_switchport_output(connection, record.port)
                mac_output = send_read_only_command(connection, f"show mac address-table interface {record.port}")
                status_line = extract_status_line(show_status, record.port)
                status = parse_interface_status(show_status, record.port)

                run_info = parse_running_interface_config(run_output) if not command_error(run_output) else RunningConfigInfo(raw=run_output)
                sw_info = parse_switchport_output(sw_output) if sw_output.strip() and not command_error(sw_output) else SwitchportInfo(raw=sw_output)
                detected = [] if command_error(mac_output) else parse_mac_table(mac_output)

                access = sw_info.operational_access_vlan
                if access == "UNKNOWN" and run_info.configured_access_vlan not in {"DEFAULT", "UNKNOWN"}:
                    access = run_info.configured_access_vlan
                voice = sw_info.operational_voice_vlan
                if voice == "NONE" and run_info.configured_voice_vlan not in {"NONE", "UNKNOWN"}:
                    voice = run_info.configured_voice_vlan

                snap = CheckPortSnapshot(
                    switch=switch,
                    port=record.port,
                    expected_mac=record.mac,
                    timestamp=now,
                    port_status=status,
                    description=run_info.description,
                    access_vlan=access,
                    voice_vlan=voice,
                    detected_macs=detected,
                    running_config=run_output,
                    switchport_output=sw_output,
                    status_output=status_line,
                    mac_output=mac_output,
                )
            except Exception as exc:
                logger.exception("%s check failed for %s %s", check_type, switch, record.port)
                snap = CheckPortSnapshot(
                    switch=switch,
                    port=record.port,
                    expected_mac=record.mac,
                    timestamp=now,
                    port_status=PORT_ERROR,
                    description="",
                    access_vlan="UNKNOWN",
                    voice_vlan="UNKNOWN",
                    detected_macs=[],
                    running_config="",
                    switchport_output="",
                    status_output="",
                    mac_output="",
                    error=str(exc),
                )

            snapshots.append(snap)
            evidence.extend([
                "-" * 78,
                f"PORT: {record.port}",
                "-" * 78,
                "",
                f"### show running-config interface {record.port}",
                snap.running_config.rstrip() or f"ERROR: {snap.error or 'No output'}",
                "",
                "### show interfaces status (matching port)",
                snap.status_output.rstrip() or f"ERROR: {snap.error or 'No output'}",
                "",
                f"### show interfaces {record.port} switchport",
                snap.switchport_output.rstrip() or f"ERROR: {snap.error or 'No output'}",
                "",
                f"### show mac address-table interface {record.port}",
                snap.mac_output.rstrip() or f"ERROR: {snap.error or 'No output'}",
                "",
            ])

        switch_file.write_text("\n".join(evidence).rstrip() + "\n", encoding="utf-8")

        # A backup is only a local copy of `show running-config`; no save/write
        # command is ever sent to the switch.
        if backup:
            backup_dir = run_dir / "Backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_file = backup_dir / f"{sanitize_filename(switch)}_RUNNING_CONFIG.txt"
            running = send_read_only_command(connection, "show running-config", read_timeout=180)
            backup_file.write_text(running.rstrip() + "\n", encoding="utf-8")

        return snapshots, str(switch_file), str(backup_file) if backup_file else None

    except Exception as exc:
        logger.exception("%s switch-level check failure on %s", check_type, switch)
        for record in records:
            snapshots.append(
                CheckPortSnapshot(
                    switch=switch,
                    port=record.port,
                    expected_mac=record.mac,
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                    port_status=PORT_ERROR,
                    description="",
                    access_vlan="UNKNOWN",
                    voice_vlan="UNKNOWN",
                    detected_macs=[],
                    running_config="",
                    switchport_output="",
                    status_output="",
                    mac_output="",
                    error=str(exc),
                )
            )
        switch_file.write_text(
            f"{check_type}-CHECKS\nSwitch: {switch}\nERROR: {exc}\n",
            encoding="utf-8",
        )
        return snapshots, str(switch_file), None
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                logger.debug("Disconnect failed for %s", switch, exc_info=True)




# ==============================================================================
# SECTION 14 - SNAPSHOT STORAGE AND PRE/POST MATCHING
# ==============================================================================
def inventory_signature(records: list[InputRecord]) -> str:
    """Create a stable SHA-256 signature for the Switch/Port/MAC inventory.
    
    The signature prevents a POST comparison from silently pairing with an unrelated
    PRE snapshot."""
    canonical = "\n".join(
        sorted(f"{r.switch.lower()}|{r.port.lower()}|{r.mac.lower()}" for r in records)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def save_snapshot_json(
    run_dir: Path,
    check_type: str,
    snapshots: list[CheckPortSnapshot],
    hosts_file: str,
    signature: str,
) -> Path:
    """Persist machine-readable PRE/POST data used by the comparison engine."""
    path = run_dir / "_snapshot.json"
    payload = {
        "schema": 1,
        "tool": "Portdeco.py",
        "version": VERSION,
        "check_type": check_type,
        "created": datetime.now().isoformat(timespec="seconds"),
        "hosts_file": hosts_file,
        "inventory_signature": signature,
        "ports": [asdict(s) for s in snapshots],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def find_latest_snapshot(root: Path, check_type: str, signature: str | None = None) -> Path | None:
    """Locate the newest compatible PRE/POST snapshot, optionally matching inventory signature."""
    if not root.is_dir():
        return None
    candidates: list[Path] = []
    for p in root.iterdir():
        snap = p / "_snapshot.json"
        if p.is_dir() and snap.is_file():
            try:
                data = json.loads(snap.read_text(encoding="utf-8"))
                if data.get("check_type") != check_type:
                    continue
                if signature and data.get("inventory_signature") != signature:
                    continue
                candidates.append(snap)
            except Exception:
                continue
    return max(candidates, key=lambda p: p.parent.name) if candidates else None


def load_snapshot(path: Path) -> dict:
    """Load a machine-readable snapshot JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))




# ==============================================================================
# SECTION 15 - SIDE-BY-SIDE DIFF ENGINE
# ==============================================================================
def normalized_config_lines(text: str) -> list[str]:
    """Normalize raw interface configuration into comparable logical lines."""
    lines: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip() == "!":
            continue
        if line.lower().startswith("building configuration") or line.lower().startswith("current configuration"):
            continue
        lines.append(line.strip())
    return lines


def side_by_side_rows(pre_text: str, post_text: str) -> list[tuple[str, str, str, str]]:
    """Convert PRE and POST configuration text into aligned Side-by-Side diff rows.
    
    Markers: `|` unchanged, `<` removed, `>` added, `!` modified."""
    pre = normalized_config_lines(pre_text)
    post = normalized_config_lines(post_text)
    # autojunk=False is important for network configurations because repeated CLI
    # tokens are meaningful and should not be discarded as low-value matches.
    matcher = difflib.SequenceMatcher(a=pre, b=post, autojunk=False)
    rows: list[tuple[str, str, str, str]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for l, r in zip(pre[i1:i2], post[j1:j2]):
                rows.append((l, "|", r, "same"))
        elif tag == "delete":
            for l in pre[i1:i2]:
                rows.append((l, "<", "", "removed"))
        elif tag == "insert":
            for r in post[j1:j2]:
                rows.append(("", ">", r, "added"))
        elif tag == "replace":
            left = pre[i1:i2]
            right = post[j1:j2]
            width = max(len(left), len(right))
            for idx in range(width):
                l = left[idx] if idx < len(left) else ""
                r = right[idx] if idx < len(right) else ""
                if l and r:
                    rows.append((l, "!", r, "modified"))
                elif l:
                    rows.append((l, "<", "", "removed"))
                else:
                    rows.append(("", ">", r, "added"))
    return rows


def snapshot_index(snapshot: dict) -> dict[tuple[str, str], dict]:
    """Index snapshot port dictionaries by (switch, port) for deterministic comparison."""
    return {(p["switch"], p["port"]): p for p in snapshot.get("ports", [])}


def compare_port(pre: dict, post: dict) -> dict:
    """Classify configuration, status, MAC, and overall PRE/POST result for one port.
    
    PASS means expected decommission-related changes were observed; REVIEW REQUIRED
    indicates unsafe or unexpected POST state. It is not a generic network-health verdict."""
    pre_cfg = normalized_config_lines(pre.get("running_config", ""))
    post_cfg = normalized_config_lines(post.get("running_config", ""))
    config_changed = pre_cfg != post_cfg
    status_changed = pre.get("port_status") != post.get("port_status")

    expected = post.get("expected_mac") or pre.get("expected_mac")
    pre_macs = set(pre.get("detected_macs") or [])
    post_macs = set(post.get("detected_macs") or [])
    pre_has = expected in pre_macs
    post_has = expected in post_macs

    if pre_has and not post_has:
        mac_state = "REMOVED"
    elif post_has:
        mac_state = "PRESENT"
    else:
        mac_state = "NO CHANGE"

    if post.get("error") or post.get("port_status") in {PORT_ERROR, PORT_NOT_FOUND, PORT_UNKNOWN, PORT_ERR_DISABLED}:
        result = "REVIEW REQUIRED"
    elif post_has or post.get("port_status") == PORT_CONNECTED:
        result = "REVIEW REQUIRED"
    elif config_changed or status_changed or mac_state == "REMOVED":
        result = "PASS"
    else:
        result = "NO CHANGE"

    return {
        "config": "CHANGED" if config_changed else "NO CHANGE",
        "status": "CHANGED" if status_changed else "NO CHANGE",
        "mac": mac_state,
        "result": result,
    }




# ==============================================================================
# SECTION 16 - CONSOLIDATED HTML REPORT GENERATION
# ==============================================================================
def generate_comparison_html(pre_snapshot: dict, post_snapshot: dict, output_path: Path) -> None:
    """Generate one self-contained HTML Side-by-Side report for all switches.
    
    The report embeds CSS and JavaScript, provides global/switch summaries, filters,
    quick navigation, and detailed per-port PRE/POST configuration/status/MAC views."""
    # Build one consolidated report: all switches and ports are indexed first, then
    # summarized globally and rendered as navigable per-switch/per-port sections.
    pre_idx = snapshot_index(pre_snapshot)
    post_idx = snapshot_index(post_snapshot)
    keys = list(dict.fromkeys(list(pre_idx.keys()) + list(post_idx.keys())))

    switch_order: list[str] = []
    for switch, _ in keys:
        if switch not in switch_order:
            switch_order.append(switch)

    comparisons: dict[str, list[dict]] = defaultdict(list)
    for key in keys:
        pre = pre_idx.get(key)
        post = post_idx.get(key)
        if pre is None:
            pre = {
                "switch": key[0], "port": key[1], "expected_mac": post.get("expected_mac", ""),
                "port_status": "NOT IN PRE", "access_vlan": "UNKNOWN", "voice_vlan": "UNKNOWN",
                "detected_macs": [], "running_config": "", "error": "Port not present in PRE snapshot",
            }
        if post is None:
            post = {
                "switch": key[0], "port": key[1], "expected_mac": pre.get("expected_mac", ""),
                "port_status": "NOT IN POST", "access_vlan": "UNKNOWN", "voice_vlan": "UNKNOWN",
                "detected_macs": [], "running_config": "", "error": "Port not present in POST snapshot",
            }
        comp = compare_port(pre, post)
        comparisons[key[0]].append({"pre": pre, "post": post, "comp": comp})

    all_items = [item for sw in switch_order for item in comparisons[sw]]
    total_ports = len(all_items)
    changed = sum(item["comp"]["result"] != "NO CHANGE" for item in all_items)
    no_change = sum(item["comp"]["result"] == "NO CHANGE" for item in all_items)
    mac_removed = sum(item["comp"]["mac"] == "REMOVED" for item in all_items)
    review = sum(item["comp"]["result"] == "REVIEW REQUIRED" for item in all_items)

    css = r"""
:root{--ink:#18212f;--muted:#64748b;--line:#dbe3ec;--panel:#fff;--bg:#f4f6f8}
*{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
header{background:linear-gradient(135deg,#0f172a,#1e293b);color:#fff;padding:24px 32px;position:sticky;top:0;z-index:10;box-shadow:0 2px 12px #0003}
header h1{margin:0;font-size:25px}header .meta{color:#cbd5e1;margin-top:6px;font-size:13px}.wrap{max-width:1500px;margin:auto;padding:24px}
.cards{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:12px;margin-bottom:20px}.card,.panel{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:0 2px 7px #0000000d}
.n{font-size:28px;font-weight:800}.label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
nav{display:flex;gap:8px;flex-wrap:wrap;align-items:center;background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px;margin:14px 0 20px}
button,a.btn{padding:8px 11px;border:1px solid #cbd5e1;border-radius:7px;background:#fff;text-decoration:none;color:#111827;cursor:pointer;font-weight:600}button:hover,a.btn:hover{background:#f8fafc}
table{width:100%;border-collapse:collapse;background:#fff;margin:10px 0 20px;border-radius:10px;overflow:hidden}th,td{padding:10px 12px;border-bottom:1px solid #e5e7eb;text-align:left;font-size:13px}th{background:#f8fafc;color:#475569}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:800}.pass{background:#dcfce7;color:#166534}.review{background:#ffedd5;color:#9a3412}.changed{background:#dbeafe;color:#1d4ed8}.nochange{background:#e5e7eb;color:#374151}.removed{background:#fee2e2;color:#991b1b}.present{background:#ffedd5;color:#9a3412}
.switch{margin-top:34px;scroll-margin-top:100px}.switch-title{display:flex;justify-content:space-between;gap:10px;align-items:center;background:#0f172a;color:white;padding:14px 16px;border-radius:10px 10px 0 0}.switch-title h2{margin:0;font-size:19px}
.port{background:#fff;border:1px solid var(--line);border-radius:10px;margin:16px 0;overflow:hidden;box-shadow:0 2px 7px #0000000d;scroll-margin-top:100px}.porthead{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;background:#f8fafc;border-bottom:1px solid #e5e7eb}.sec{font-size:11px;font-weight:800;padding:12px 14px 6px;color:#475569;text-transform:uppercase;letter-spacing:.06em}
.diff{display:grid;grid-template-columns:minmax(0,1fr) 44px minmax(0,1fr);font-family:Consolas,Monaco,monospace;font-size:12px}.diff>div{padding:6px 10px;border-top:1px solid #eef2f7;white-space:pre-wrap;word-break:break-word;min-height:30px}.hdr{font-family:Segoe UI,Arial,sans-serif;font-weight:800;background:#eef2f7}.mark{text-align:center;font-weight:900}.same{background:#fff}.modl{background:#fff7ed}.modr{background:#fef3c7}.add{background:#dcfce7}.del{background:#fee2e2}.marksame{background:#f8fafc;color:#64748b}.markmod{background:#fef3c7;color:#92400e}.markadd{background:#dcfce7;color:#166534}.markdel{background:#fee2e2;color:#991b1b}
.kv{display:grid;grid-template-columns:1fr 44px 1fr;font-family:Consolas,Monaco,monospace;font-size:12px}.kv>div{padding:8px 10px;border-top:1px solid #eef2f7}.mid{text-align:center;font-weight:900;background:#f8fafc}.result{display:flex;gap:8px;flex-wrap:wrap;padding:12px 14px;background:#fafafa}.hide{display:none!important}.legend{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.legend span{padding:5px 8px;border-radius:6px;border:1px solid #e5e7eb;font-size:12px}
footer{padding:28px;text-align:center;color:#64748b;font-size:12px}@media(max-width:850px){.cards{grid-template-columns:repeat(2,1fr)}.wrap{padding:12px}.diff{grid-template-columns:1fr 34px 1fr}.switch-title{align-items:flex-start;flex-direction:column}}
"""
    js = r"""
function applyFilter(mode){
 document.querySelectorAll('.port').forEach(el=>{
   const r=el.dataset.result, c=el.dataset.changed;
   let show=true;
   if(mode==='changed') show=(c==='yes');
   if(mode==='nochange') show=(r==='NO CHANGE');
   if(mode==='review') show=(r==='REVIEW REQUIRED');
   el.classList.toggle('hide',!show);
 });
}
"""

    def badge_class(kind: str, value: str) -> str:
        """Map comparison states to CSS badge classes used by the HTML report."""
        if kind == "result":
            return "pass" if value == "PASS" else ("review" if value == "REVIEW REQUIRED" else "nochange")
        if kind == "mac":
            return "removed" if value == "REMOVED" else ("present" if value == "PRESENT" else "nochange")
        return "changed" if value == "CHANGED" else "nochange"

    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Port Decommission PRE/POST Diff</title>",
        f"<style>{css}</style><script>{js}</script></head><body>",
        "<header><h1>PORT DECOMMISSION - PRE/POST DIFF</h1>",
        f"<div class='meta'>Generated: {html.escape(datetime.now().isoformat(timespec='seconds'))} &nbsp; | &nbsp; PRE: {html.escape(str(pre_snapshot.get('created','UNKNOWN')))} &nbsp; | &nbsp; POST: {html.escape(str(post_snapshot.get('created','UNKNOWN')))}</div></header>",
        "<div class='wrap'>",
        "<div class='cards'>",
        f"<div class='card'><div class='label'>Switches</div><div class='n'>{len(switch_order)}</div></div>",
        f"<div class='card'><div class='label'>Ports</div><div class='n'>{total_ports}</div></div>",
        f"<div class='card'><div class='label'>Changed</div><div class='n'>{changed}</div></div>",
        f"<div class='card'><div class='label'>MAC Removed</div><div class='n'>{mac_removed}</div></div>",
        f"<div class='card'><div class='label'>Review Required</div><div class='n'>{review}</div></div>",
        "</div>",
        "<nav><strong>Filters:</strong>",
        "<button onclick=\"applyFilter('all')\">ALL</button>",
        "<button onclick=\"applyFilter('changed')\">CHANGED</button>",
        "<button onclick=\"applyFilter('nochange')\">NO CHANGE</button>",
        "<button onclick=\"applyFilter('review')\">REVIEW REQUIRED</button>",
        "<strong style='margin-left:10px'>Jump to:</strong>",
    ]
    for sw in switch_order:
        parts.append(f"<a class='btn' href='#{html.escape(sanitize_filename(sw))}'>{html.escape(sw)}</a>")
    parts.append("</nav>")

    parts.append("<table><thead><tr><th>Switch</th><th>Ports</th><th>Changed</th><th>No Change</th><th>MAC Removed</th><th>Review Required</th></tr></thead><tbody>")
    for sw in switch_order:
        items = comparisons[sw]
        sw_changed = sum(i["comp"]["result"] != "NO CHANGE" for i in items)
        sw_no = sum(i["comp"]["result"] == "NO CHANGE" for i in items)
        sw_removed = sum(i["comp"]["mac"] == "REMOVED" for i in items)
        sw_review = sum(i["comp"]["result"] == "REVIEW REQUIRED" for i in items)
        parts.append(f"<tr><td><a href='#{html.escape(sanitize_filename(sw))}'>{html.escape(sw)}</a></td><td>{len(items)}</td><td>{sw_changed}</td><td>{sw_no}</td><td>{sw_removed}</td><td>{sw_review}</td></tr>")
    parts.append("</tbody></table>")
    parts.append("<div class='legend'><span style='background:#dcfce7'>GREEN = Added</span><span style='background:#fee2e2'>RED = Removed</span><span style='background:#fef3c7'>YELLOW = Modified</span><span>WHITE = No change</span></div>")

    for sw in switch_order:
        items = comparisons[sw]
        sw_changed = sum(i["comp"]["result"] != "NO CHANGE" for i in items)
        sw_no = sum(i["comp"]["result"] == "NO CHANGE" for i in items)
        sw_removed = sum(i["comp"]["mac"] == "REMOVED" for i in items)
        sw_review = sum(i["comp"]["result"] == "REVIEW REQUIRED" for i in items)
        sw_id = sanitize_filename(sw)
        parts.append(f"<section class='switch' id='{html.escape(sw_id)}'><div class='switch-title'><h2>{html.escape(sw)}</h2><div>Ports: {len(items)} &nbsp; | &nbsp; Changed: {sw_changed} &nbsp; | &nbsp; No Change: {sw_no} &nbsp; | &nbsp; MAC Removed: {sw_removed} &nbsp; | &nbsp; Review: {sw_review}</div></div>")
        parts.append("<table><thead><tr><th>Port</th><th>Config</th><th>Status</th><th>MAC</th><th>Result</th></tr></thead><tbody>")
        for item in items:
            post = item["post"]
            comp = item["comp"]
            anchor = sanitize_filename(f"{sw}-{post['port']}")
            parts.append(
                f"<tr><td><a href='#{html.escape(anchor)}'>{html.escape(post['port'])}</a></td>"
                f"<td><span class='badge {badge_class('config', comp['config'])}'>{comp['config']}</span></td>"
                f"<td><span class='badge {badge_class('status', comp['status'])}'>{comp['status']}</span></td>"
                f"<td><span class='badge {badge_class('mac', comp['mac'])}'>{comp['mac']}</span></td>"
                f"<td><span class='badge {badge_class('result', comp['result'])}'>{comp['result']}</span></td></tr>"
            )
        parts.append("</tbody></table>")

        for item in items:
            pre, post, comp = item["pre"], item["post"], item["comp"]
            anchor = sanitize_filename(f"{sw}-{post['port']}")
            changed_flag = "yes" if comp["result"] != "NO CHANGE" else "no"
            parts.append(f"<div class='port' id='{html.escape(anchor)}' data-result='{html.escape(comp['result'])}' data-changed='{changed_flag}'>")
            parts.append(f"<div class='porthead'><strong>{html.escape(post['port'])}</strong><span class='badge {badge_class('result', comp['result'])}'>{html.escape(comp['result'])}</span></div>")
            parts.append("<div class='sec'>Configuration</div><div class='diff'><div class='hdr'>PRE</div><div class='hdr'></div><div class='hdr'>POST</div>")
            for left, marker, right, kind in side_by_side_rows(pre.get("running_config", ""), post.get("running_config", "")):
                if kind == "same":
                    lc = rc = "same"; mc = "marksame"
                elif kind == "modified":
                    lc = "modl"; rc = "modr"; mc = "markmod"
                elif kind == "removed":
                    lc = "del"; rc = "same"; mc = "markdel"
                else:
                    lc = "same"; rc = "add"; mc = "markadd"
                parts.append(f"<div class='{lc}'>{html.escape(left)}</div><div class='mark {mc}'>{html.escape(marker)}</div><div class='{rc}'>{html.escape(right)}</div>")
            parts.append("</div>")

            def kv(label: str, left: str, right: str) -> str:
                """Render one aligned PRE/POST key-value row for the HTML report."""
                marker = "|" if left == right else "!"
                return f"<div class='kv'><div>{html.escape(label)}: {html.escape(str(left))}</div><div class='mid'>{marker}</div><div>{html.escape(label)}: {html.escape(str(right))}</div></div>"

            parts.append("<div class='sec'>Status</div>")
            parts.append(kv("Port Status", pre.get("port_status", "UNKNOWN"), post.get("port_status", "UNKNOWN")))
            parts.append(kv("Access VLAN", pre.get("access_vlan", "UNKNOWN"), post.get("access_vlan", "UNKNOWN")))
            parts.append(kv("Voice VLAN", pre.get("voice_vlan", "UNKNOWN"), post.get("voice_vlan", "UNKNOWN")))

            expected = post.get("expected_mac") or pre.get("expected_mac") or "UNKNOWN"
            pre_mac = expected if expected in set(pre.get("detected_macs") or []) else "NOT DETECTED"
            post_mac = expected if expected in set(post.get("detected_macs") or []) else "NOT DETECTED"
            mac_marker = "|" if pre_mac == post_mac else ("<" if post_mac == "NOT DETECTED" else "!")
            parts.append("<div class='sec'>MAC Address</div>")
            parts.append(f"<div class='kv'><div>{html.escape(pre_mac)}</div><div class='mid'>{mac_marker}</div><div>{html.escape(post_mac)}</div></div>")
            if pre.get("error") or post.get("error"):
                err = " | ".join(x for x in [pre.get("error", ""), post.get("error", "")] if x)
                parts.append(f"<div class='sec'>Errors</div><div style='padding:10px 14px;color:#991b1b'>{html.escape(err)}</div>")
            parts.append("<div class='result'>")
            parts.append(f"<span class='badge {badge_class('config', comp['config'])}'>Config: {comp['config']}</span>")
            parts.append(f"<span class='badge {badge_class('status', comp['status'])}'>Status: {comp['status']}</span>")
            parts.append(f"<span class='badge {badge_class('mac', comp['mac'])}'>MAC: {comp['mac']}</span>")
            parts.append(f"<span class='badge {badge_class('result', comp['result'])}'>Overall: {comp['result']}</span>")
            parts.append("</div></div>")
        parts.append("</section>")

    parts.append(
        f"<div class='panel' style='margin-top:28px'><div class='label'>Final Summary</div>"
        f"<p><strong>Switches Compared:</strong> {len(switch_order)} &nbsp; | &nbsp; <strong>Ports Compared:</strong> {total_ports} &nbsp; | &nbsp; <strong>Changed:</strong> {changed} &nbsp; | &nbsp; <strong>No Change:</strong> {no_change} &nbsp; | &nbsp; <strong>MAC Removed:</strong> {mac_removed} &nbsp; | &nbsp; <strong>Review Required:</strong> {review}</p>"
        f"<p style='color:#64748b;font-size:12px;margin-bottom:0'>PRE source: {html.escape(str(pre_snapshot.get('_source','')))}<br>POST source: {html.escape(str(post_snapshot.get('_source','')))}</p></div>"
    )
    parts.append("</div><footer>Generated by Portdeco.py — read-only PRE/POST evidence comparison</footer></body></html>")
    output_path.write_text("".join(parts), encoding="utf-8")




# ==============================================================================
# SECTION 17 - CHECK-MODE CONSOLE OUTPUT AND WORKFLOW
# ==============================================================================
def print_checks_table(check_type: str, snapshots: list[CheckPortSnapshot]) -> None:
    """Render the PRE/POST collection result table in the terminal."""
    table = Table(title=f"{check_type}-CHECKS RESULTS", header_style="bold")
    table.add_column("Switch")
    table.add_column("Port")
    table.add_column("Status")
    table.add_column("Access VLAN")
    table.add_column("Voice VLAN")
    table.add_column("Expected MAC")
    table.add_column("MAC Present")
    table.add_column("Error")
    for s in snapshots:
        table.add_row(
            s.switch,
            s.port,
            s.port_status,
            s.access_vlan,
            s.voice_vlan,
            s.expected_mac,
            "YES" if s.expected_mac in s.detected_macs else "NO",
            s.error,
        )
    console.print(table)


def run_checks(args: argparse.Namespace, records: list[InputRecord], password: str, logger: logging.Logger) -> int:
    """Orchestrate PRE/POST evidence collection, optional backups, and optional HTML comparison."""
    check_type = choose_check_type(args)
    if args.compare and check_type != "POST":
        console.print("[yellow]WARNING: --compare is only performed during POST-CHECKS. Comparison skipped.[/yellow]")

    root = Path(args.pre_dir if check_type == "PRE" else args.post_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = root / timestamp
    run_dir.mkdir(parents=True, exist_ok=False)

    grouped: dict[str, list[InputRecord]] = defaultdict(list)
    switch_order: list[str] = []
    for record in records:
        if record.switch not in grouped:
            switch_order.append(record.switch)
        grouped[record.switch].append(record)

    console.print(Panel.fit("[bold]PORT DECOMMISSION CHECKS[/bold]"))
    console.print(f"[+] Check Type : {check_type}-CHECKS")
    console.print(f"[+] Backup     : {'ENABLED' if args.backup else 'DISABLED'}")
    console.print(f"[+] Switches   : {len(grouped)}")
    console.print(f"[+] Ports      : {len(records)}\n")

    all_snaps: list[CheckPortSnapshot] = []
    files: list[str] = []
    backups: list[str] = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(grouped))) as executor:
        futures = {
            executor.submit(
                capture_switch_checks,
                sw,
                grouped[sw],
                username=args.username,
                password=password,
                timeout=args.timeout,
                check_type=check_type,
                backup=args.backup,
                run_dir=run_dir,
                logger=logger,
            ): sw
            for sw in switch_order
        }
        results_by_switch: dict[str, tuple[list[CheckPortSnapshot], str | None, str | None]] = {}
        for future in as_completed(futures):
            sw = futures[future]
            try:
                results_by_switch[sw] = future.result()
            except Exception as exc:
                logger.exception("Unhandled check worker failure for %s", sw)
                results_by_switch[sw] = ([], None, None)
                console.print(f"[red]ERROR {sw}: {exc}[/red]")

    for sw in switch_order:
        snaps, check_file, backup_file = results_by_switch.get(sw, ([], None, None))
        all_snaps.extend(snaps)
        if check_file:
            files.append(check_file)
        if backup_file:
            backups.append(backup_file)

    signature = inventory_signature(records)
    snapshot_path = save_snapshot_json(run_dir, check_type, all_snaps, args.hosts, signature)
    print_checks_table(check_type, all_snaps)

    console.print("\nFiles Generated:")
    for f in files:
        console.print(f"    {f}")
    if backups:
        console.print("\nBackups:")
        for f in backups:
            console.print(f"    {f}")
    if check_type == "POST" and args.compare:
        # Pair POST only with a PRE snapshot carrying the same inventory signature.
        # This prevents accidental comparison against another change window.
        pre_snapshot_path = find_latest_snapshot(Path(args.pre_dir), "PRE", signature)
        if pre_snapshot_path is None:
            console.print("[red]ERROR: No matching PRE snapshot found for this hosts inventory. Run PRE-CHECKS first.[/red]")
            return 2
        pre_data = load_snapshot(pre_snapshot_path)
        post_data = load_snapshot(snapshot_path)
        pre_data["_source"] = str(pre_snapshot_path)
        post_data["_source"] = str(snapshot_path)
        compare_dir = Path(args.comparison_dir) / timestamp
        compare_dir.mkdir(parents=True, exist_ok=True)
        html_path = compare_dir / "Port_Decommission_DIFF.html"
        generate_comparison_html(pre_data, post_data, html_path)
        console.print("\n[bold green][+] Comparison generated[/bold green]")
        console.print(f"    HTML : {html_path}")

    logger.info("%s checks completed: %d ports", check_type, len(all_snaps))
    return 0




# ==============================================================================
# SECTION 18 - NORMAL VALIDATION / CONFIG-GENERATION WORKFLOW
# ==============================================================================
def run_normal(args: argparse.Namespace, records: list[InputRecord], password: str, logger: logging.Logger) -> int:
    """Orchestrate normal validation/config generation as an all-or-nothing run.

    Configuration and status files are written only after every requested switch
    successfully establishes an SSH session. If any switch fails authentication or
    connection creation, the run is aborted and neither output file is generated or
    modified. The detailed failure remains available in Port_decommission.log.
    """
    template = load_and_validate_template(Path(args.template))
    grouped: dict[str, list[InputRecord]] = defaultdict(list)
    switch_order: list[str] = []
    for record in records:
        if record.switch not in grouped:
            switch_order.append(record.switch)
        grouped[record.switch].append(record)

    print_main_banner()
    results_by_switch: dict[str, list[PortResult]] = {}
    connection_failures: list[DeviceConnectionError] = []

    with ThreadPoolExecutor(max_workers=min(args.workers, len(grouped))) as executor:
        future_map = {
            executor.submit(
                process_switch,
                switch,
                grouped[switch],
                username=args.username,
                password=password,
                timeout=args.timeout,
                template=template,
                logger=logger,
            ): switch
            for switch in switch_order
        }

        for future in as_completed(future_map):
            switch = future_map[future]
            try:
                results_by_switch[switch] = future.result()
            except DeviceConnectionError as exc:
                # Do not convert connection failures into ordinary port results.
                # They are run-level blockers because partial config/status files
                # could be mistaken for a complete change package.
                connection_failures.append(exc)
                logger.error(
                    "Run-blocking connection failure | Switch=%s | Category=%s | Detail=%s",
                    exc.switch,
                    exc.category,
                    exc.detail,
                )
            except Exception as exc:
                logger.exception("Unhandled worker failure for %s", switch)
                results_by_switch[switch] = [
                    PortResult(
                        switch=switch,
                        port=r.port,
                        expected_mac=r.mac,
                        port_status=PORT_ERROR,
                        error=str(exc),
                        warning="WORKER ERROR - NO CONFIG GENERATED",
                    )
                    for r in grouped[switch]
                ]

    if connection_failures:
        console.print()
        console.print(
            Panel(
                Align.center(
                    Text(
                        "CONNECTION VALIDATION FAILED\nOUTPUT FILE GENERATION ABORTED",
                        style="bold red",
                    )
                ),
                border_style="red",
                padding=(1, 2),
            )
        )

        error_table = Table(header_style="bold red")
        error_table.add_column("Switch", style="bold")
        error_table.add_column("Failure")
        error_table.add_column("Recommended Action")
        for exc in sorted(connection_failures, key=lambda item: item.switch.lower()):
            if exc.category == "AUTHENTICATION FAILED":
                action = "Verify SSH username/password and AAA authorization."
            elif exc.category == "CONNECTION TIMEOUT":
                action = "Verify DNS/IP, reachability, TCP/22, SSH service, and timeout."
            else:
                action = "Verify hostname/IP, reachability, SSH service, and network path."
            error_table.add_row(exc.switch, exc.category, action)
        console.print(error_table)
        console.print()
        console.print(
            f"[bold red]No {args.output_config} or {args.output_status} file was generated or modified.[/bold red]"
        )
        console.print(f"Detailed diagnostics: [bold]{args.log_file}[/bold]")
        logger.error(
            "Normal run aborted because %d switch connection(s) failed. Config/status outputs were not written.",
            len(connection_failures),
        )
        return 3

    all_results: list[PortResult] = []
    for switch in switch_order:
        switch_results = results_by_switch.get(switch, [])
        order = {r.port: i for i, r in enumerate(grouped[switch])}
        switch_results.sort(key=lambda r: order.get(r.port, 999999))
        console.print(make_switch_table(switch, switch_results))
        console.print()
        all_results.extend(switch_results)

    # Transactional output boundary: files are written only after connection
    # validation has succeeded for the complete requested switch inventory.
    write_config_file(Path(args.output_config), all_results, switch_order)
    write_status_csv(Path(args.output_status), all_results)
    print_summary(all_results, args)
    logger.info("Completed: %d ports", len(all_results))
    return 0



# ==============================================================================
# SECTION 19 - APPLICATION ENTRY POINT
# ==============================================================================
def main() -> int:
    """Application entry point.
    
    Validates runtime prerequisites, loads the inventory, obtains credentials, starts
    logging, and dispatches to check mode or normal mode."""
    args = parse_args()
    if args.workers < 1:
        console.print("[red]ERROR: --workers must be >= 1[/red]")
        return 2
    if args.timeout < 1:
        console.print("[red]ERROR: --timeout must be >= 1[/red]")
        return 2
    if ConnectHandler is None:
        console.print("[red]ERROR: Netmiko is not installed.[/red]")
        console.print("Install requirements with: pip install netmiko rich ntc-templates")
        return 2

    try:
        records = read_hosts_csv(Path(args.hosts))
    except Exception as exc:
        console.print(f"[red]ERROR: {exc}[/red]")
        return 2

    password = args.password if args.password is not None else getpass.getpass("SSH Password: ")
    logger = setup_logging(Path(args.log_file), args.log_level)
    logger.info("%s started | Version: %s | Author: %s", TOOL_NAME, VERSION, AUTHOR)
    logger.info("Safety: read-only show commands only; no configuration push path exists")

    try:
        if args.checks:
            return run_checks(args, records, password, logger)
        return run_normal(args, records, password, logger)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return 130
    except Exception as exc:
        logger.exception("Fatal error")
        console.print(f"[red]ERROR: {exc}[/red]")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
