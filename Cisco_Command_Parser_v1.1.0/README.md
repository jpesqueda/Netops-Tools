# Cisco Command Parser v1.1.0

Offline command-output parser for Catalyst IOS-XE command captures. Designed for Windows and Python 3.10+; no Genie/pyATS/Linux requirement.

## Installation

```powershell
py -m pip install -r requirements.txt
```

## Examples

```powershell
py Cisco_Command_Parser.py Commands_Output.txt
py Cisco_Command_Parser.py Commands_Output.txt -o SW01_Audit.xlsx --json
py Cisco_Command_Parser.py Commands_Output.txt --json --no-excel
py Cisco_Command_Parser.py Commands_Output.txt -o Reports --json --raw-json
py Cisco_Command_Parser.py Commands_Output.txt --overwrite
py Cisco_Command_Parser.py --help
```

Default: Excel. `--json` adds JSON; `--no-excel` produces JSON only. `--raw-json` embeds raw outputs in the JSON. Every Excel export includes a Raw_Commands sheet and Parsing_Summary.

## Supported parsing commands

`show version`, `show inventory`, `show interfaces status`, `show interfaces description`, `show interfaces counters`, `show interfaces counters errors`, `show ip interface brief`, `show vlan brief`, `show interfaces trunk`, `show ip arp`, `show ip arp inspection interfaces`, `show ip dhcp snooping binding`, `show device-tracking database`, `show environment all`.

Other commands are UNSUPPORTED and their raw text is preserved in Excel. Commands returning a non-empty but unrecognized format are UNPARSED. Missing commands produce no data, not a fatal error. Duplicate sections are processed independently and their records appended.

## Limitations

- Capture splitter requires exact three-line `====` delimiter blocks with a `show ...` command on the middle line.
- Output format of Cisco commands changes across IOS-XE versions and platforms; review UNPARSED results and extend parsers as needed.
- Some structured formats (e.g. multiple VLAN ports wrapped onto new lines, different interface counter columns, complex routing tables) require additional validation against production outputs.
- `Interfaces_Master` is a convenience summary: it is **not** a lossless relational join. Repeated IP/MAC bindings per interface are concatenated. Detailed per-command sheets and JSON retain the individual records.
- `Raw_Commands` cells over 32,750 characters are truncated to meet Excel limits. Use original TXT or JSON `--raw-json` for complete raw data.
- The tool **does not connect to network devices or change configurations**.

## Extend the parser

Add `parse_command(raw: str) -> list[dict]` to the relevant file under `parsers/`. Register its CLI text in `parsers/__init__.py` `PARSERS` map. Return `[]` when there is no parseable record; exceptions are logged and do not stop other sections.

## v1.1.0 terminal improvements

- Rich progress bar updates once per detected command.
- Terminal results table: `COMMAND | RECORDS | STATUS`.
- Color-coded statuses: green PARSED, yellow UNSUPPORTED/UNPARSED/EMPTY, red ERROR.
- Run summary displays command totals, consolidated interfaces, execution time, generated files, and log location.
- With `NO_COLOR=1`, Rich omits ANSI styling for CI/redirected runs.

### Example output

```text
Parsing commands ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 15/15
CISCO COMMAND PARSER  v1.1.0
Device: SW01
COMMAND                              RECORDS  STATUS
show version                               1  PARSED
show inventory                             2  PARSED
...
show logging                               0  UNSUPPORTED

SUMMARY
  Commands: 15   Parsed: 14   Skipped: 1   Errors: 0
  Master interfaces: 7   Duration: 3.42s
GENERATED FILES
  PASS  Commands_Output_Audit.xlsx
  PASS  Commands_Output_Audit.json
  Log: Logs/parser.log
```
