# PROJECT CONTEXT

- **Project:** Cisco Command Parser — offline Cisco IOS-XE TXT → JSON / Excel auditing
- **Current Version:** 1.1.0
- **Environment:** Python 3.10+, Windows, `artifact-tool`, `rich`; no pyATS or Genie
- **Features:** 14 modular parsers, rich progress and color terminal summary, command delimiter detection, unsupported/empty/unparsed status, JSON, multi-sheet Excel, interface consolidation, error log, safe overwrite option
- **CLI:** `input`, `-o/--output`, `--json`, `--no-excel`, `--excel`, `--raw-json`, `--overwrite`, `-h/--help`
- **Input:** command blocks marked by separator lines of 20 or more `=` characters
- **Output:** audit Excel, optional JSON, `Logs/parser.log`
- **Modules:** `parsers/`, `utils/`, `exporters/`
- **Next:** production format fixtures, BGP/route/STP/MAC parsers, strict schema validation, richer inventory/link correlation
