# NetCommandRunner — Project Context

## Project
SSH command collection and execution for network devices, with independent text results, CSV summary, and per-run logs. Intended primarily for Cisco IOS-XE Catalyst 9K.

## Current Version
**1.1.0** — 2026-10-28

## Environment
Windows / PowerShell, Python 3.10+, Netmiko (`pip install -r requirements.txt`).

## Features
- Standard inputs: `-ho HOST` or `-hf hosts.txt`, combined with `-cf/-cmd commands.txt`.
- Multifile input: `-mf multifile.txt`: `HostName:SW01` then device-specific commands; `!` closes block. Whitespace and `#` comments ignored; case-insensitive header; blocks automatically end at next HostName or EOF; repeated hostname blocks merged (preserving duplicate command lines).
- Input validation before connections; no empty blocks, malformed hostname headers, or commands outside blocks.
- SSH parallelism (20 workers default); authentication errors isolated by device; transient connection retries.
- EXEC (default) and CONFIG (`--mode config`) execution using Netmiko. CONFIG sends the entire block as one configuration set and is guarded by confirmation, unless `--yes`.
- Special handling of `wr`, `write memory`, `copy running-config startup-config` with `send_command_timing`, validation of Cisco `[OK]` and support for destination filename prompt.
- `--on-error {continue,stop}` applies to EXEC command failures; command exceptions that may desynchronize the SSH session always stop that device. In CONFIG mode the batch is submitted as a single set.
- `--prefix`, `--suffix`, and optional `--timestamp` modify OUTPUT filenames only.
- `--dry-run` previews all device commands and filenames, without SSH or writing files.
- Results in `OUTPUT/Results/`, logs in `OUTPUT/Logs/`, CSV in `OUTPUT/summary.csv`. Logs have a timestamp regardless of `--timestamp`.

## CLI Arguments
`-ho/--host`, `-hf/--host-file`, `-mf/--multifile` (mutually exclusive); `-cf/-cmd/--command-file` (required for standard mode, forbidden with -mf); `-u/--user`, `-p/--password`, `--secret`; `-dt/--device-type`, `-w/--workers`, `--timeout`, `--conn-timeout`, `--retries`, `--mode`, `--on-error`, `--dry-run`, `-y/--yes`, `-o/--output`, `--prefix`, `--suffix`, `--timestamp`, `--overwrite`, `-v/--version`.

## Files
- `NetCommandRunner.py` main executable
- `hosts.txt`, `commands.txt`: standard examples
- `multifile.txt`: per-device example
- `requirements.txt`: dependencies
- `PROJECT_CONTEXT.md`: project notes
- `README.md`: installation and use

## Safety Notes
`exec` mode can run disruptive commands such as `wr` and does not imply read-only access. `--dry-run` is recommended first. Passwords passed via `-p` may appear in shell history; prefer interactive prompting. Cisco `[OK]` validation is used for write commands; other output error detection is heuristic. Avoid overwriting existing summary/results unless explicitly requested.

## Future Work
Structured per-command status, improved interaction handling for platform-specific commands, config-mode line-level error handling, automated mock SSH unit tests.
