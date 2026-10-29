# NetCommandRunner v1.1.0

Execute a list of network CLI commands over SSH, in parallel, and save per-device output.

## Windows installation

```powershell
py -m pip install -r requirements.txt
python NetCommandRunner.py -h
```

## Standard mode (same commands for every host)

```powershell
python NetCommandRunner.py -ho SW01 -cmd commands.txt -u admin
python NetCommandRunner.py -hf hosts.txt -cf commands.txt -u admin -w 20
```

## Multifile mode (specific commands for each host)

```powershell
python NetCommandRunner.py -mf multifile.txt -u admin --dry-run
python NetCommandRunner.py -mf multifile.txt -u admin --prefix pre --suffix checks --timestamp -o Audit_PRE
python NetCommandRunner.py -mf multifile.txt -u admin --on-error stop
```

Example input:

```text
HostName:SW01
show version
show platform
!
HostName:SW02
show inventory
wr
!
```

`HostName:` is case-insensitive and accepts spaces after `:`. The `!` delimiter is optional before the next header and at EOF. Comments starting with `#` and blank lines are ignored. Repeating a hostname merges commands into a single execution on that device, preserving their order. Input errors are reported before any SSH connections.

**Note:** `-mf` cannot be used with `-ho`, `-hf`, `-cf`, or `-cmd`. `--prefix` and `--suffix` change output names, **not device commands**.

## Output

```text
Audit_PRE/
  Results/
    pre_SW01_checks_20261028_075500.txt
    pre_SW02_checks_20261028_075500.txt
  Logs/
    NetCommandRunner_20261028_075500.log
  summary.csv
```

Time shown above is illustrative. Without `--timestamp`, device output filenames do not contain date/time; log filenames always do.

## Execution behavior

- Default `--mode exec` executes one command at a time. `--on-error continue` tries the next command after a device-reported error. `--on-error stop` stops that device's command list on a reported error; other devices continue. SSH command exceptions stop that device because session state may be unreliable.
- `--mode config` executes each device's commands as one Netmiko configuration batch and asks for confirmation. Use `--yes` for noninteractive runs. `!` in multifile is a separator, not an actual CLI command.
- `wr` / `write memory` and `copy running-config startup-config` are recognized and require an `[OK]` device response to count as PASS.
- `--dry-run` prints per-host commands without connecting or creating files.
- The CSV counts configured commands, successful commands and the rest as failed/not completed, even if an early stop occurred.
- `--overwrite` is required if a device result or `summary.csv` already exists in the output directory.

## Credentials

If omitted, `-u` and `-p` are prompted interactively. Avoid passing `-p` in a shared terminal due to process listings and command history.
