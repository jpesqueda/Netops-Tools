# Cisco SmartDiff (prototype)

**Offline and read-only:** does not connect to switches or apply any configuration.

## Windows / PowerShell

```powershell
python SmartDiff.py --pre C9300-ACCESS-01_PRE_SIMULATED.txt --post C9300-ACCESS-01_POST_SIMULATED.txt --expected-version 17.5.6 -o Test_SmartDiff
```

Python 3.10+. Standard library only. No need to install Netmiko, Genie, or Linux for this comparison.

Outputs: `JSON/*_PRE.json`, `JSON/*_POST.json`, `smart_diff.json`, `smart_diff.diff`, `summary.csv`.

## Supported structured commands

- `show version`: IOS-XE release (desired version via CLI)
- `show ip bgp summary`: local AS, peers, state, received prefixes
- `show ip interface brief`: addresses, state, protocol
- `show interface status` / `show interfaces status`: state and VLAN
- `show vlan brief`: VLAN name and state (not per-port membership)
- `show ip route`: prefixes, sources, next-hops, connected interfaces
- `show port-security`: max/current secure MAC, violations, action
- `show environment all`: reported fan, PSU and temperature status (not sensor numeric values)
- `show running-config`: compares top-level stanzas and their indented children; excludes comments, build metadata, `version` line.

Other commands are explicitly marked `UNSUPPORTED`. Parse failures are `NOT_EVALUATED`.

## Limitations and safety

- This is an initial parser for the **simulated** C9300 data, not a fully validated IOS-XE parser. Syntax differs by release, license, device, locale, and command options.
- No blanket PASS is emitted for unsupported commands. Reports are **not a certification of network health**.
- State differences are reported as CHANGE, including improvements. Version CHANGE is EXPECTED only if `--expected-version` matches POST.
- Running-config comparisons are structure-aware but not semantic; reordering certain config lines may still produce a CHANGE.
- Text formatting differences may cause PARSE_ERROR. Review `smart_diff.json`.
- Sensitive data from `show running-config` may appear in JSON/diff reports: store locally with restricted access and do not commit to Git.
- To test on production, first capture PRE and POST with your existing collector, copy files locally, and run this tool offline. No live command collection is performed by SmartDiff.
- `diff_rules.yaml` currently documents proposed policy only; **it is not loaded or active yet**.

Exit codes: 0 = no actionable changes reported (unsupported commands might remain); 2 = changes/missing/not-evaluated; unexpected parse/input errors return nonzero.
