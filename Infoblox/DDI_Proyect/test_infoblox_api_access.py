"""Simple read-only Infoblox WAPI access test.

Usage examples:
    python scripts/test_infoblox_api_access.py --url https://infoblox.example.com --user readonly
    python scripts/test_infoblox_api_access.py --url https://infoblox.example.com --user readonly --insecure

Environment variables:
    INFOBLOX_URL
    INFOBLOX_USERNAME
    INFOBLOX_PASSWORD
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Test read-only Infoblox WAPI access.")
    parser.add_argument("--url", default=os.getenv("INFOBLOX_URL"), help="Infoblox HTTPS URL.")
    parser.add_argument("--user", default=os.getenv("INFOBLOX_USERNAME"), help="Infoblox username.")
    parser.add_argument(
        "--password",
        default=os.getenv("INFOBLOX_PASSWORD"),
        help="Infoblox password. Prefer INFOBLOX_PASSWORD or secure prompt.",
    )
    parser.add_argument("--wapi-version", default="auto", help="WAPI version, or 'auto'.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate validation.")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds.")
    return parser.parse_args()


def latest_version(versions: list[str]) -> str | None:
    parsed: list[tuple[Version, str]] = []
    for version in versions:
        try:
            parsed.append((Version(version), version))
        except InvalidVersion:
            continue
    if not parsed:
        return None
    return max(parsed, key=lambda item: item[0])[1]


def discover_wapi_version(client: httpx.Client, base_url: str, configured_version: str) -> str:
    schema_version = "1.0" if configured_version == "auto" else configured_version
    response = client.get(f"{base_url}/wapi/v{schema_version}/", params={"_schema": 1})
    response.raise_for_status()
    schema: dict[str, Any] = response.json()

    if configured_version != "auto":
        return configured_version

    supported_versions = schema.get("supported_versions", [])
    if not isinstance(supported_versions, list):
        raise RuntimeError("WAPI schema did not return a supported_versions list.")

    detected = latest_version([str(version) for version in supported_versions])
    if detected is None:
        raise RuntimeError("Could not detect a WAPI version from schema output.")
    return detected


def main() -> int:
    args = parse_args()

    if not args.url:
        print("[FAIL] Missing Infoblox URL. Use --url or INFOBLOX_URL.")
        return 5
    if not args.url.lower().startswith("https://"):
        print("[FAIL] Infoblox URL must start with https://")
        return 5
    if not args.user:
        print("[FAIL] Missing Infoblox username. Use --user or INFOBLOX_USERNAME.")
        return 5

    password = args.password or getpass.getpass("Password: ")
    if not password:
        print("[FAIL] Missing Infoblox password.")
        return 5

    base_url = args.url.rstrip("/")
    verify_tls = not args.insecure

    if args.insecure:
        print("WARNING: TLS certificate validation is disabled.")

    print("INFOBLOX API ACCESS TEST")
    print(f"URL              : {base_url}")
    print(f"Username         : {args.user}")
    print(f"TLS Verification : {'Enabled' if verify_tls else 'Disabled'}")

    try:
        with httpx.Client(
            auth=(args.user, password),
            verify=verify_tls,
            timeout=args.timeout,
            headers={"Accept": "application/json"},
        ) as client:
            print("[+] Discovering WAPI version...")
            wapi_version = discover_wapi_version(client, base_url, args.wapi_version)
            print(f"[PASS] WAPI version: v{wapi_version}")

            print("[+] Reading Grid object...")
            grid_response = client.get(
                f"{base_url}/wapi/v{wapi_version}/grid",
                params={"_return_fields+": "grid_name,nios_version"},
            )
            grid_response.raise_for_status()
            grid_data = grid_response.json()

            if not isinstance(grid_data, list) or not grid_data:
                print("[WARN] Authentication worked, but no Grid object was returned.")
                return 0

            grid = grid_data[0]
            print("[PASS] Authentication successful")
            print("[PASS] Grid reachable")
            print(f"Grid Name        : {grid.get('grid_name', 'Not exposed')}")
            print(f"NIOS Version     : {grid.get('nios_version', 'Not exposed')}")
            return 0

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status in {401, 403}:
            print("[FAIL] Authentication failed or API permissions are insufficient.")
            return 2
        print(f"[FAIL] Infoblox WAPI returned HTTP {status}.")
        print(exc.response.text[:500])
        return 1
    except httpx.ConnectError as exc:
        print("[FAIL] Could not connect to Infoblox.")
        print(str(exc))
        return 3
    except httpx.TimeoutException:
        print("[FAIL] Infoblox API request timed out.")
        return 3
    except httpx.TLSError as exc:
        print("[FAIL] TLS certificate validation failed.")
        print(str(exc))
        return 3
    except Exception as exc:
        print("[FAIL] API access test failed.")
        print(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
