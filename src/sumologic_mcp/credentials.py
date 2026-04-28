import getpass
import os
import sys
from dataclasses import dataclass

import keyring

SERVICE_NAME = "sumologic-mcp"
KEY_ACCESS_ID = "access_id"
KEY_ACCESS_KEY = "access_key"

VALID_REGIONS = {"us1", "us2", "eu", "de", "au", "jp", "ca", "in"}


@dataclass(frozen=True)
class Credentials:
    access_id: str
    access_key: str
    region: str
    analyst_username: str
    soar_owner_id: int


def _missing_secret(item: str) -> str:
    return f"Missing {item}. Run 'sumologic-mcp setup' to configure."


def _missing_env(item: str) -> str:
    return f"Missing {item}. Set it in your Claude Desktop config 'env:' block."


def load_credentials() -> Credentials:
    access_id = keyring.get_password(SERVICE_NAME, KEY_ACCESS_ID)
    access_key = keyring.get_password(SERVICE_NAME, KEY_ACCESS_KEY)
    if not access_id:
        raise RuntimeError(_missing_secret("Sumo access_id"))
    if not access_key:
        raise RuntimeError(_missing_secret("Sumo access_key"))

    region = os.environ.get("SUMO_API_REGION", "").strip().lower()
    if not region:
        raise RuntimeError(_missing_env("SUMO_API_REGION"))
    if region not in VALID_REGIONS:
        raise RuntimeError(
            f"Invalid SUMO_API_REGION '{region}'. Valid: {', '.join(sorted(VALID_REGIONS))}"
        )

    analyst = os.environ.get("ANALYST_USERNAME", "").strip()
    if not analyst:
        raise RuntimeError(_missing_env("ANALYST_USERNAME"))

    owner_raw = os.environ.get("SOAR_OWNER_ID", "").strip()
    if not owner_raw:
        raise RuntimeError(_missing_env("SOAR_OWNER_ID"))
    try:
        owner_id = int(owner_raw)
    except ValueError as e:
        raise RuntimeError(f"SOAR_OWNER_ID must be an integer; got '{owner_raw}'") from e

    return Credentials(
        access_id=access_id,
        access_key=access_key,
        region=region,
        analyst_username=analyst,
        soar_owner_id=owner_id,
    )


def run_setup() -> None:
    print("sumologic-mcp credential setup")
    print(f"Storing under Windows Credential Manager service: '{SERVICE_NAME}'")
    print("Existing values shown as defaults. Press Enter to keep.\n")

    current_id = keyring.get_password(SERVICE_NAME, KEY_ACCESS_ID) or ""
    current_key = keyring.get_password(SERVICE_NAME, KEY_ACCESS_KEY) or ""

    id_suffix = f" [{current_id}]" if current_id else ""
    access_id = input(f"Sumo access ID{id_suffix}: ").strip() or current_id
    if not access_id:
        sys.exit("Aborted: access_id cannot be empty.")

    key_suffix = " [keep existing]" if current_key else ""
    access_key = getpass.getpass(f"Sumo access key (hidden){key_suffix}: ").strip() or current_key
    if not access_key:
        sys.exit("Aborted: access_key cannot be empty.")

    keyring.set_password(SERVICE_NAME, KEY_ACCESS_ID, access_id)
    keyring.set_password(SERVICE_NAME, KEY_ACCESS_KEY, access_key)

    print("\nStored:")
    print(f"  - {SERVICE_NAME}/{KEY_ACCESS_ID}")
    print(f"  - {SERVICE_NAME}/{KEY_ACCESS_KEY}")
    print("\nNext: add the env block to your Claude Desktop config:")
    print('  "env": {')
    print('    "SUMO_API_REGION": "<us1|us2|eu|de|au|jp|ca|in>",')
    print('    "ANALYST_USERNAME": "<your-sumo-username>",')
    print('    "SOAR_OWNER_ID": "<numeric-owner-id>"')
    print("  }")
