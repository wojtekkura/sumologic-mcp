import getpass
import os
import sys
from dataclasses import dataclass

import keyring
from keyring.errors import KeyringError

SERVICE_NAME = "sumologic-mcp"
KEY_ACCESS_ID = "access_id"
KEY_ACCESS_KEY = "access_key"

# Env-var fallbacks for the two secrets. Used when the system keyring is
# unavailable (headless Linux / containers without a D-Bus session) or
# when the user wants to override the keyring (CI, ephemeral runs).
ENV_ACCESS_ID = "SUMO_ACCESS_ID"
ENV_ACCESS_KEY = "SUMO_ACCESS_KEY"

VALID_REGIONS = {"us1", "us2", "eu", "de", "au", "jp", "ca", "in"}


@dataclass(frozen=True)
class Credentials:
    access_id: str
    access_key: str
    region: str
    analyst_username: str
    soar_owner_id: int


def _missing_secret(item: str, env_var: str) -> str:
    return (
        f"Missing {item}. Set the {env_var} environment variable, "
        f"or run 'sumologic-mcp setup' to store it in the system keyring."
    )


def _missing_env(item: str) -> str:
    return f"Missing {item}. Set it in your MCP host config 'env:' block."


def _read_secret(keyring_key: str, env_var: str) -> str | None:
    """Look up a secret. Env var wins (explicit override / Linux headless),
    keyring is the fallback. Keyring backend errors (e.g. no SecretService
    on a headless Linux box) are treated as "secret not found" — the env
    var is the documented escape hatch."""
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        return env_val
    try:
        return keyring.get_password(SERVICE_NAME, keyring_key)
    except KeyringError:
        return None


def load_credentials() -> Credentials:
    access_id = _read_secret(KEY_ACCESS_ID, ENV_ACCESS_ID)
    access_key = _read_secret(KEY_ACCESS_KEY, ENV_ACCESS_KEY)
    if not access_id:
        raise RuntimeError(_missing_secret("Sumo access_id", ENV_ACCESS_ID))
    if not access_key:
        raise RuntimeError(_missing_secret("Sumo access_key", ENV_ACCESS_KEY))

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


def _keyring_is_usable() -> bool:
    """Detect whether the system keyring can accept writes. On headless
    Linux (no D-Bus / no gnome-keyring), keyring raises KeyringError on
    any operation — we surface that early so the user knows to switch
    to the env-var path."""
    try:
        keyring.get_password(SERVICE_NAME, "__probe__")
        return True
    except KeyringError:
        return False


def run_setup() -> None:
    print("sumologic-mcp credential setup")

    if not _keyring_is_usable():
        print(
            "\nNo usable system keyring on this host "
            "(typical on headless Linux / containers without D-Bus).\n"
            "Use the env-var path instead. Add these to the 'env:' block "
            "of your MCP host config, or export them in your shell:\n"
        )
        print(f"  export {ENV_ACCESS_ID}='your-access-id'")
        print(f"  export {ENV_ACCESS_KEY}='your-access-key'")
        print('  export SUMO_API_REGION="<us1|us2|eu|de|au|jp|ca|in>"')
        print('  export ANALYST_USERNAME="<your-sumo-username>"')
        print('  export SOAR_OWNER_ID="<numeric-owner-id>"')
        return

    print(f"Storing secrets in the system keyring under service: '{SERVICE_NAME}'")
    print(
        "(Windows Credential Manager / macOS Keychain / Linux libsecret. "
        f"Override with {ENV_ACCESS_ID} / {ENV_ACCESS_KEY} env vars at runtime.)"
    )
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
    print("\nNext: add the env block to your MCP host config:")
    print('  "env": {')
    print('    "SUMO_API_REGION": "<us1|us2|eu|de|au|jp|ca|in>",')
    print('    "ANALYST_USERNAME": "<your-sumo-username>",')
    print('    "SOAR_OWNER_ID": "<numeric-owner-id>"')
    print("  }")
