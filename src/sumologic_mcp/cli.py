import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sumologic-mcp",
        description="MCP server for Sumo Logic SIEM/SOAR (claim_incident, attach_note).",
    )
    parser.add_argument(
        "--mode",
        choices=["stdio"],
        default="stdio",
        help="Transport mode (only 'stdio' is implemented; flag reserved for future HTTP support).",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Run the MCP server (default).")
    sub.add_parser(
        "setup", help="Interactively store Sumo credentials in Windows Credential Manager."
    )

    args = parser.parse_args()
    command = args.command or "serve"

    if command == "setup":
        from sumologic_mcp.credentials import run_setup

        run_setup()
        return

    if command == "serve":
        from sumologic_mcp.server import run_stdio

        run_stdio()
        return

    parser.error(f"unknown command: {command}")
    sys.exit(2)
