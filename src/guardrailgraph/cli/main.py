"""GuardrailGraph CLI — main entry point."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from guardrailgraph.cli.commands import init, dev, test, validate


def create_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="guardrailgraph",
        description="GuardrailGraph — Composable AI safety pipeline framework",
    )
    parser.add_argument(
        "--version", action="store_true", help="Show version"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init command
    init_parser = subparsers.add_parser(
        "init", help="Initialize a new GuardrailGraph project"
    )
    init_parser.add_argument(
        "project_name", nargs="?", default="my-guardrails",
        help="Project name (default: my-guardrails)",
    )
    init_parser.add_argument(
        "--pack", choices=["hipaa", "sox", "gdpr", "basic"],
        default="basic", help="Starter pack template",
    )
    init_parser.add_argument(
        "--dir", default=".", help="Directory to create project in",
    )

    # dev command
    dev_parser = subparsers.add_parser(
        "dev", help="Start local development/testing server"
    )
    dev_parser.add_argument(
        "--port", type=int, default=8080, help="Port for dev server",
    )

    # test command
    test_parser = subparsers.add_parser(
        "test", help="Run guardrail tests"
    )
    test_parser.add_argument(
        "--adversarial", action="store_true",
        help="Run adversarial test suite",
    )
    test_parser.add_argument(
        "--config", default="guardrailgraph.yaml",
        help="Config file path",
    )

    # validate command
    validate_parser = subparsers.add_parser(
        "validate", help="Validate pipeline configuration"
    )
    validate_parser.add_argument(
        "--config", default="guardrailgraph.yaml",
        help="Config file path",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.version:
        from guardrailgraph import __version__
        print(f"guardrailgraph {__version__}")
        return 0

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to command handlers
    commands = {
        "init": init.run,
        "dev": dev.run,
        "test": test.run,
        "validate": validate.run,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
