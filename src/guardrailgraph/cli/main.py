"""GuardrailGraph CLI — main entry point."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from guardrailgraph.cli.commands import init, dev, test, validate, deploy, report, eject


def create_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="guardrailgraph",
        description="GuardrailGraph — Composable AI safety pipeline framework",
    )
    parser.add_argument("--version", action="store_true", help="Show version")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize a new project")
    init_parser.add_argument("project_name", nargs="?", default="my-guardrails")
    init_parser.add_argument("--pack", choices=["hipaa", "sox", "gdpr", "basic"], default="basic")
    init_parser.add_argument("--dir", default=".")

    # dev
    dev_parser = subparsers.add_parser("dev", help="Start local dev server")
    dev_parser.add_argument("--port", type=int, default=8080)

    # test
    test_parser = subparsers.add_parser("test", help="Run guardrail tests")
    test_parser.add_argument("--adversarial", action="store_true")
    test_parser.add_argument("--config", default="guardrailgraph.yaml")

    # validate
    validate_parser = subparsers.add_parser("validate", help="Validate config")
    validate_parser.add_argument("--config", default="guardrailgraph.yaml")

    # deploy
    deploy_parser = subparsers.add_parser("deploy", help="Deploy infrastructure")
    deploy_parser.add_argument("--env", default="dev", choices=["dev", "staging", "prod"])
    deploy_parser.add_argument("--config", default="guardrailgraph.yaml")
    deploy_parser.add_argument("--dry-run", action="store_true")

    # report
    report_parser = subparsers.add_parser("report", help="Generate compliance report")
    report_parser.add_argument("--framework", default="general", choices=["general", "HIPAA", "SOX", "GDPR", "FedRAMP"])
    report_parser.add_argument("--format", default="text", choices=["text", "json"])
    report_parser.add_argument("--output", default=None)
    report_parser.add_argument("--config", default="guardrailgraph.yaml")

    # eject
    eject_parser = subparsers.add_parser("eject", help="Export raw infrastructure")
    eject_parser.add_argument("--format", default="cdk", choices=["cdk", "sam"])
    eject_parser.add_argument("--config", default="guardrailgraph.yaml")

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

    commands = {
        "init": init.run,
        "dev": dev.run,
        "test": test.run,
        "validate": validate.run,
        "deploy": deploy.run,
        "report": report.run,
        "eject": eject.run,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
