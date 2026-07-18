from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence, TextIO

from .backend import apply_transaction
from .catalog import load_catalog
from .errors import ComponentsError, NotImplementedTransactionError
from .jsonio import atomic_write_json, load_strict
from .models import create_confirmation, create_request_plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="linxira-components")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_parser = subcommands.add_parser("list", help="list catalog profiles")
    list_parser.add_argument("--catalog", type=Path, required=True)
    list_parser.add_argument("--arch", default="x86_64")
    list_parser.add_argument("--json", action="store_true", dest="as_json")

    plan_parser = subcommands.add_parser("plan", help="create a canonical request plan")
    plan_parser.add_argument("--catalog", type=Path, required=True)
    plan_parser.add_argument("--arch", default="x86_64")
    plan_parser.add_argument("--profile", action="append", required=True, dest="profiles")
    plan_parser.add_argument("--output-dir", type=Path, required=True)
    plan_parser.add_argument("--output", default="request-plan.json")

    confirm_parser = subcommands.add_parser("confirm", help="confirm an unchanged request plan")
    confirm_parser.add_argument("--catalog", type=Path, required=True)
    confirm_parser.add_argument("--arch", default="x86_64")
    confirm_parser.add_argument("--plan", type=Path, required=True)
    confirm_parser.add_argument("--output-dir", type=Path, required=True)
    confirm_parser.add_argument("--output", default="confirmation.json")

    apply_parser = subcommands.add_parser("apply", help="reserved transaction entry point")
    apply_parser.add_argument("--confirmation", type=Path)
    return parser


def _print_json(document: object, *, stream: TextIO | None = None) -> None:
    print(
        json.dumps(document, ensure_ascii=False, sort_keys=True),
        file=sys.stdout if stream is None else stream,
    )


def _run(args: argparse.Namespace) -> int:
    if args.command == "list":
        catalog = load_catalog(args.catalog, args.arch)
        profiles = sorted(catalog.profiles, key=lambda profile: (profile.order, profile.id))
        if args.as_json:
            _print_json([
                {
                    "id": profile.id,
                    "name": profile.names,
                    "packages": list(profile.packages),
                    "networkRequired": profile.network_required,
                }
                for profile in profiles
            ])
        else:
            for profile in profiles:
                print(f"{profile.id}\t{profile.names['en']}")
        return 0

    if args.command == "plan":
        catalog = load_catalog(args.catalog, args.arch)
        plan = create_request_plan(catalog, args.profiles, args.arch)
        path = atomic_write_json(args.output_dir, args.output, plan)
        _print_json({"path": str(path), "digest": plan["digest"]})
        return 0

    if args.command == "confirm":
        catalog = load_catalog(args.catalog, args.arch)
        plan = load_strict(args.plan)
        confirmation = create_confirmation(plan, catalog)
        path = atomic_write_json(args.output_dir, args.output, confirmation)
        _print_json({"path": str(path), "digest": confirmation["digest"]})
        return 0

    if args.command == "apply":
        apply_transaction(args.confirmation)
    raise AssertionError("unreachable command")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _run(_parser().parse_args(argv))
    except ComponentsError as exc:
        _print_json({"error": exc.code, "message": str(exc)}, stream=sys.stderr)
        return 3 if isinstance(exc, NotImplementedTransactionError) else 2


if __name__ == "__main__":
    raise SystemExit(main())
