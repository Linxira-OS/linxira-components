from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence, TextIO

from .backend import apply_transaction
from .catalog import load_catalog
from .catalog_v3 import CatalogV3
from .errors import ComponentsError, ValidationError
from .jsonio import atomic_write_json, load_strict
from .models import create_confirmation, create_request_plan
from .selection import create_bundle_selection


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="linxira-components")
    parser.add_argument("--version", action="version", version="%(prog)s 0.4.0")
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_parser = subcommands.add_parser("list", help="list catalog profiles")
    list_parser.add_argument("--catalog", type=Path, required=True)
    list_parser.add_argument("--arch", default="x86_64")
    list_parser.add_argument("--json", action="store_true", dest="as_json")

    plan_parser = subcommands.add_parser("plan", help="create a canonical request plan")
    plan_parser.add_argument("--catalog", type=Path, required=True)
    plan_parser.add_argument("--arch", default="x86_64")
    plan_parser.add_argument("--profile", action="append", default=[], dest="profiles")
    plan_parser.add_argument("--application", action="append", default=[], dest="applications")
    plan_parser.add_argument("--selection", "--selection-document", type=Path)
    plan_parser.add_argument("--bundle", help="select one fixed Catalog v3 bundle")
    plan_parser.add_argument("--accept-license", action="append", default=[], dest="license_acceptances")
    plan_parser.add_argument("--output-dir", type=Path, required=True)
    plan_parser.add_argument("--output", default="request-plan.json")

    confirm_parser = subcommands.add_parser("confirm", help="confirm an unchanged request plan")
    confirm_parser.add_argument("--catalog", type=Path, required=True)
    confirm_parser.add_argument("--arch", default="x86_64")
    confirm_parser.add_argument("--plan", type=Path, required=True)
    confirm_parser.add_argument("--output-dir", type=Path, required=True)
    confirm_parser.add_argument("--output", default="confirmation.json")

    apply_parser = subcommands.add_parser("apply", help="apply a confirmed Arch transaction as root")
    apply_parser.add_argument("--confirmation", type=Path, required=True)
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
        if args.bundle is not None and args.selection is not None:
            raise ValidationError("--bundle and --selection are mutually exclusive")
        if args.bundle is not None and not isinstance(catalog, CatalogV3):
            raise ValidationError("--bundle requires a Catalog v3 input")
        selection = (
            create_bundle_selection(catalog, args.bundle)
            if args.bundle is not None
            else load_strict(args.selection) if args.selection is not None else None
        )
        plan = create_request_plan(
            catalog,
            args.profiles,
            args.arch,
            application_ids=args.applications,
            selection=selection,
            license_acceptances=args.license_acceptances,
        )
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
        confirmation = load_strict(args.confirmation)
        receipt = apply_transaction(confirmation)
        _print_json(receipt)
        return 0
    raise AssertionError("unreachable command")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _run(_parser().parse_args(argv))
    except ComponentsError as exc:
        _print_json({"error": exc.code, "message": str(exc)}, stream=sys.stderr)
        return 3 if exc.code == "TRANSACTION_FAILED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
