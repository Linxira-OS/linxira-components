# Linxira Components

`linxira-components` is the Phase 1 component-management core for Linxira OS.
It validates catalog v2, lists profiles, creates deterministic-content request
plans, confirms unchanged plans, and models transaction receipts. It does not
install, remove, upgrade, or invoke packages.

## Safety boundary

- Catalog JSON is decoded as UTF-8 with duplicate keys rejected.
- Catalog structures, references, Arch sources, architectures, and package
  identifiers are strictly validated before use.
- Plans contain direct package targets only. They never contain commands.
- Plan and confirmation digests are SHA-256 over RFC-style canonical JSON
  (sorted keys, compact separators, ASCII encoding) excluding `digest` itself.
- Confirmation rejects a changed catalog and a modified plan.
- Writes require an existing explicit output directory and one plain filename.
  Symlinked directories and targets are rejected; files use temporary-file,
  fsync, and atomic replace semantics.
- `apply` always returns `NOT_IMPLEMENTED` with exit status 3. This package does
  not import or call subprocess, shells, privilege tools, or package managers.

The API XML and Polkit policy in this repository are review drafts. Packaging
does not install or enable them.

## CLI

Run directly from a checkout on Python 3.11 or newer:

```console
set PYTHONPATH=src
python -m linxira_components list --catalog catalog-v2.json
python -m linxira_components plan --catalog catalog-v2.json --profile developer --output-dir out
python -m linxira_components confirm --catalog catalog-v2.json --plan out/request-plan.json --output-dir out
python -m linxira_components apply --confirmation out/confirmation.json
```

`--profile` may be repeated. Profile IDs and direct package targets are
de-duplicated and sorted. `systemUpgradeRequired` is always `false` in Phase 1.

## Development

No runtime or test dependencies are required:

```console
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

The production transaction design and its trust boundary are documented in
[`docs/TRANSACTION_BACKEND.md`](docs/TRANSACTION_BACKEND.md).
