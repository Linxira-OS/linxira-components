# Linxira Components

`linxira-components` is the catalog-bound Arch package transaction backend for
Linxira OS. It validates catalog v2, creates deterministic request plans for
profiles and individual applications, confirms unchanged plans, applies a
root-only pacman transaction, and persists durable receipts.

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
- `apply` reloads the fixed system catalog, rejects catalog drift, re-expands
  profile and application IDs, and compares the exact package target set.
- The backend must run as root. It invokes pacman once with a fixed argument
  vector and never uses a shell, client repository settings, removals, arbitrary
  paths, hooks, environment variables, or system upgrades.
- Receipts are written atomically under
  `/var/lib/linxira/components/receipts` before and after each state transition.

The API XML and Polkit policy remain review drafts. Phase 1 uses an explicit
`pkexec linxira-components apply` boundary owned by Package Center; packaging
does not install a D-Bus service.

## CLI

Run directly from a checkout on Python 3.11 or newer:

```console
set PYTHONPATH=src
python -m linxira_components list --catalog catalog-v2.json
python -m linxira_components plan --catalog catalog-v2.json --profile developer --output-dir out
python -m linxira_components plan --catalog catalog-v2.json --application haruna --output-dir out
python -m linxira_components confirm --catalog catalog-v2.json --plan out/request-plan.json --output-dir out
python -m linxira_components apply --confirmation out/confirmation.json
```

`--profile` and `--application` may be repeated. IDs and direct package targets
are de-duplicated and sorted. `systemUpgradeRequired` is always `false`.

## Development

No runtime or test dependencies are required:

```console
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

The production transaction design and its trust boundary are documented in
[`docs/TRANSACTION_BACKEND.md`](docs/TRANSACTION_BACKEND.md).
