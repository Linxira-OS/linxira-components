# Linxira Components

`linxira-components` is the catalog-bound Arch package transaction backend for
Linxira OS. It supports Catalog v3 selection documents as well as the Catalog
v2 profile/application compatibility interface, creates deterministic request
plans, confirms unchanged plans, applies root-only pacman transactions, and
persists durable receipts.

## Safety boundary

- Catalog JSON is decoded as UTF-8 with duplicate keys rejected.
- Catalog structures, references, Arch sources, architectures, and package
  identifiers are strictly validated before use.
- Catalog v3 selections are revalidated against the exact catalog bytes,
  nested bundle references, required/recommended/optional provenance, user
  overrides, and `multi`/`exclusive`/`bounded`/`preset` constraints.
- Plans contain catalog-expanded package targets and metadata, never commands.
  Only available `pacman` leaves from source `arch` can produce targets.
- AUR, Conda, operation, unavailable, and unsupported-provider leaves are
  recorded as pending or unsupported and are never executed.
- Plan and confirmation digests are SHA-256 over RFC-style canonical JSON
  (sorted keys, compact separators, ASCII encoding) excluding `digest` itself.
- Confirmation rejects a changed catalog and a modified plan.
- Writes require an existing explicit output directory and one plain filename.
  Symlinked directories and targets are rejected; files use temporary-file,
  fsync, and atomic replace semantics.
- `apply` reloads the fixed system catalog, rejects catalog drift, re-expands
  v2 IDs or the complete v3 selection, and compares all final leaves,
  provenance, provider/source requirements, statuses, and package targets.
- The backend must run as root. It invokes pacman once with a fixed argument
  vector and never uses a shell, client repository settings, removals, arbitrary
  paths, hooks, environment variables, or system upgrades.
- Receipts are written atomically under
  `/var/lib/linxira/components/receipts` before and after each state transition.

The packaged system D-Bus service owns fixed system-tool transactions below
`/var/lib/linxira/components/system-transactions`. It accepts operation IDs and strict JSON
parameters, binds short-lived plans to the caller UID, machine ID, boot ID, and
operation registry digest, checks Polkit authorization, and writes immutable
receipts. The initial registry exposes only pacman-lock diagnosis and live-chroot
readiness inspection and strict hardware/driver-state diagnosis; none of those
operations mutates the system. The fixed Hyper-V guest-tools operation binds
hardware evidence, Timeshift Btrfs health, pacman database digests, and exact
resolved artifacts into a root-owned plan. Its isolated worker must create and
verify a pre-change snapshot, revalidate state, install only `hyperv`, and verify
all artifacts before writing a receipt. Snapshot restore remains a separate
authorization and requires reboot. Package Center
continues to use its catalog-bound `pkexec linxira-components apply` boundary.

## CLI

Run directly from a checkout on Python 3.11 or newer:

```console
set PYTHONPATH=src
python -m linxira_components list --catalog catalog-v2.json
python -m linxira_components plan --catalog catalog-v2.json --profile developer --output-dir out
python -m linxira_components plan --catalog catalog-v2.json --application haruna --output-dir out
python -m linxira_components plan --catalog catalog-v3.json --selection selection.json --output-dir out
python -m linxira_components confirm --catalog catalog-v2.json --plan out/request-plan.json --output-dir out
python -m linxira_components apply --catalog catalog-v3.json --confirmation out/confirmation.json
```

`--profile` and `--application` may be repeated. IDs and direct package targets
are de-duplicated and sorted. `systemUpgradeRequired` is always `false`.

Catalog v3 uses `--selection` (alias `--selection-document`) exclusively. The
selection must use `org.linxira.component-selection.v1` and must already contain
the user's resolved leaf choices. A pacman leaf may declare one of `package`,
`packages`, or `artifact`; the current Catalog v3 design example omits these and
therefore uses the stable leaf ID as its catalog-authorized package target.
Plans, confirmations, and receipts use their v2 schemas for this path and retain
`finalLeafIds`, every leaf's `requestedBy` and provenance, provider/source
requirements, and pending/unsupported IDs.

## Development

The core unit suite has no extra Python dependencies. The optional D-Bus smoke
test requires `python-dbus`, `python-gobject`, `pytest`, and `dbus-run-session`:

```console
python -m unittest discover -s tests -v
python -m compileall -q src tests
PYTHONPATH=src dbus-run-session python -m pytest -q tests/test_dbus_service.py
```

The production transaction design and its trust boundary are documented in
[`docs/TRANSACTION_BACKEND.md`](docs/TRANSACTION_BACKEND.md).
