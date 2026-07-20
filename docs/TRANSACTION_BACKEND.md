# Production Transaction Backend

## Status

Phase 1 provides a root-only CLI backend used through Package Center's explicit
`pkexec` boundary. It revalidates confirmation fields, catalog bytes, Catalog v2
profile/application IDs or a Catalog v3 selection graph, and the expanded
package target set before invoking pacman. The repository does not yet install
a D-Bus service or systemd unit.

## Trust boundary

The current backend accepts only a schema-validated confirmation document. It
does not accept package-manager arguments, repository definitions, filesystem
paths, hooks, environment variables, removals, upgrades, or command strings.
Package Center creates the plan and confirmation as the unprivileged user, then
authorizes only `apply` through `pkexec`.

The later service hardening target remains a narrowly scoped root-owned system
D-Bus service with peer authorization through Polkit and serialized operations.

## Frozen transaction inputs

Future frozen planning will resolve package versions and signed package files
without touching the host package database. Resolution and preflight checks
will use **pyalpm with a private DBPath**, private cache, and an explicit,
distribution-owned mirror configuration. The resulting frozen plan will bind:

- catalog SHA-256 and profile IDs;
- architecture and repository database digests;
- exact package name, epoch/version/release, architecture, size, and SHA-256;
- expected package signature identity and trust result;
- dependency closure and declared conflict/removal set;
- network and full-system-upgrade requirements.

The Phase 1 backend currently delegates dependency/version resolution and
signature enforcement to the target system's pacman configuration. Only the
catalog-expanded direct targets cross the privilege boundary. A later backend
must ensure only frozen, downloaded, cryptographically signed package files accepted by the
distribution keyring may cross into apply. The backend will not reinterpret
profile IDs or resolve newer versions while applying.

## Catalog v3 selection boundary

`plan --selection FILE` accepts only the resolved selection document produced
from the same catalog bytes. Planning independently validates stable
application/component/bundle IDs, every nested `requestedBy` edge, exact
required/recommended/optional/user provenance, effective nested bundles, user
overrides, selection constraints, and provider/source requirement summaries.

Only available leaves with `provider: pacman` and `source: arch` become package
targets. Package targets come only from the catalog leaf's `package`,
`packages`, or `artifact` field; the current draft v3 catalog compatibility
rule uses the stable leaf ID when a pacman leaf omits all three. Selection input
cannot supply package names. AUR and Conda leaves, operation leaves, and
unavailable leaves are recorded as `pending`; other providers and non-Arch
pacman sources are `unsupported`. Neither class is converted into an argv or
arbitrary command. A pending-only confirmation writes a receipt without
starting a process.

Catalog v3 request plans, confirmations, and receipts record final leaf IDs,
selected bundle IDs, each leaf's requested paths and provenance,
provider/source requirements, exact ready package targets, and all pending or
unsupported items. Confirmation and apply independently re-expand the embedded
selection and require every recorded field to match.

## Drift rejection

Immediately before apply, the service will independently recalculate all bound
state. It must reject the transaction as `stale` when any relevant input differs
from the confirmed plan, including catalog bytes, repository databases, local
package database state, dependency closure, file hashes, signatures,
architecture, conflicts, removals, or upgrade requirements. It must never
silently re-plan, broaden targets, or ask the package manager to choose newer
artifacts after confirmation.

Phase 1 host mutations use pacman without a shell and reject system upgrades.
Future D-Bus service mutations should use libalpm through pyalpm. Package
scripts and hooks remain part of the Arch package trust boundary.

## Receipt lifecycle

The service persists receipts atomically before and after state transitions:

```text
planned -> confirmed -> applying -> succeeded
    |          |           |------> failed
    |          |           |------> interrupted
    |          |           `------> stale
    |          |------------------> interrupted
    |          `------------------> stale
    `-----------------------------> stale
```

Terminal receipts are immutable. Startup recovery marks a receipt left in
`applying` as `interrupted`; it does not resume automatically. Logs and receipts
must not contain secrets from the calling process environment.

## Draft interfaces

`api/org.linxira.Components1.xml` and
`policy/org.linxira.components.policy.in` are review artifacts only. A later
packaging phase must choose final bus ownership, activation, sandboxing,
authorization defaults, audit storage, rollback policy, and operational limits
before installing any interface.
