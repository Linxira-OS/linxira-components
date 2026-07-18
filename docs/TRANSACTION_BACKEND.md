# Production Transaction Backend

## Status

This is a Phase 1 design contract, not an enabled service. The repository does
not install a D-Bus service file, systemd unit, Polkit rule, or privileged
executable. `linxira-components apply` is intentionally unimplemented.

## Trust boundary

The production backend will be a narrowly scoped root-owned **system D-Bus**
service. An unprivileged client may submit only a schema-validated confirmation
document. It may not submit package-manager arguments, repository definitions,
filesystem paths, hooks, environment variables, or command strings.

Authorization will be checked for the calling D-Bus peer through Polkit at the
moment an apply operation begins. Identity and authorization must not be passed
as client-controlled fields. The service will serialize transactions and emit
state changes tied to a receipt UUID.

## Frozen transaction inputs

Planning in production will resolve package versions and signed package files
without touching the host package database. Resolution and preflight checks
will use **pyalpm with a private DBPath**, private cache, and an explicit,
distribution-owned mirror configuration. The resulting frozen plan will bind:

- catalog SHA-256 and profile IDs;
- architecture and repository database digests;
- exact package name, epoch/version/release, architecture, size, and SHA-256;
- expected package signature identity and trust result;
- dependency closure and declared conflict/removal set;
- network and full-system-upgrade requirements.

Only frozen, downloaded, cryptographically signed package files accepted by the
distribution keyring may cross into apply. The backend will not reinterpret
profile IDs or resolve newer versions while applying.

## Drift rejection

Immediately before apply, the service will independently recalculate all bound
state. It must reject the transaction as `stale` when any relevant input differs
from the confirmed plan, including catalog bytes, repository databases, local
package database state, dependency closure, file hashes, signatures,
architecture, conflicts, removals, or upgrade requirements. It must never
silently re-plan, broaden targets, or ask the package manager to choose newer
artifacts after confirmation.

Host mutations will use libalpm through pyalpm, not shell commands. A system
upgrade will require an explicit plan flag and authorization. Package scripts
and hooks remain part of the Arch package trust boundary and must be surfaced
in audit records.

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
