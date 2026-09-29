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
operations mutates the system. The fixed Hyper-V, QEMU, and VMware guest operations bind
hardware evidence, Timeshift Btrfs health, pacman database digests, and exact
resolved artifacts into a root-owned plan. Its isolated worker must create and
verify a pre-change snapshot while holding the libalpm transaction lock, install
only each adapter's fixed packages, and verify artifacts and service state before
writing a receipt. VirtualBox remains unavailable until its dual-kernel module
providers are fixed. Snapshot restore remains a separate
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

---

## 简体中文

`linxira-components` 是面向 Linxira OS、与目录绑定的 Arch 软件包事务后端。它支持 Catalog v3 选择文档以及 Catalog v2 的 profile/application 兼容接口，创建确定性的请求计划，确认计划未发生变化，执行仅限 root 的 pacman 事务，并持久化持久回执。

## 安全边界

- Catalog JSON 以 UTF-8 解码，拒绝重复键。
- Catalog 结构、引用、Arch 来源、架构与包标识符在使用前均严格校验。
- Catalog v3 选择会针对确切的 catalog 字节、嵌套 bundle 引用、required/recommended/optional 来源、用户覆盖以及 `multi`/`exclusive`/`bounded`/`preset` 约束重新校验。
- 计划包含 catalog 展开后的包目标与元数据，绝不包含命令。只有来自 `arch` 源、当前可用的 `pacman` 叶子才能产生目标。
- AUR、Conda、operation、不可用与不支持提供方的叶子被记录为 pending 或 unsupported，从不执行。
- 计划与确认摘要是对 RFC 风格规范 JSON（键排序、紧凑分隔符、ASCII 编码）计算的 SHA-256，且排除 `digest` 本身。
- 确认会拒绝已变更的 catalog 与被修改的计划。
- 写入要求一个已存在的显式输出目录和一个纯文件名。符号链接的目录与目标被拒绝；文件使用临时文件、fsync 与原子替换语义。
- `apply` 会重新加载固定的系统 catalog，拒绝 catalog 漂移，重新展开 v2 ID 或完整 v3 选择，并比较所有最终叶子、来源、provider/source 要求、状态与包目标。
- 后端必须以 root 运行。它以固定参数向量调用一次 pacman，绝不使用 shell、客户端仓库设置、移除操作、任意路径、hooks、环境变量或系统升级。
- 回执在每次状态转换前后原子地写入 `/var/lib/linxira/components/receipts` 之下。

打包的系统 D-Bus 服务拥有 `/var/lib/linxira/components/system-transactions` 之下的固定系统工具事务。它接受操作 ID 与严格 JSON 参数，把短生命周期计划绑定到调用者 UID、machine ID、boot ID 与操作注册表摘要，检查 Polkit 授权，并写入不可变回执。初始注册表仅暴露 pacman 锁诊断、live-chroot 就绪检查以及严格的硬件/驱动状态诊断；这些操作都不变更系统。固定的 Hyper-V、QEMU 与 VMware 客体操作把硬件证据、Timeshift Btrfs 健康状态、pacman 数据库摘要与精确解析的工件绑定到 root 所属的计划中。其隔离 worker 必须在持有 libalpm 事务锁的同时创建并校验变更前快照，仅安装各适配器固定的软件包，并在写入回执前校验工件与服务状态。VirtualBox 在其双内核模块提供方修复之前保持不可用。快照恢复仍是单独的授权且需要重启。Package Center 继续使用其目录绑定的 `pkexec linxira-components apply` 边界。

## CLI

在 Python 3.11 或更新版本的检出目录中直接运行：

```console
set PYTHONPATH=src
python -m linxira_components list --catalog catalog-v2.json
python -m linxira_components plan --catalog catalog-v2.json --profile developer --output-dir out
python -m linxira_components plan --catalog catalog-v2.json --application haruna --output-dir out
python -m linxira_components plan --catalog catalog-v3.json --selection selection.json --output-dir out
python -m linxira_components confirm --catalog catalog-v2.json --plan out/request-plan.json --output-dir out
python -m linxira_components apply --catalog catalog-v3.json --confirmation out/confirmation.json
```

`--profile` 与 `--application` 可以重复。ID 与直接包目标会去重并排序。`systemUpgradeRequired` 恒为 `false`。

Catalog v3 专门使用 `--selection`（别名 `--selection-document`）。选择文档必须使用 `org.linxira.component-selection.v1`，并且必须已包含用户已解析的叶子选择。pacman 叶子可声明 `package`、`packages` 或 `artifact` 之一；当前的 Catalog v3 设计示例省略了这些字段，因此使用稳定叶子 ID 作为其 catalog 授权的包目标。此路径的计划、确认与回执沿用其 v2 schema，并保留 `finalLeafIds`、每个叶子的 `requestedBy` 与来源、provider/source 要求以及 pending/unsupported ID。

## 开发

核心单元测试套件没有额外的 Python 依赖。可选的 D-Bus 冒烟测试需要 `python-dbus`、`python-gobject`、`pytest` 与 `dbus-run-session`：

```console
python -m unittest discover -s tests -v
python -m compileall -q src tests
PYTHONPATH=src dbus-run-session python -m pytest -q tests/test_dbus_service.py
```

生产事务设计及其信任边界记录在 [`docs/TRANSACTION_BACKEND.md`](docs/TRANSACTION_BACKEND.md)。
