# linxira-components · Agent 开发规范

> **档位**:A 档 · 系统源仓(带 `VERSION` + `.github/workflows/release.yml`)。
> **本仓职责**:面向 Linxira OS、与 catalog 绑定的 Arch 软件包事务后端——**全系统唯一的提权/事务执行入口**。
> 通用条款见工作区总纲 `f:\Linxira-OS\AGENTS.md`;发布/测试口径见 `linxira-os/docs/RELEASE_STANDARD.md`。本文件只写本仓特有约定。

## 职责与边界

- **负责**:Catalog v3 选择文档与 v2 profile/application 兼容接口 → 确定性 `request-plan` → 确认(confirm)→ 仅限 root 的 pacman 事务(apply)→ 持久回执(receipt)。以及打包的系统 D-Bus 服务(固定系统工具事务)与 `guard`(工作区守护)日常操作。
- **这是唯一入口**:事务计划、确认、提权执行、回执**只在本仓实现**。`linxira-component-manager` / `linxira-package-center` / `linxira-config-hub stack` 都只是调用方,通过固定参数向量调 `linxira-components plan/confirm`,再经 `pkexec linxira-components apply` 提权;**UI 仓不得重新实现提权或展开包名**。
- **不负责**:catalog 数据本身(归 `linxira-catalog`);UI(归各 UI 仓)。
- 提权只走 **本仓 + polkit**,禁直接 `sudo`/`su`/`doas`/`run0`。

## 目录布局

```
src/linxira_components/   cli.py / service.py / backend.py / models.py
                          guard_cli.py / guard_worker.py / guard_store.py
                          driver_worker.py / catalog_v3.py / selection.py
                          schemas/  (request-plan / confirmation / receipt / catalog / selection)
policy/    org.linxira.components.policy.in   Polkit 策略
service/   org.linxira.Components1.service / linxira-components.service
           linxira-components-worker@.service / linxira-workspace-guard-snapshot.*
api/       org.linxira.Components1.xml        D-Bus 接口
scripts/   linxira-components / -worker / -service / -guard / -guard-timer
docs/      TRANSACTION_BACKEND.md             事务设计与信任边界
tests/     test_core / test_v3 / test_dbus_service / test_system_transactions ...
```

## 本地校验

核心单测无额外依赖;D-Bus 冒烟测试需 `python-dbus` / `python-gobject` / `pytest` / `dbus-run-session`:

```sh
python -m unittest discover -s tests -v
python -m compileall -q src tests
PYTHONPATH=src dbus-run-session python -m pytest -q tests/test_dbus_service.py
python -m pip wheel --no-deps --wheel-dir dist .   # CI 构建校验
```

CI(`.github/workflows/ci.yml`)先校验 **`VERSION` 与 `pyproject.toml` 的 version 一致**,再跑上面前三项与 wheel 构建。

## 版本与发布

- 版本唯一来源是根目录 `VERSION`(当前 0.8.3);`pyproject.toml` 的 `version` 必须与 `VERSION` 同步(CI 会拒)。
- CLI 入口:`linxira-components = linxira_components.cli:main`(另有 `python -m linxira_components`,Python ≥ 3.11)。
- 提交 `VERSION` 变更即触发 `.github/workflows/release.yml` 走全自动发布链。**禁止手工 bump**。

## 禁区

- **安全边界不可放宽**:catalog 严格校验、计划/确认 SHA-256 摘要、拒绝 catalog 漂移与被改计划、原子回执写入 `/var/lib/linxira/components/receipts`。
- 计划**只含包目标与元数据,绝不含命令**;AUR/Conda/operation/unavailable/unsupported 叶子只记录为 pending/unsupported,**从不执行**。
- 调用 pacman 只允许**固定参数向量**,禁 shell、仓库设置、移除、任意路径、hooks、环境变量、系统升级。
- `apply` 必须以 root 运行;快照恢复是**独立授权且需重启**,不得并入普通 apply。
- 只读命令免提权;破坏性操作(`reset --hard`、批量删除)先确认。