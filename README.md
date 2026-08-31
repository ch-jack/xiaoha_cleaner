# 秒杀小哈

用于扫描并移除 FiveM 服务器中的小哈/HGAdmin 资源、自动注入守卫、启动配置引用和数据库对象。双击独立 EXE 可直接打开图形界面，也保留完整命令行接口供 CK 免费工具箱和自动化任务调用。工具基于 raw dumper 与 decrypted 样本建立识别规则，并内置从 decrypted 样本确认的数据库表清单。

## 主要能力

- 识别 `xiaoha_*`、`xiaoha-*`、`hgadmin*` 以及 manifest 作者/产品特征确认归属的资源。
- 将确认归属资源移动到目标目录外的隔离目录，而不是直接永久删除。
- 在其他正常资源中精确移除 `hgadmin_guard.lua`、`hgadmin_guard_sv.lua`、`@hgadmin/shared/anticheat_hookfactory.lua` 和带 `[[HGADMIN-*]]` 标记的 manifest 注入。
- 注释 `server.cfg` 等配置中的精确 `ensure`、`start`、`restart`、`stop` 与 ACE 引用。
- 自动读取 `server.cfg`，跟随 `exec *.cfg` 配置链，并安全解析最终生效的 `mysql_connection_string`。
- 支持 MySQL URI 和 `host=...;user=...;password=...;database=...` 属性格式。
- 生成并可选择执行全部已确认小哈/HGAdmin 建表、删列和品牌表清理 SQL。
- 为扫描、文件清理、数据库清理和恢复分别生成本次执行的 JSON/Markdown 报告，逐项记录实际操作、结果与注意事项。
- 支持按 `run-report.json` 恢复文件系统修改；恢复会检查清理后的文件是否又被改动，遇到冲突时保留当前文件并写入报告。

## 下载

从仓库的 [Releases](https://github.com/ch-jack/xiaoha_cleaner/releases) 下载：

- `xiaoha-cleaner-vX.Y.Z-windows-x64.exe`
- `xiaoha-cleaner-vX.Y.Z-windows-x64.exe.sha256`
- `xiaoha-cleaner-vX.Y.Z-windows.zip`
- `xiaoha-cleaner-vX.Y.Z-windows.zip.sha256`

普通用户直接运行 EXE，不需要安装 Python。兼容包解压后也可运行 `xiaoha-cleaner.exe`；源码入口 `xiaoha-cleaner.cmd` 仍需要 Python 3.7+。只有执行数据库清理时才需要 MySQL/MariaDB 命令行客户端。

## 使用

双击 `xiaoha-cleaner.exe` 会打开“秒杀小哈”图形界面。先停止 FiveM 服务器；涉及数据库删除时，必须先备份数据库。

EXE 同时保留稳定 CLI：

```powershell
# 只读扫描，不修改文件、不连接数据库
.\xiaoha-cleaner.exe scan "D:\server-data"

# 隔离资源、清理注入和配置引用，仅生成数据库 SQL
.\xiaoha-cleaner.exe clean "D:\server-data" --yes

# 同时从 server.cfg 自动读取 MySQL，并执行删表/删列
.\xiaoha-cleaner.exe clean "D:\server-data" --yes `
  --apply-sql --yes-drop-tables
```

如果目标目录下存在多个 txAdmin profile，并且连接到不同数据库，工具会拒绝自动选择。此时明确指定配置：

```powershell
.\xiaoha-cleaner.exe clean "D:\txData" --yes `
  --apply-sql --yes-drop-tables `
  --server-cfg "D:\txData\default\server.cfg"
```

如果 `mysql.exe` 不在 PATH：

```powershell
--mysql-command "C:\MariaDB\bin\mysql.exe"
```

仍可通过 `--mysql-uri` 手动覆盖自动读取结果。连接串只在当前进程内存中使用；密码不会写入报告、终端或 MySQL 命令行参数。

## 支持的 server.cfg 写法

URI：

```cfg
set mysql_connection_string "mysql://user:password@127.0.0.1:3306/fivem"
```

属性格式：

```cfg
set mysql_connection_string "host=127.0.0.1;port=3306;user=root;password=secret;database=fivem"
```

拆分配置：

```cfg
exec config/database.cfg
```

工具按 `server.cfg` 的配置顺序跟随 `exec`，使用最终一次 `mysql_connection_string` 赋值。若引用的是环境变量，仅在该环境变量存在时读取。

## 数据库清理范围

内置样本确认的 14 张表：

```text
bans
hgadmin_ac_logs
hgadmin_ban_videos
hgadmin_groups
hgadmin_high_risk_log
hgadmin_local_bans
hgadmin_log
hgadmin_members
hgadmin_ticket_messages
hgadmin_tickets
hgadmin_whitelist
joint_ban_whitelist
joint_bans
warns
```

还会清理：

- 小哈资源源码中实际解析出的每一个 `CREATE TABLE`。
- `owned_vehicles.type`、`player_vehicles.type`、`users.last_seen`。
- 当前数据库内表名包含 `xiaoha` 或 `hgadmin` 的其他基础表。

按项目需求，`bans`、`warns` 也属于有效删除范围；如果其他管理资源共用这些表，删除会同时影响它们。MySQL 不记录共享表中每条数据由哪个 FiveM 资源写入，因此工具不会无条件清空玩家、车辆、职业等核心框架表。

## 文件恢复

清理会在目标目录外创建 `_xiaoha_quarantine`，其中包含原资源、注入文件、被编辑文件备份和运行报告：

```powershell
.\xiaoha-cleaner.exe restore `
  "D:\_xiaoha_quarantine\server-data_YYYYMMDD_HHMMSS\run-report.json" `
  --yes
```

数据库 `DROP` 操作无法通过文件报告恢复，只能从执行前的数据库备份恢复。

## 执行报告

- 扫描：`scan-report.json` / `scan-report.md`，明确本次只读发现内容，没有修改文件或数据库。
- 清理：隔离目录内的 `run-report.json` / `run-report.md`，逐项记录资源隔离、注入移除、配置修改、备份与最终状态。
- 数据库：清理报告会记录是否请求执行、目标数据库、SQL 哈希与成功/失败结果；SQL 失败时会明确提示数据库可能已经部分变更。独立执行 `apply-sql` 时生成 `database-report.json` / `database-report.md`。
- 恢复：`restore-report.json` / `restore-report.md`，分别列出恢复成功、冲突与失败项目。

报告中的 `terminal=false` 表示进程尚未形成最终结论，例如 SQL 正在执行或任务被强制停止。报告不会保存 MySQL URI、密码或完整数据库命令行。文件恢复不会撤销数据库 `DROP` / `ALTER`；数据库只能从执行前备份恢复。

## 本地验证与打包

```powershell
python -m py_compile *.py
python -m unittest discover -s tests -v
python -m pip install -r requirements-build.txt
$exe = .\tools\Build-Executable.ps1 -Version v1.1.0 | ConvertFrom-Json
.\tools\Build-Release.ps1 -Version v1.1.0 -ExecutablePath $exe.executable
```

推送 `v*` 标签后，GitHub Actions 会运行 Python 3.7/3.8/3.12 测试，以固定版本 PyInstaller 生成 Windows x64 单文件 EXE，验证 GUI、CLI、失败报告和 SHA-256，再发布 EXE、兼容 ZIP 及各自校验文件。
