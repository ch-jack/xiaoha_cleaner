# Changelog

## v1.1.1 - 2026-08-31

- 声明 Per-Monitor DPI Aware V2，避免 Windows 125%/150%/200% 显示缩放对整个窗口做模糊的位图拉伸。
- 在创建第一个 Tk 窗口前设置 DPI 感知，并按当前显示器 DPI 动态计算 Tk 字体缩放和窗口尺寸。
- EXE 内嵌 Windows 10/11 高 DPI 清单，同时保留旧系统 API 回退和 GUI DPI 冒烟测试。

## v1.1.0 - 2026-08-31

- 产品显示名称改为“秒杀小哈”。
- 新增 Windows x64 单文件 EXE；双击打开独立 GUI，传入参数时保持原 CLI 契约。
- GUI 复用同一 CLI 子进程，保留只读扫描、隔离清理、数据库双重确认、报告和文件恢复边界。
- 默认报告迁移到 `%LOCALAPPDATA%\XiaohaCleaner\reports`，不依赖源码目录或 PyInstaller 临时目录。
- GitHub Actions 同时发布 EXE、兼容 ZIP 和各自 SHA-256，并执行 EXE GUI/CLI 冒烟验证。
- 兼容 ZIP 保留 Python 入口并加入 EXE，支持旧工具箱回退运行。

## v1.0.1 - 2026-07-18

- 为扫描、文件清理、数据库清理和恢复分别生成本次执行报告与注意事项。
- 逐项记录实际文件操作、备份和 SHA-256，而不再只给出操作总数。
- 准确区分预检失败、完整回滚、回滚不完整、SQL 成功和数据库可能部分变更。
- 扫描失败、自动数据库配置失败及独立 `apply-sql` 执行也会留下终态报告。
- 恢复时检测清理后的文件变更和隔离内容冲突，跳过冲突项并逐项报告。
- 保持 Auto/Final 稳定入口和 Python 3.7 兼容。
- 修复 Windows CMD 启动器丢失组件失败退出码的问题，并在 CI 中锁定该行为。
- 拒绝伪造根目录恢复目标和通过目录联接越界的隔离/恢复路径。

## v1.0.0 - 2026-07-17

- Initial public release.
- Detect and quarantine Xiaoha/HGAdmin FiveM resources.
- Remove dedicated HGAdmin guard injections and manifest/startup references.
- Generate and optionally execute the confirmed 14-table HGAdmin cleanup catalog.
- Reverse three confirmed framework-column additions.
- Automatically discover MySQL settings from `server.cfg` and followed `exec` files.
- Support reversible filesystem cleanup, JSON/Markdown reports and SHA-256 release artifacts.
