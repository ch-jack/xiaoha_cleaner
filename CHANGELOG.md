# Changelog

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
