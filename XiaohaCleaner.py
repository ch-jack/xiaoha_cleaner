#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Final public launcher built from both raw and decrypted sample evidence."""

from __future__ import print_function

import re
import sys
from pathlib import Path

import xiaoha_cleaner as core

_base_print_summary = core.print_summary

# Installs extraction of every CREATE TABLE plus ALTER TABLE ADD COLUMN.
import xiaoha_cleaner_all_sql as aggressive  # noqa: E402,F401

_base_build_plan = core.build_plan
_base_markdown_report = core.markdown_report
_base_database_cleanup_sql = core.database_cleanup_sql


# Confirmed from D:\fivem\dump\decrypted, not guessed from resource names.
HGADMIN_SAMPLE_TABLES = {
    "bans",
    "hgadmin_ac_logs",
    "hgadmin_ban_videos",
    "hgadmin_groups",
    "hgadmin_high_risk_log",
    "hgadmin_local_bans",
    "hgadmin_log",
    "hgadmin_members",
    "hgadmin_ticket_messages",
    "hgadmin_tickets",
    "hgadmin_whitelist",
    "joint_ban_whitelist",
    "joint_bans",
    "warns",
}
HGADMIN_SAMPLE_COLUMNS = {
    ("owned_vehicles", "type"),
    ("player_vehicles", "type"),
    ("users", "last_seen"),
}


def guard_header(text):
    lowered = text.lower()
    return "hgadmin" in lowered and ("保护守卫" in text or "anti-cheat guard" in lowered)


def find_dedicated_injection_files(resource_root, manifest_text):
    """Only isolate dedicated guards; never manifests or arbitrary business Lua."""
    manifest_lower = manifest_text.lower()
    found = []
    for path in core.iter_files(resource_root):
        if path.suffix.lower() != ".lua" or path.name.lower() in core.MANIFEST_NAMES:
            continue
        try:
            head, _, _ = core.read_text_file(path, max_bytes=32 * 1024)
        except OSError:
            head = ""
        name_match = path.name.lower() in core.INJECTION_FILE_NAMES
        marker = core.INJECTION_MARKER_RE.search(head)
        manifest_match = name_match and path.name.lower() in manifest_lower
        dedicated_custom_guard = bool(
            marker and marker.start() <= 128 and guard_header(head[:512])
        )
        if (name_match and (marker or manifest_match)) or dedicated_custom_guard:
            found.append({
                "path": str(path),
                "relative_to_resource": core.relative_text(path, resource_root),
                "reason": "guard-marker" if marker else "manifest-reference",
            })
    return found


def plan_has_hgadmin(plan):
    for item in plan["resources"]["owned"]:
        if core.HGADMIN_NAME_RE.search(item["name"]):
            return True
        if "hgadmin-v3" in item.get("content_hits", {}):
            return True
        try:
            manifest, _, _ = core.read_text_file(item["manifest"], max_bytes=512 * 1024)
        except OSError:
            manifest = ""
        if re.search(r"\bHG\s*&?\s*ADMIN\b|\bHGADMIN\b", manifest, re.I):
            return True
    return False


def refresh_external_sql_edits(plan):
    target = Path(plan["target"])
    owned_roots = [Path(item["path"]) for item in plan["resources"]["owned"]]
    safe_tables = set(plan["sql"]["safe_tables"])
    edits = {}
    for path in core.iter_files(target):
        if path.suffix.lower() != ".sql" or core.is_owned_path(path, owned_roots):
            continue
        edit = core.plan_external_sql_edit(path, target, safe_tables)
        if edit:
            edits[core.path_key(path)] = edit
    plan["edits"]["sql_files"] = sorted(
        edits.values(), key=lambda item: core.path_key(item["path"])
    )
    plan["summary"]["external_sql_edits"] = len(plan["edits"]["sql_files"])


def build_catalog_plan(target, include_review=False):
    plan = _base_build_plan(target, include_review=include_review)
    catalog_applied = plan_has_hgadmin(plan)
    if catalog_applied:
        active = set(plan["sql"]["safe_tables"])
        active.update(HGADMIN_SAMPLE_TABLES)
        plan["sql"]["safe_tables"] = sorted(active)
        created = set(plan["sql"].get("created_tables", []))
        created.update(HGADMIN_SAMPLE_TABLES)
        plan["sql"]["created_tables"] = sorted(created)
        plan["sql"]["review_tables"] = sorted(
            table for table in plan["sql"]["review_tables"] if table not in active
        )
        occurrences = plan["sql"].setdefault("occurrences", {})
        for table in HGADMIN_SAMPLE_TABLES:
            occurrences.setdefault(table, []).append(
                "built-in-catalog:dump/decrypted HGAdmin sample"
            )
            occurrences[table] = sorted(set(occurrences[table]))

        columns = {
            (item["table"], item["column"])
            for item in plan["sql"].get("added_columns", [])
        }
        columns.update(HGADMIN_SAMPLE_COLUMNS)
        plan["sql"]["added_columns"] = [
            {"table": table, "column": column}
            for table, column in sorted(columns)
            if table not in active
        ]
        refresh_external_sql_edits(plan)

    plan["sql"]["sample_catalog_applied"] = catalog_applied
    plan["sql"]["sample_catalog"] = (
        "D:/fivem/dump/decrypted HGAdmin" if catalog_applied else None
    )
    plan["summary"]["safe_sql_tables"] = len(plan["sql"]["safe_tables"])
    plan["summary"]["review_sql_tables"] = len(plan["sql"]["review_tables"])
    plan["summary"]["added_sql_columns"] = len(plan["sql"].get("added_columns", []))
    return plan


def database_cleanup_sql(plan):
    sql = _base_database_cleanup_sql(plan)
    marker = "SET FOREIGN_KEY_CHECKS = @XIAOHA_OLD_FOREIGN_KEY_CHECKS;"
    dynamic = """-- Catch branded tables created by encrypted server-only code.
-- MySQL does not retain creator provenance, so generic names must come from
-- decrypted CREATE TABLE evidence; xiaoha/hgadmin-branded names are found live.
SET SESSION group_concat_max_len = 1048576;
SELECT GROUP_CONCAT(
  CONCAT('DROP TABLE IF EXISTS `', REPLACE(TABLE_NAME, '`', '``'), '`')
  SEPARATOR '; '
) INTO @XIAOHA_BRANDED_DROPS
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND (LOWER(TABLE_NAME) LIKE '%xiaoha%' OR LOWER(TABLE_NAME) LIKE '%hgadmin%');
SET @XIAOHA_BRANDED_DROPS = IFNULL(@XIAOHA_BRANDED_DROPS, 'SELECT 1');
PREPARE XIAOHA_BRANDED_STMT FROM @XIAOHA_BRANDED_DROPS;
EXECUTE XIAOHA_BRANDED_STMT;
DEALLOCATE PREPARE XIAOHA_BRANDED_STMT;

"""
    if marker in sql:
        sql = sql.replace(marker, dynamic + marker, 1)
    return sql


def markdown_report(
    plan, status="scan", operations=None, error=None,
    database_execution=None, notices=None,
    terminal=True, finished_at=None,
):
    text = _base_markdown_report(
        plan, status, operations, error, database_execution, notices,
        terminal, finished_at,
    )
    note = (
        "- 已应用 decrypted 样本内置 SQL 表库：{}\n".format(
            "是" if plan["sql"].get("sample_catalog_applied") else "否"
        )
    )
    marker = "## 汇总\n\n"
    if marker in text:
        text = text.replace(marker, marker + note, 1)
    return text


def print_summary(plan):
    _base_print_summary(plan)
    print("Added SQL columns to remove: {}".format(
        plan["summary"].get("added_sql_columns", 0)
    ))
    print("Decrypted SQL catalog: {}".format(
        "applied" if plan["sql"].get("sample_catalog_applied") else "not applicable"
    ))


core.find_injection_files = find_dedicated_injection_files
core.build_plan = build_catalog_plan
core.database_cleanup_sql = database_cleanup_sql
core.markdown_report = markdown_report
core.print_summary = print_summary


if __name__ == "__main__":
    sys.exit(core.main())
