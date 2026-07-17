#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FiveM Xiaoha/HGAdmin resource and injection cleaner.

The default operation is read-only scanning.  ``clean --yes`` quarantines
owned resources, strips known HGAdmin guard injections from otherwise normal
resources, comments exact startup references, and backs up every edited file.
Database cleanup SQL is generated on every run and is only applied when the
caller supplies both ``--apply-sql`` and ``--yes-drop-tables``.

Python 3.7+; standard library only.
"""

from __future__ import print_function

import argparse
import datetime as _datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import traceback
from pathlib import Path
from urllib.parse import unquote, urlparse


VERSION = "1.0.0"

MANIFEST_NAMES = ("fxmanifest.lua", "__resource.lua")
IGNORED_DIR_NAMES = {
    ".git",
    ".svn",
    ".hg",
    ".cache",
    "cache",
    "node_modules",
    "__pycache__",
    "xiaoha_reports",
    "_xiaoha_quarantine",
    "fivem_xiaoha_cleaner",
}
TEXT_SUFFIXES = {
    ".lua", ".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx",
    ".json", ".jsonc", ".md", ".txt", ".cfg", ".conf", ".ini",
    ".toml", ".xml", ".html", ".htm", ".css", ".scss", ".sql",
    ".yml", ".yaml",
}
CODE_REFERENCE_SUFFIXES = {
    ".lua", ".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx",
    ".json", ".jsonc", ".html", ".htm", ".md", ".txt",
}

XIAOHA_NAME_RE = re.compile(r"xiao[\s._-]*ha", re.I)
HGADMIN_NAME_RE = re.compile(r"^hg[\s._-]*admin(?:$|[\s._-])", re.I)
AUTHOR_RE = re.compile(r"(?im)^\s*author\s*(?:\(\s*)?['\"]([^'\"]+)['\"]")
INJECTION_MARKER_RE = re.compile(
    r"\[\[HGADMIN-(?:GUARD(?:-SV)?|DEEPHOOK)[^\]]*\]\]", re.I
)
INJECTION_PATH_RE = re.compile(
    r"(?:hgadmin_guard(?:_sv)?\.lua|@hgadmin[/\\]shared[/\\]anticheat_hookfactory\.lua)",
    re.I,
)
INJECTION_FILE_NAMES = {"hgadmin_guard.lua", "hgadmin_guard_sv.lua"}

OWNERSHIP_CONTENT_PATTERNS = (
    ("xiaoha-cloud", re.compile(r"(?:https?://)?[A-Za-z0-9_.-]*xiaoha\.cloud", re.I)),
    ("hgadmin-v3", re.compile(r"\bH\s*&\s*GADMIN\s*v?3\b|\bHGADMINV?3\b", re.I)),
    ("xiaoha-event", re.compile(r"\bxiaohahenshuai\s*:", re.I)),
    ("xiaoha-product", re.compile(r"小哈(?:脚本|团队出品|小助手|科技)", re.I)),
)

SQL_TABLE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:"
    r"CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|"
    r"INSERT\s+INTO|REPLACE\s+INTO|DELETE\s+FROM|"
    r"UPDATE|FROM|JOIN"
    r")\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?[`\"']?([A-Za-z_][A-Za-z0-9_$]*)"
)
SQL_CREATE_TABLE_RE = re.compile(
    r"(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"[`\"']?([A-Za-z_][A-Za-z0-9_$]*)"
)
SAFE_TABLE_NAME_RE = re.compile(r"^(?:hgadmin|xiaoha)[_-][A-Za-z0-9_$]+$", re.I)
SAFE_EXACT_TABLES = {"joint_bans", "joint_ban_whitelist"}
SQL_MUTATION_RE = re.compile(
    r"(?is)\b(?:CREATE|ALTER|DROP|TRUNCATE|INSERT|REPLACE|UPDATE|DELETE)\b"
)

START_COMMAND_RE = re.compile(
    r"^\s*(?:ensure|start|restart|stop)\s+['\"]?([^\s#;'\"]+)", re.I
)
ACE_RESOURCE_RE = re.compile(r"\bresource\.([A-Za-z0-9_.-]+)\b", re.I)


def now_stamp():
    return _datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def now_iso():
    return _datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def path_key(path):
    return os.path.normcase(os.path.abspath(str(path)))


def is_within(child, parent):
    try:
        return os.path.commonpath([path_key(child), path_key(parent)]) == path_key(parent)
    except (ValueError, OSError):
        return False


def relative_text(path, root):
    try:
        return str(Path(path).relative_to(Path(root))).replace("\\", "/")
    except ValueError:
        return str(path)


def human_bytes(value):
    size = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return "{:.2f} {}".format(size, unit)
        size /= 1024.0
    return "{:.2f} TiB".format(size)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def decode_bytes(data):
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1"), "latin-1"


def read_text_file(path, max_bytes=None):
    path = Path(path)
    with path.open("rb") as handle:
        data = handle.read() if max_bytes is None else handle.read(max_bytes)
    text, encoding = decode_bytes(data)
    return text, encoding, data


def encode_text(text, encoding):
    return text.encode(encoding)


def iter_files(root):
    root = Path(root)
    for current, dirs, files in os.walk(str(root), topdown=True, followlinks=False):
        dirs[:] = [
            name for name in dirs
            if name.lower() not in IGNORED_DIR_NAMES
            and not name.lower().startswith("_xiaoha_quarantine")
        ]
        for name in files:
            yield Path(current) / name


def find_resource_roots(target):
    roots = {}
    for path in iter_files(target):
        if path.name.lower() in MANIFEST_NAMES:
            roots[path.parent] = path
    return [(root, roots[root]) for root in sorted(roots, key=lambda p: path_key(p))]


def collapse_nested_paths(paths):
    selected = []
    for path in sorted({Path(p) for p in paths}, key=lambda p: (len(p.parts), path_key(p))):
        if any(is_within(path, parent) for parent in selected):
            continue
        selected.append(path)
    return selected


def measure_tree(root):
    files = 0
    size = 0
    lua_files = 0
    sql_files = 0
    errors = []
    for path in iter_files(root):
        try:
            stat = path.stat()
        except OSError as exc:
            errors.append("{}: {}".format(path, exc))
            continue
        files += 1
        size += stat.st_size
        suffix = path.suffix.lower()
        if suffix == ".lua":
            lua_files += 1
        elif suffix == ".sql":
            sql_files += 1
    return {
        "files": files,
        "bytes": size,
        "lua_files": lua_files,
        "sql_files": sql_files,
        "errors": errors[:20],
    }


def ownership_content_hits(resource_root, byte_budget=4 * 1024 * 1024, file_budget=250):
    hits = {}
    used = 0
    checked = 0
    preferred = []
    other = []
    for path in iter_files(resource_root):
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        name = path.name.lower()
        if (
            name in MANIFEST_NAMES
            or "readme" in name
            or "license" in name
            or "config" in name
            or name == "main.lua"
        ):
            preferred.append(path)
        else:
            other.append(path)
    for path in preferred + other:
        if checked >= file_budget or used >= byte_budget:
            break
        try:
            remaining = byte_budget - used
            text, _, data = read_text_file(path, max_bytes=min(1024 * 1024, remaining))
        except OSError:
            continue
        checked += 1
        used += len(data)
        for label, pattern in OWNERSHIP_CONTENT_PATTERNS:
            if label not in hits and pattern.search(text):
                hits[label] = relative_text(path, resource_root)
        if "xiaoha-cloud" in hits or ("hgadmin-v3" in hits and len(hits) >= 2):
            break
    return hits


def classify_resource(resource_root, manifest_path, target):
    manifest_text = ""
    try:
        manifest_text, _, _ = read_text_file(manifest_path, max_bytes=2 * 1024 * 1024)
    except OSError:
        pass

    name = resource_root.name
    reasons = []
    review_reasons = []
    decisive = False

    if XIAOHA_NAME_RE.search(name):
        reasons.append("resource-name:xiaoha")
        decisive = True
    if HGADMIN_NAME_RE.search(name):
        reasons.append("resource-name:hgadmin")
        decisive = True

    authors = AUTHOR_RE.findall(manifest_text)
    if any(XIAOHA_NAME_RE.search(author) for author in authors):
        reasons.append("manifest-author:xiaoha")
        decisive = True

    if re.search(r"(?im)^\s*description\b[^\r\n]*(?:小哈脚本|小哈团队出品)", manifest_text):
        reasons.append("manifest-description:xiaoha-product")
        decisive = True

    hits = {}
    if not decisive:
        hits = ownership_content_hits(resource_root)
        if "xiaoha-cloud" in hits:
            reasons.append("content:xiaoha-cloud")
            decisive = True
        elif "hgadmin-v3" in hits and len(hits) >= 2:
            reasons.append("content:hgadmin-v3-plus-brand")
            decisive = True
        elif len(hits) >= 2:
            review_reasons.append("multiple-brand-signatures")
        elif hits:
            review_reasons.append("single-brand-signature")

    injection_only = bool(INJECTION_PATH_RE.search(manifest_text) or INJECTION_MARKER_RE.search(manifest_text))
    if injection_only and not decisive:
        review_reasons.append("hgadmin-injection-present-not-owner")

    return {
        "path": str(resource_root),
        "relative_path": relative_text(resource_root, target),
        "name": name,
        "manifest": str(manifest_path),
        "authors": authors,
        "owned": bool(decisive),
        "reasons": reasons,
        "review_reasons": review_reasons,
        "content_hits": hits,
        "injection_present": injection_only,
    }


def is_owned_path(path, owned_roots):
    return any(is_within(path, root) for root in owned_roots)


def script_paths_in_line(line):
    return re.findall(r"['\"]([^'\"]+\.(?:lua|js|cjs|mjs))['\"]", line, re.I)


def plan_manifest_edit(manifest_path, target):
    try:
        text, encoding, original = read_text_file(manifest_path)
    except OSError as exc:
        return None, {"path": str(manifest_path), "error": str(exc)}

    kept = []
    removed = []
    manual = []
    for number, line in enumerate(text.splitlines(True), 1):
        has_injection = bool(INJECTION_PATH_RE.search(line) or INJECTION_MARKER_RE.search(line))
        if not has_injection:
            kept.append(line)
            continue
        paths = script_paths_in_line(line)
        other_paths = [value for value in paths if not INJECTION_PATH_RE.search(value)]
        if other_paths:
            kept.append(line)
            manual.append({"line": number, "text": line.rstrip("\r\n")[:500]})
            continue
        removed.append({"line": number, "text": line.rstrip("\r\n")[:500]})

    if not removed:
        return None, ({"path": str(manifest_path), "manual_lines": manual} if manual else None)
    new_data = encode_text("".join(kept), encoding)
    return {
        "kind": "manifest",
        "path": str(manifest_path),
        "relative_path": relative_text(manifest_path, target),
        "original_sha256": sha256_bytes(original),
        "removed_lines": removed,
        "manual_lines": manual,
        "_new_bytes": new_data,
    }, None


def find_injection_files(resource_root, manifest_text):
    manifest_lower = manifest_text.lower()
    found = []
    for path in iter_files(resource_root):
        if path.suffix.lower() != ".lua":
            continue
        name_match = path.name.lower() in INJECTION_FILE_NAMES
        marker_match = False
        try:
            head, _, _ = read_text_file(path, max_bytes=32 * 1024)
            marker_match = bool(INJECTION_MARKER_RE.search(head))
        except OSError:
            pass
        manifest_match = name_match and path.name.lower() in manifest_lower
        if marker_match or manifest_match:
            found.append({
                "path": str(path),
                "relative_to_resource": relative_text(path, resource_root),
                "reason": "guard-marker" if marker_match else "manifest-reference",
            })
    return found


def comment_config_line(line):
    newline = ""
    body = line
    if body.endswith("\r\n"):
        body, newline = body[:-2], "\r\n"
    elif body.endswith("\n") or body.endswith("\r"):
        body, newline = body[:-1], body[-1]
    return "# [xiaoha-cleaner] " + body + newline


def plan_config_edit(path, target, removed_names):
    try:
        text, encoding, original = read_text_file(path)
    except OSError:
        return None
    kept = []
    changed = []
    for number, line in enumerate(text.splitlines(True), 1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith(";") or stripped.startswith("--"):
            kept.append(line)
            continue
        matched_name = None
        start_match = START_COMMAND_RE.search(line)
        if start_match and start_match.group(1).lower() in removed_names:
            matched_name = start_match.group(1)
        if matched_name is None:
            ace_names = [value.lower() for value in ACE_RESOURCE_RE.findall(line)]
            if any(value in removed_names for value in ace_names):
                matched_name = next(value for value in ace_names if value in removed_names)
        if matched_name is None:
            kept.append(line)
            continue
        changed.append({
            "line": number,
            "resource": matched_name,
            "text": line.rstrip("\r\n")[:500],
        })
        kept.append(comment_config_line(line))
    if not changed:
        return None
    return {
        "kind": "config",
        "path": str(path),
        "relative_path": relative_text(path, target),
        "original_sha256": sha256_bytes(original),
        "changed_lines": changed,
        "_new_bytes": encode_text("".join(kept), encoding),
    }


def collect_sql_tables(owned_roots, target):
    occurrences = {}
    created = set()
    scanned_files = 0
    for root in owned_roots:
        for path in iter_files(root):
            if path.suffix.lower() not in {".lua", ".js", ".cjs", ".mjs", ".ts", ".sql"}:
                continue
            try:
                if path.stat().st_size > 8 * 1024 * 1024:
                    continue
                text, _, _ = read_text_file(path)
            except OSError:
                continue
            scanned_files += 1
            for table in SQL_TABLE_CONTEXT_RE.findall(text):
                name = table.lower()
                if name in {"table", "information_schema", "columns"}:
                    continue
                occurrences.setdefault(name, set()).add(relative_text(path, target))
            for table in SQL_CREATE_TABLE_RE.findall(text):
                created.add(table.lower())

    safe = set()
    review = set()
    for table in occurrences:
        if SAFE_TABLE_NAME_RE.match(table) or table in SAFE_EXACT_TABLES:
            safe.add(table)
        elif table in created:
            review.add(table)
    return {
        "safe_tables": sorted(safe),
        "review_tables": sorted(review - safe),
        "occurrences": {
            name: sorted(paths) for name, paths in sorted(occurrences.items())
            if name in safe or name in review
        },
        "scanned_files": scanned_files,
    }


def split_sql_statements(text):
    parts = []
    start = 0
    quote = None
    line_comment = False
    block_comment = False
    escaped = False
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        nxt = text[index + 1] if index + 1 < length else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\" and quote in ("'", '"'):
                escaped = True
            elif char == quote:
                if index + 1 < length and text[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            index += 1
            continue
        if char == "#":
            line_comment = True
            index += 1
            continue
        if char == "-" and nxt == "-":
            line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        if char == ";":
            parts.append(text[start:index + 1])
            start = index + 1
        index += 1
    if start < length:
        parts.append(text[start:])
    return parts


def sql_statement_tables(statement):
    return {name.lower() for name in SQL_TABLE_CONTEXT_RE.findall(statement)}


def plan_external_sql_edit(path, target, safe_tables):
    try:
        text, encoding, original = read_text_file(path)
    except OSError:
        return None
    kept = []
    removed = []
    for index, statement in enumerate(split_sql_statements(text), 1):
        tables = sql_statement_tables(statement)
        matched = sorted(tables.intersection(safe_tables))
        if matched and SQL_MUTATION_RE.search(statement):
            preview = " ".join(statement.strip().split())[:500]
            removed.append({"statement": index, "tables": matched, "preview": preview})
        else:
            kept.append(statement)
    if not removed:
        return None
    return {
        "kind": "sql",
        "path": str(path),
        "relative_path": relative_text(path, target),
        "original_sha256": sha256_bytes(original),
        "removed_statements": removed,
        "_new_bytes": encode_text("".join(kept), encoding),
    }


def external_reference_pattern(resource_names):
    names = [re.escape(name) for name in sorted(resource_names, key=len, reverse=True) if name]
    name_part = "|".join(names) if names else r"(?!)"
    return re.compile(
        r"(?:@hgadmin[/\\]|\[\[HGADMIN-|xiaoha\.cloud|xiaohahenshuai\s*:|"
        r"(?:exports|TriggerEvent|TriggerServerEvent|TriggerClientEvent|dependency)"
        r"[^\r\n]{0,160}(?:" + name_part + r"))",
        re.I,
    )


def find_external_references(target, owned_roots, injection_paths, resource_names, limit=500):
    pattern = external_reference_pattern(resource_names)
    injection_keys = {path_key(path) for path in injection_paths}
    references = []
    truncated = False
    for path in iter_files(target):
        if len(references) >= limit:
            truncated = True
            break
        if path.suffix.lower() not in CODE_REFERENCE_SUFFIXES:
            continue
        if is_owned_path(path, owned_roots) or path_key(path) in injection_keys:
            continue
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                continue
            text, _, _ = read_text_file(path)
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                references.append({
                    "path": str(path),
                    "relative_path": relative_text(path, target),
                    "line": number,
                    "preview": line.strip()[:500],
                })
                if len(references) >= limit:
                    truncated = True
                    break
    return references, truncated


def build_plan(target, include_review=False):
    target = Path(target).absolute()
    if not target.exists() or not target.is_dir():
        raise ValueError("Target is not an existing directory: {}".format(target))
    if path_key(target) == path_key(Path(target.anchor)):
        raise ValueError("Refusing to scan a drive/filesystem root: {}".format(target))

    resources = []
    for resource_root, manifest_path in find_resource_roots(target):
        resources.append(classify_resource(resource_root, manifest_path, target))

    owned_records = [item for item in resources if item["owned"]]
    review_records = [
        item for item in resources
        if not item["owned"] and item["review_reasons"]
    ]
    if include_review:
        for item in review_records:
            if item["review_reasons"] != ["hgadmin-injection-present-not-owner"]:
                item["owned"] = True
                item["reasons"].append("operator:include-review")
                owned_records.append(item)

    owned_roots = collapse_nested_paths([Path(item["path"]) for item in owned_records])
    owned_root_keys = {path_key(path) for path in owned_roots}
    owned_records = [item for item in owned_records if path_key(item["path"]) in owned_root_keys]

    for item in owned_records:
        item["metrics"] = measure_tree(item["path"])

    sql = collect_sql_tables(owned_roots, target)
    safe_tables = set(sql["safe_tables"])

    manifest_edits = []
    manual_manifest = []
    injection_files = []
    for item in resources:
        root = Path(item["path"])
        if is_owned_path(root, owned_roots):
            continue
        manifest_path = Path(item["manifest"])
        try:
            manifest_text, _, _ = read_text_file(manifest_path, max_bytes=2 * 1024 * 1024)
        except OSError:
            manifest_text = ""
        edit, manual = plan_manifest_edit(manifest_path, target)
        if edit:
            manifest_edits.append(edit)
        if manual:
            manual_manifest.append(manual)
        injection_files.extend(find_injection_files(root, manifest_text))

    unique_injections = {}
    for item in injection_files:
        if not is_owned_path(item["path"], owned_roots):
            unique_injections[path_key(item["path"])] = item
    injection_files = sorted(unique_injections.values(), key=lambda item: path_key(item["path"]))

    removed_names = {item["name"].lower() for item in owned_records}
    config_edits = []
    sql_edits = []
    for path in iter_files(target):
        if is_owned_path(path, owned_roots):
            continue
        suffix = path.suffix.lower()
        if suffix in {".cfg", ".conf"}:
            edit = plan_config_edit(path, target, removed_names)
            if edit:
                config_edits.append(edit)
        elif suffix == ".sql" and safe_tables:
            edit = plan_external_sql_edit(path, target, safe_tables)
            if edit:
                sql_edits.append(edit)

    injection_paths = [item["path"] for item in injection_files]
    references, references_truncated = find_external_references(
        target, owned_roots, injection_paths, removed_names
    )

    total_files = sum(item["metrics"]["files"] for item in owned_records)
    total_bytes = sum(item["metrics"]["bytes"] for item in owned_records)
    total_lua = sum(item["metrics"]["lua_files"] for item in owned_records)

    return {
        "tool": "fivem-xiaoha-cleaner",
        "version": VERSION,
        "created_at": now_iso(),
        "target": str(target),
        "include_review": bool(include_review),
        "resources": {
            "all_count": len(resources),
            "owned": owned_records,
            "review": review_records,
        },
        "injection_files": injection_files,
        "edits": {
            "manifests": manifest_edits,
            "configs": config_edits,
            "sql_files": sql_edits,
            "manual_manifests": manual_manifest,
        },
        "sql": sql,
        "external_references": references,
        "external_references_truncated": references_truncated,
        "summary": {
            "owned_resources": len(owned_records),
            "review_resources": len(review_records),
            "resource_files": total_files,
            "resource_lua_files": total_lua,
            "resource_bytes": total_bytes,
            "injection_files": len(injection_files),
            "manifest_edits": len(manifest_edits),
            "config_edits": len(config_edits),
            "external_sql_edits": len(sql_edits),
            "safe_sql_tables": len(sql["safe_tables"]),
            "review_sql_tables": len(sql["review_tables"]),
            "external_references": len(references),
        },
    }


def json_ready(value):
    if isinstance(value, dict):
        return {
            key: json_ready(item) for key, item in value.items()
            if not key.startswith("_")
        }
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def database_cleanup_sql(plan):
    safe = plan["sql"]["safe_tables"]
    review = plan["sql"]["review_tables"]
    lines = [
        "-- Generated by FiveM Xiaoha Cleaner {} at {}".format(VERSION, now_iso()),
        "-- Target: {}".format(plan["target"]),
        "-- Back up the database before executing this file.",
        "-- Only strongly owned tables are active DROP statements.",
        "",
        "SET @XIAOHA_OLD_FOREIGN_KEY_CHECKS = @@FOREIGN_KEY_CHECKS;",
        "SET FOREIGN_KEY_CHECKS = 0;",
        "",
    ]
    if safe:
        lines.append("-- Strongly owned Xiaoha/HGAdmin tables")
        for table in safe:
            lines.append("DROP TABLE IF EXISTS `{}`;".format(table.replace("`", "``")))
    else:
        lines.append("-- No strongly owned tables were detected.")
    lines.extend(["", "-- Shared/generic tables: review manually; never auto-executed."])
    if review:
        for table in review:
            lines.append("-- DROP TABLE IF EXISTS `{}`;".format(table.replace("`", "``")))
    else:
        lines.append("-- None detected.")
    lines.extend([
        "",
        "SET FOREIGN_KEY_CHECKS = @XIAOHA_OLD_FOREIGN_KEY_CHECKS;",
        "",
    ])
    return "\n".join(lines)


def markdown_report(plan, status="scan", operations=None, error=None):
    summary = plan["summary"]
    lines = [
        "# FiveM 小哈/HGAdmin 清理报告",
        "",
        "- 状态：`{}`".format(status),
        "- 目标：`{}`".format(plan["target"]),
        "- 生成时间：{}".format(plan["created_at"]),
        "- 工具版本：{}".format(plan["version"]),
        "",
        "## 汇总",
        "",
        "- 确认归属资源：{}".format(summary["owned_resources"]),
        "- 待人工复核资源：{}".format(summary["review_resources"]),
        "- 将隔离文件：{} 个（Lua {} 个）".format(
            summary["resource_files"], summary["resource_lua_files"]
        ),
        "- 将释放运行目录体积：{}".format(human_bytes(summary["resource_bytes"])),
        "- 独立注入守卫：{}".format(summary["injection_files"]),
        "- manifest / cfg / 外部 SQL 修改：{} / {} / {}".format(
            summary["manifest_edits"], summary["config_edits"],
            summary["external_sql_edits"]
        ),
        "- 可安全清理数据库表：{}".format(summary["safe_sql_tables"]),
        "- 外部代码引用：{}{}".format(
            summary["external_references"],
            "（结果已截断）" if plan["external_references_truncated"] else "",
        ),
        "",
        "## 确认归属资源",
        "",
    ]
    if plan["resources"]["owned"]:
        for item in plan["resources"]["owned"]:
            lines.append("- `{}` — {}，{} 个文件".format(
                item["relative_path"], ", ".join(item["reasons"]),
                item["metrics"]["files"],
            ))
    else:
        lines.append("- 无")

    lines.extend(["", "## 数据库", ""])
    if plan["sql"]["safe_tables"]:
        lines.append("自动清理范围：`{}`".format(
            "`, `".join(plan["sql"]["safe_tables"])
        ))
    else:
        lines.append("未发现强归属数据库表。")
    if plan["sql"]["review_tables"]:
        lines.extend([
            "",
            "仅人工复核（SQL 中保持注释）：`{}`".format(
                "`, `".join(plan["sql"]["review_tables"])
            ),
        ])

    lines.extend(["", "## 外部引用", ""])
    if plan["external_references"]:
        for item in plan["external_references"][:100]:
            lines.append("- `{}`:{} — `{}`".format(
                item["relative_path"], item["line"], item["preview"].replace("`", "'")
            ))
        if len(plan["external_references"]) > 100:
            lines.append("- 其余引用请查看 JSON 报告。")
    else:
        lines.append("- 未发现位于保留资源中的外部代码引用。")

    if operations is not None:
        lines.extend(["", "## 已执行文件操作", "", "- {} 项".format(len(operations))])
    if error:
        lines.extend(["", "## 错误", "", "```text", str(error), "```"])
    lines.append("")
    return "\n".join(lines)


def write_reports(plan, output_dir, status="scan", operations=None, error=None):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = json_ready(plan)
    payload["status"] = status
    if operations is not None:
        payload["operations"] = json_ready(operations)
    if error:
        payload["error"] = str(error)
    json_name = "run-report.json" if status != "scan" else "scan-report.json"
    md_name = "run-report.md" if status != "scan" else "scan-report.md"
    json_path = output_dir / json_name
    md_path = output_dir / md_name
    json_path.write_bytes((json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    md_path.write_bytes(markdown_report(plan, status, operations, error).encode("utf-8"))
    sql_path = output_dir / "cleanup_database.sql"
    sql_path.write_bytes(database_cleanup_sql(plan).encode("utf-8"))
    return json_path, md_path, sql_path


def unique_run_dir(base):
    base = Path(base)
    if not base.exists():
        return base
    counter = 2
    while True:
        candidate = Path(str(base) + "_{}".format(counter))
        if not candidate.exists():
            return candidate
        counter += 1


def verify_edit_preconditions(plan):
    errors = []
    for group in ("manifests", "configs", "sql_files"):
        for edit in plan["edits"][group]:
            path = Path(edit["path"])
            try:
                current = path.read_bytes()
            except OSError as exc:
                errors.append("{}: {}".format(path, exc))
                continue
            if sha256_bytes(current) != edit["original_sha256"]:
                errors.append("File changed after scan: {}".format(path))
    for item in plan["resources"]["owned"]:
        if not Path(item["path"]).exists():
            errors.append("Resource disappeared after scan: {}".format(item["path"]))
    for item in plan["injection_files"]:
        if not Path(item["path"]).exists():
            errors.append("Injection file disappeared after scan: {}".format(item["path"]))
    if errors:
        raise RuntimeError("Preflight failed:\n- " + "\n- ".join(errors))


def backup_and_edit(edit, target, run_dir, operations):
    path = Path(edit["path"])
    if not is_within(path, target):
        raise RuntimeError("Refusing to edit outside target: {}".format(path))
    relative = Path(relative_text(path, target))
    backup = run_dir / "backups" / relative
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(path), str(backup))
    path.write_bytes(edit["_new_bytes"])
    operations.append({
        "type": "edit",
        "kind": edit["kind"],
        "path": str(path),
        "backup": str(backup),
    })


def move_to_quarantine(source, target, destination_root, kind, operations):
    source = Path(source)
    if not is_within(source, target):
        raise RuntimeError("Refusing to move outside target: {}".format(source))
    relative = Path(relative_text(source, target))
    destination = destination_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RuntimeError("Quarantine destination already exists: {}".format(destination))
    shutil.move(str(source), str(destination))
    operations.append({
        "type": "move",
        "kind": kind,
        "source": str(source),
        "destination": str(destination),
    })


def rollback_operations(operations):
    errors = []
    for operation in reversed(operations):
        try:
            if operation["type"] == "edit":
                backup = Path(operation["backup"])
                path = Path(operation["path"])
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(backup), str(path))
            elif operation["type"] == "move":
                source = Path(operation["source"])
                destination = Path(operation["destination"])
                if source.exists():
                    raise RuntimeError("Restore target already exists: {}".format(source))
                source.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(destination), str(source))
        except Exception as exc:  # rollback must attempt every operation
            errors.append("{}: {}".format(operation, exc))
    return errors


def clean_target(plan, quarantine_root=None):
    target = Path(plan["target"]).absolute()
    if quarantine_root is None:
        quarantine_root = target.parent / "_xiaoha_quarantine"
    else:
        quarantine_root = Path(quarantine_root).absolute()
    if is_within(quarantine_root, target):
        raise ValueError("Quarantine directory must be outside the target directory")

    run_dir = unique_run_dir(
        quarantine_root / "{}_{}".format(target.name or "server", now_stamp())
    )
    run_dir.mkdir(parents=True, exist_ok=False)
    write_reports(plan, run_dir, status="preflight", operations=[])
    verify_edit_preconditions(plan)

    operations = []
    try:
        for item in plan["resources"]["owned"]:
            move_to_quarantine(
                item["path"], target, run_dir / "resources", "resource", operations
            )
        for item in plan["injection_files"]:
            path = Path(item["path"])
            if path.exists():
                move_to_quarantine(
                    path, target, run_dir / "injections", "injection", operations
                )
        for group in ("manifests", "configs", "sql_files"):
            for edit in plan["edits"][group]:
                path = Path(edit["path"])
                if path.exists():
                    backup_and_edit(edit, target, run_dir, operations)
        report_paths = write_reports(plan, run_dir, status="cleaned", operations=operations)
        return run_dir, operations, report_paths
    except Exception as exc:
        rollback_errors = rollback_operations(operations)
        detail = "{}".format(exc)
        if rollback_errors:
            detail += "\nRollback errors:\n- " + "\n- ".join(rollback_errors)
        write_reports(plan, run_dir, status="failed-rolled-back", operations=operations, error=detail)
        raise RuntimeError(detail)


def validate_restore_operation(operation, target, run_dir):
    if operation["type"] == "edit":
        if not is_within(operation["path"], target):
            raise RuntimeError("Invalid edit path in report: {}".format(operation["path"]))
        if not is_within(operation["backup"], run_dir):
            raise RuntimeError("Invalid backup path in report: {}".format(operation["backup"]))
    elif operation["type"] == "move":
        if not is_within(operation["source"], target):
            raise RuntimeError("Invalid source path in report: {}".format(operation["source"]))
        if not is_within(operation["destination"], run_dir):
            raise RuntimeError("Invalid quarantine path in report: {}".format(operation["destination"]))
    else:
        raise RuntimeError("Unknown operation type: {}".format(operation.get("type")))


def restore_report(report_path):
    report_path = Path(report_path).absolute()
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    target = Path(payload["target"]).absolute()
    run_dir = report_path.parent.absolute()
    operations = payload.get("operations") or []
    if not operations:
        raise RuntimeError("Report contains no completed operations: {}".format(report_path))
    for operation in operations:
        validate_restore_operation(operation, target, run_dir)
    errors = rollback_operations(operations)
    result = {
        "tool": "fivem-xiaoha-cleaner",
        "version": VERSION,
        "restored_at": now_iso(),
        "source_report": str(report_path),
        "target": str(target),
        "operations": len(operations),
        "errors": errors,
        "database_note": "Database DROP operations are not reversible by this restore command.",
    }
    restore_path = run_dir / "restore-report.json"
    restore_path.write_bytes((json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    if errors:
        raise RuntimeError("Restore completed with errors:\n- " + "\n- ".join(errors))
    return restore_path, result


def parse_mysql_uri(uri):
    parsed = urlparse(uri)
    if parsed.scheme.lower() not in {"mysql", "mariadb"}:
        raise ValueError("MySQL URI must start with mysql:// or mariadb://")
    if not parsed.hostname or not parsed.path.strip("/"):
        raise ValueError("MySQL URI must include host and database name")
    return {
        "host": parsed.hostname,
        "port": parsed.port or 3306,
        "user": unquote(parsed.username or "root"),
        "password": unquote(parsed.password or ""),
        "database": unquote(parsed.path.lstrip("/")),
    }


def apply_sql_file(sql_path, mysql_uri, mysql_command="mysql"):
    sql_path = Path(sql_path).absolute()
    connection = parse_mysql_uri(mysql_uri)
    executable = shutil.which(mysql_command)
    if executable is None and Path(mysql_command).is_file():
        executable = str(Path(mysql_command).absolute())
    if executable is None:
        raise RuntimeError("MySQL client was not found: {}".format(mysql_command))
    command = [
        executable,
        "--host", connection["host"],
        "--port", str(connection["port"]),
        "--user", connection["user"],
        "--default-character-set=utf8mb4",
        connection["database"],
    ]
    environment = os.environ.copy()
    if connection["password"]:
        environment["MYSQL_PWD"] = connection["password"]
    with sql_path.open("rb") as sql_handle:
        completed = subprocess.run(
            command,
            stdin=sql_handle,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    if completed.returncode != 0:
        stderr = decode_bytes(completed.stderr)[0].strip()
        raise RuntimeError("MySQL cleanup failed (exit {}): {}".format(
            completed.returncode, stderr
        ))
    return decode_bytes(completed.stdout)[0]


def default_scan_dir(target):
    script_dir = Path(__file__).absolute().parent
    return script_dir / "reports" / "scan_{}_{}".format(Path(target).name, now_stamp())


def print_summary(plan):
    summary = plan["summary"]
    print("Target: {}".format(plan["target"]))
    print("Owned resources: {}".format(summary["owned_resources"]))
    print("Review resources: {}".format(summary["review_resources"]))
    print("Files / Lua: {} / {}".format(
        summary["resource_files"], summary["resource_lua_files"]
    ))
    print("Quarantine size: {}".format(human_bytes(summary["resource_bytes"])))
    print("Guard injections: {}".format(summary["injection_files"]))
    print("Safe SQL tables: {}".format(summary["safe_sql_tables"]))
    print("External references: {}".format(summary["external_references"]))


def build_parser():
    parser = argparse.ArgumentParser(
        description="Scan and remove Xiaoha/HGAdmin FiveM resources, guard injections and SQL."
    )
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Read-only scan and report (default safe mode)")
    scan.add_argument("target", help="FiveM server-data/resources directory")
    scan.add_argument("--output", help="Report output directory")
    scan.add_argument(
        "--include-review", action="store_true",
        help="Treat multi-signature review resources as owned (not recommended for first run)",
    )

    clean = subparsers.add_parser("clean", help="Quarantine detected resources and edit references")
    clean.add_argument("target", help="FiveM server-data/resources directory")
    clean.add_argument("--yes", action="store_true", help="Required confirmation to modify files")
    clean.add_argument("--quarantine-root", help="Directory outside target used for backups/quarantine")
    clean.add_argument("--include-review", action="store_true")
    clean.add_argument("--apply-sql", action="store_true", help="Apply generated DROP TABLE SQL")
    clean.add_argument("--yes-drop-tables", action="store_true", help="Required SQL DROP confirmation")
    clean.add_argument("--mysql-uri", help="mysql://user:password@host:3306/database")
    clean.add_argument("--mysql-command", default="mysql", help="mysql/mariadb CLI path or command")

    restore = subparsers.add_parser("restore", help="Restore filesystem changes from run-report.json")
    restore.add_argument("report", help="Path to a cleaned run-report.json")
    restore.add_argument("--yes", action="store_true", help="Required confirmation")

    sql = subparsers.add_parser("apply-sql", help="Apply a generated cleanup_database.sql")
    sql.add_argument("sql_file")
    sql.add_argument("--mysql-uri", required=True)
    sql.add_argument("--mysql-command", default="mysql")
    sql.add_argument("--yes-drop-tables", action="store_true", help="Required confirmation")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    try:
        if args.command == "scan":
            plan = build_plan(args.target, include_review=args.include_review)
            output = Path(args.output).absolute() if args.output else default_scan_dir(args.target)
            reports = write_reports(plan, output, status="scan")
            print_summary(plan)
            print("JSON report: {}".format(reports[0]))
            print("Markdown report: {}".format(reports[1]))
            print("Database SQL: {}".format(reports[2]))
            return 0

        if args.command == "clean":
            if not args.yes:
                print("Refusing to modify files without --yes. Running a read-only scan instead.")
                plan = build_plan(args.target, include_review=args.include_review)
                reports = write_reports(plan, default_scan_dir(args.target), status="scan")
                print_summary(plan)
                print("Scan report: {}".format(reports[0]))
                return 2
            if args.apply_sql:
                if not args.yes_drop_tables or not args.mysql_uri:
                    raise ValueError(
                        "--apply-sql requires --yes-drop-tables and --mysql-uri"
                    )
                if shutil.which(args.mysql_command) is None and not Path(args.mysql_command).is_file():
                    raise RuntimeError("MySQL client was not found: {}".format(args.mysql_command))
                parse_mysql_uri(args.mysql_uri)
            plan = build_plan(args.target, include_review=args.include_review)
            print_summary(plan)
            run_dir, operations, reports = clean_target(plan, args.quarantine_root)
            print("Cleaned with {} reversible filesystem operations.".format(len(operations)))
            print("Quarantine/report: {}".format(run_dir))
            if args.apply_sql:
                apply_sql_file(reports[2], args.mysql_uri, args.mysql_command)
                marker = run_dir / "database-cleanup-applied.json"
                marker.write_bytes((json.dumps({
                    "applied_at": now_iso(),
                    "sql_file": str(reports[2]),
                    "database": parse_mysql_uri(args.mysql_uri)["database"],
                    "tables": plan["sql"]["safe_tables"],
                    "warning": "Database changes are not restored by the filesystem restore command.",
                }, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
                print("Database cleanup applied. Marker: {}".format(marker))
            return 0

        if args.command == "restore":
            if not args.yes:
                raise ValueError("restore requires --yes")
            restore_path, result = restore_report(args.report)
            print("Restored {} filesystem operations.".format(result["operations"]))
            print("Restore report: {}".format(restore_path))
            print("Note: database DROP operations require a database backup to restore.")
            return 0

        if args.command == "apply-sql":
            if not args.yes_drop_tables:
                raise ValueError("apply-sql requires --yes-drop-tables")
            apply_sql_file(args.sql_file, args.mysql_uri, args.mysql_command)
            print("Database cleanup applied from {}".format(Path(args.sql_file).absolute()))
            return 0
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        if os.environ.get("XIAOHA_CLEANER_DEBUG") == "1":
            traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
