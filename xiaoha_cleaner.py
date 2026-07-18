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


VERSION = "1.0.1"

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


def real_path_key(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(str(path))))


def is_real_within(child, parent):
    try:
        return (
            os.path.commonpath([real_path_key(child), real_path_key(parent)])
            == real_path_key(parent)
        )
    except (ValueError, OSError):
        return False


def is_root_path(path):
    absolute = Path(path).absolute()
    return bool(absolute.anchor) and path_key(absolute) == path_key(absolute.anchor)


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


def path_snapshot_sha256(path):
    path = Path(path)
    digest = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    if not path.is_dir():
        raise OSError("Path does not exist for hashing: {}".format(path))

    digest.update(b"directory\0")
    for current_text, dirs, files in os.walk(str(path), topdown=True, followlinks=False):
        dirs.sort(key=str.lower)
        files.sort(key=str.lower)
        current = Path(current_text)
        for name in dirs:
            relative = str((current / name).relative_to(path)).replace("\\", "/")
            digest.update(("D\0" + relative + "\0").encode("utf-8"))
        for name in files:
            file_path = current / name
            relative = str(file_path.relative_to(path)).replace("\\", "/")
            file_digest = hashlib.sha256()
            file_size = file_path.stat().st_size
            with file_path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    file_digest.update(chunk)
            digest.update((
                "F\0{}\0{}\0".format(relative, file_size).encode("utf-8")
            ))
            digest.update(file_digest.digest())
    return digest.hexdigest()


def decode_bytes(data):
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1"), "latin-1"


def mysql_secret_values(mysql_uri):
    values = []
    if mysql_uri:
        values.append(str(mysql_uri))
        try:
            password = unquote(urlparse(str(mysql_uri)).password or "")
        except (TypeError, ValueError):
            password = ""
        if password:
            values.append(password)
    return values


def redact_sensitive_text(value, secrets=None):
    text = str(value or "")
    secret_values = sorted(
        {str(item) for item in (secrets or []) if str(item)},
        key=len, reverse=True,
    )
    for secret in secret_values:
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(
        r"(?i)\b(mysql|mariadb)://[^\s/@:]+:[^@\s/]*@",
        r"\1://[REDACTED]@", text,
    )
    text = re.sub(
        r"(?i)\b((?:mysql_)?pwd|password)\s*=\s*[^;\s]+",
        r"\1=[REDACTED]", text,
    )
    return text


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


def markdown_value(value):
    return str(value or "").replace("`", "'")


def markdown_operation(operation, index):
    operation_type = operation.get("type", "unknown")
    kind = operation.get("kind", "unknown")
    if operation_type == "move":
        return "{}. 隔离 `{}` → `{}`（{}）".format(
            index,
            markdown_value(operation.get("source")),
            markdown_value(operation.get("destination")),
            kind,
        )
    if operation_type == "edit":
        return "{}. 修改 `{}`（{}；备份：`{}`）".format(
            index,
            markdown_value(operation.get("path")),
            kind,
            markdown_value(operation.get("backup")),
        )
    return "{}. {}：`{}`".format(index, operation_type, markdown_value(operation))


def default_database_execution(plan, sql_path, status):
    generated_only = status in {"scan", "cleaned"}
    return {
        "requested": False,
        "status": "generated-only" if generated_only else "not-started",
        "applied": False,
        "partial_changes_possible": False,
        "sql_file": str(Path(sql_path).absolute()),
        "tables": list(plan["sql"].get("safe_tables", [])),
        "added_columns": list(plan["sql"].get("added_columns", [])),
    }


def report_notices(status, operations, database_execution):
    notices = []
    if status == "scan":
        notices.append("本次仅扫描并生成报告，没有修改服务器文件或数据库。")
    elif status == "failed-preflight":
        notices.append("清理在预检阶段失败，文件修改尚未开始；请处理错误后重新扫描。")
    elif status == "failed-rolled-back":
        notices.append("清理过程中发生错误，工具已尝试回滚已记录的文件操作；请结合错误和隔离目录复核实际状态。")
    elif status == "failed-rollback-incomplete":
        notices.append("清理失败且自动回滚不完整；部分文件可能仍处于修改或隔离状态，必须按逐项操作和错误人工处理。")
    elif operations is not None:
        notices.append("文件修改和隔离路径已逐项记录；需要恢复时请使用本次 run-report.json。")

    database_status = (database_execution or {}).get("status")
    if database_status == "generated-only":
        notices.append("cleanup_database.sql 仅已生成、未执行；执行前必须停止服务器并备份数据库。")
    elif database_status == "pending":
        notices.append("数据库 SQL 已开始交给客户端执行，但尚无最终结果；请不要把 pending 当作成功。")
    elif database_status == "failed":
        notices.append("数据库客户端未成功完成，不能确认 SQL 全部应用；数据库可能已部分变更，请立即核对并准备从备份恢复。")
    elif database_status == "applied":
        notices.append("数据库 SQL 已成功执行；文件恢复命令不会恢复数据库，只能使用数据库备份。")
    elif database_status == "not-started" and status != "scan":
        notices.append("本次未开始执行数据库 SQL。")
    if (database_execution or {}).get("marker_error"):
        notices.append(
            "数据库已确认执行成功，但本地成功标记写入失败；请以本次 run-report.json 为准。"
        )
    return notices


def report_phase(status):
    if status.startswith("scan"):
        return "scan"
    if "preflight" in status:
        return "preflight"
    if "rollback" in status or status.startswith("restore"):
        return "rollback"
    if "database" in status:
        return "database"
    return "filesystem"


def report_terminal(status):
    return status not in {
        "preflight",
        "filesystem-cleaned-database-not-started",
        "filesystem-cleaned-database-pending",
    }


def markdown_report(
    plan, status="scan", operations=None, error=None,
    database_execution=None, notices=None,
    terminal=True, finished_at=None,
):
    summary = plan["summary"]
    lines = [
        "# FiveM 小哈/HGAdmin 清理报告",
        "",
        "- 状态：`{}`".format(status),
        "- 目标：`{}`".format(plan["target"]),
        "- 生成时间：{}".format(plan["created_at"]),
        "- 工具版本：{}".format(plan["version"]),
        "- 报告终态：{}".format("是" if terminal else "否"),
        "- 完成时间：{}".format(finished_at or "尚未完成"),
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
        lines.extend(["", "## 已执行文件操作", ""])
        if operations:
            for index, operation in enumerate(operations, 1):
                lines.append("- " + markdown_operation(operation, index))
        else:
            lines.append("- 无")

    if database_execution is not None:
        lines.extend([
            "",
            "## 数据库执行结果",
            "",
            "- 请求执行：{}".format("是" if database_execution.get("requested") else "否"),
            "- 状态：`{}`".format(database_execution.get("status", "unknown")),
            "- 已确认应用：{}".format("是" if database_execution.get("applied") else "否"),
        ])
        if database_execution.get("sql_file"):
            lines.append("- SQL 文件：`{}`".format(
                markdown_value(database_execution.get("sql_file"))
            ))
        if database_execution.get("database"):
            lines.append("- 数据库：`{}`".format(markdown_value(database_execution["database"])))
        if database_execution.get("marker"):
            lines.append("- 成功标记：`{}`".format(markdown_value(database_execution["marker"])))
        if database_execution.get("marker_status"):
            lines.append("- 成功标记状态：`{}`".format(
                markdown_value(database_execution["marker_status"])
            ))
        if database_execution.get("marker_error"):
            lines.append("- 成功标记错误：`{}`".format(
                markdown_value(database_execution["marker_error"])
            ))
        if database_execution.get("error"):
            lines.append("- 执行错误：`{}`".format(markdown_value(database_execution["error"])))

    if notices:
        lines.extend(["", "## 注意事项", ""])
        for notice in notices:
            lines.append("- {}".format(notice))
    if error:
        lines.extend(["", "## 错误", ""])
        error_lines = str(error).splitlines() or [""]
        for error_line in error_lines:
            lines.append("    " + error_line)
    lines.append("")
    return "\n".join(lines)


def write_reports(
    plan, output_dir, status="scan", operations=None, error=None,
    database_execution=None, notices=None, rewrite_sql=True,
    operation=None, phase=None, filesystem_partial_changes_possible=False, include_sql=True,
    terminal=None, rollback=None, secrets=None,
):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    sql_path = output_dir / "cleanup_database.sql"
    if include_sql and (rewrite_sql or not sql_path.is_file()):
        sql_path.write_bytes(database_cleanup_sql(plan).encode("utf-8"))

    if database_execution is None:
        database_execution = default_database_execution(plan, sql_path, status)
    else:
        database_execution = dict(database_execution)
        database_execution.setdefault("sql_file", str(sql_path.absolute()))
        database_execution.setdefault("tables", list(plan["sql"].get("safe_tables", [])))
        database_execution.setdefault("added_columns", list(plan["sql"].get("added_columns", [])))
    if database_execution.get("error"):
        database_execution["error"] = redact_sensitive_text(
            database_execution["error"], secrets
        )
    if database_execution.get("marker_error"):
        database_execution["marker_error"] = redact_sensitive_text(
            database_execution["marker_error"], secrets
        )
    try:
        if include_sql:
            database_execution.setdefault("sql_sha256", sha256_bytes(sql_path.read_bytes()))
    except OSError:
        pass
    database_partial_changes_possible = bool(
        database_execution.get("partial_changes_possible", False)
    )
    database_execution["partial_changes_possible"] = database_partial_changes_possible
    if notices is None:
        notices = report_notices(status, operations, database_execution)
    notices = [redact_sensitive_text(item, secrets) for item in notices]
    safe_error = redact_sensitive_text(error, secrets)

    payload = json_ready(plan)
    operation = operation or ("scan" if status.startswith("scan") else "clean")
    payload["status"] = status
    payload["operation"] = operation
    payload["phase"] = phase or report_phase(status)
    updated_at = now_iso()
    terminal = report_terminal(status) if terminal is None else bool(terminal)
    payload["report_updated_at"] = updated_at
    payload["started_at"] = plan.get("created_at") or updated_at
    payload["terminal"] = terminal
    payload["finished_at"] = updated_at if terminal else None
    payload["database_execution"] = json_ready(database_execution)
    payload["notices"] = list(notices)
    payload["filesystem_partial_changes_possible"] = bool(
        filesystem_partial_changes_possible
    )
    payload["database_partial_changes_possible"] = database_partial_changes_possible
    payload["partial_changes_possible"] = bool(
        filesystem_partial_changes_possible or database_partial_changes_possible
    )
    payload["operations"] = json_ready(operations or [])
    if rollback is not None:
        payload["rollback"] = json_ready(rollback)
    if safe_error:
        payload["error"] = safe_error
    json_name = "scan-report.json" if operation == "scan" else "run-report.json"
    md_name = "scan-report.md" if operation == "scan" else "run-report.md"
    json_path = output_dir / json_name
    md_path = output_dir / md_name
    json_path.write_bytes((json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    md_path.write_bytes(markdown_report(
        plan, status, operations, safe_error, database_execution, notices,
        terminal, payload["finished_at"],
    ).encode("utf-8"))
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
    before_sha256 = path_snapshot_sha256(path)
    shutil.copy2(str(path), str(backup))
    operation = {
        "type": "edit",
        "kind": edit["kind"],
        "path": str(path),
        "backup": str(backup),
        "before_sha256": before_sha256,
        "backup_sha256": path_snapshot_sha256(backup),
        "completed": False,
    }
    operations.append(operation)
    path.write_bytes(edit["_new_bytes"])
    operation["after_sha256"] = path_snapshot_sha256(path)
    operation["completed"] = True


def move_to_quarantine(source, target, destination_root, kind, operations):
    source = Path(source)
    if not is_within(source, target):
        raise RuntimeError("Refusing to move outside target: {}".format(source))
    relative = Path(relative_text(source, target))
    destination = destination_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    content_sha256 = path_snapshot_sha256(source)
    if destination.exists():
        raise RuntimeError("Quarantine destination already exists: {}".format(destination))
    operation = {
        "type": "move",
        "kind": kind,
        "source": str(source),
        "destination": str(destination),
        "content_sha256": content_sha256,
        "completed": False,
    }
    operations.append(operation)
    shutil.move(str(source), str(destination))
    operation["completed"] = True


class RestoreConflictError(RuntimeError):
    pass


class ExecutionReportError(RuntimeError):
    def __init__(self, message, report_path=None, report_dir=None):
        RuntimeError.__init__(self, message)
        self.report_path = str(report_path or "")
        self.report_dir = str(report_dir or "")


def rollback_operations(operations, include_results=False):
    errors = []
    results = []
    for operation in reversed(operations):
        result = {"operation": json_ready(operation), "status": "restored"}
        try:
            if operation["type"] == "edit":
                backup = Path(operation["backup"])
                path = Path(operation["path"])
                expected_backup = operation.get("backup_sha256")
                if expected_backup and (
                    not backup.is_file() or path_snapshot_sha256(backup) != expected_backup
                ):
                    raise RestoreConflictError(
                        "Backup changed after clean: {}".format(backup)
                    )
                expected_after = operation.get("after_sha256")
                if expected_after and (
                    not path.is_file() or path_snapshot_sha256(path) != expected_after
                ):
                    raise RestoreConflictError(
                        "Edited file changed after clean: {}".format(path)
                    )
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(backup), str(path))
            elif operation["type"] == "move":
                source = Path(operation["source"])
                destination = Path(operation["destination"])
                if (
                    operation.get("completed") is False
                    and source.exists()
                    and not destination.exists()
                ):
                    result["status"] = "not-applied"
                    results.append(result)
                    continue
                if source.exists():
                    raise RestoreConflictError(
                        "Restore target already exists: {}".format(source)
                    )
                if not destination.exists():
                    raise RuntimeError(
                        "Quarantined content is missing: {}".format(destination)
                    )
                expected_content = operation.get("content_sha256")
                if expected_content and (
                    not destination.exists()
                    or path_snapshot_sha256(destination) != expected_content
                ):
                    raise RestoreConflictError(
                        "Quarantined content changed after clean: {}".format(destination)
                    )
                source.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(destination), str(source))
            else:
                raise RuntimeError("Unknown operation type: {}".format(operation.get("type")))
        except Exception as exc:  # rollback must attempt every operation
            message = "{}: {}".format(operation, exc)
            errors.append(message)
            result["status"] = (
                "conflict" if isinstance(exc, RestoreConflictError) else "failed"
            )
            result["error"] = str(exc)
        results.append(result)
    if include_results:
        return errors, results
    return errors


def clean_target(plan, quarantine_root=None, database_execution=None):
    target = Path(plan["target"]).absolute()
    database_execution = dict(database_execution or {}) or None
    database_requested = bool(
        database_execution and database_execution.get("requested")
    )
    if quarantine_root is None:
        quarantine_root = target.parent / "_xiaoha_quarantine"
    else:
        quarantine_root = Path(quarantine_root).absolute()
    if is_within(quarantine_root, target) or is_real_within(quarantine_root, target):
        raise ValueError("Quarantine directory must be outside the target directory")

    run_dir = unique_run_dir(
        quarantine_root / "{}_{}".format(target.name or "server", now_stamp())
    )
    run_dir.mkdir(parents=True, exist_ok=False)
    operations = []
    write_reports(
        plan, run_dir, status="preflight", operations=[],
        database_execution=database_execution,
    )
    try:
        verify_edit_preconditions(plan)
    except Exception as exc:
        detail = "{}".format(exc)
        report_paths = write_reports(
            plan, run_dir, status="failed-preflight", operations=[],
            error=detail, rewrite_sql=False,
            database_execution=database_execution,
            filesystem_partial_changes_possible=False,
        )
        raise ExecutionReportError(
            detail, report_path=report_paths[0], report_dir=run_dir
        )

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
        success_status = (
            "filesystem-cleaned-database-not-started"
            if database_requested else "cleaned"
        )
        report_paths = write_reports(
            plan, run_dir, status=success_status, operations=operations,
            rewrite_sql=False, filesystem_partial_changes_possible=False,
            database_execution=database_execution,
        )
        return run_dir, operations, report_paths
    except Exception as exc:
        rollback_errors, rollback_results = rollback_operations(
            operations, include_results=True
        )
        detail = "{}".format(exc)
        if rollback_errors:
            detail += "\nRollback errors:\n- " + "\n- ".join(rollback_errors)
        failure_status = (
            "failed-rollback-incomplete" if rollback_errors else "failed-rolled-back"
        )
        rollback = {
            "attempted": True,
            "operation_results": rollback_results,
            "successful_operations": len([
                item for item in rollback_results
                if item.get("status") in {"restored", "not-applied"}
            ]),
            "failed_operations": len([
                item for item in rollback_results
                if item.get("status") == "failed"
            ]),
            "conflict_operations": len([
                item for item in rollback_results
                if item.get("status") == "conflict"
            ]),
            "pending_restore_operations": [
                item.get("operation") for item in rollback_results
                if item.get("status") in {"failed", "conflict"}
            ],
            "errors": rollback_errors,
        }
        report_paths = write_reports(
            plan, run_dir, status=failure_status, operations=operations,
            error=detail, rewrite_sql=False,
            database_execution=database_execution, rollback=rollback,
            filesystem_partial_changes_possible=bool(rollback_errors),
        )
        raise ExecutionReportError(
            detail, report_path=report_paths[0], report_dir=run_dir
        )


def validate_restore_operation(operation, target, run_dir):
    if not isinstance(operation, dict):
        raise RuntimeError("Invalid operation entry in report")
    if operation["type"] == "edit":
        path = Path(operation["path"])
        backup = Path(operation["backup"])
        if not path.is_absolute() or not backup.is_absolute():
            raise RuntimeError("Restore paths must be absolute")
        if not is_within(path, target) or not is_real_within(path, target):
            raise RuntimeError("Invalid edit path in report: {}".format(operation["path"]))
        if not is_within(backup, run_dir) or not is_real_within(backup, run_dir):
            raise RuntimeError("Invalid backup path in report: {}".format(operation["backup"]))
    elif operation["type"] == "move":
        source = Path(operation["source"])
        destination = Path(operation["destination"])
        if not source.is_absolute() or not destination.is_absolute():
            raise RuntimeError("Restore paths must be absolute")
        source_boundary = source if source.exists() else source.parent
        if (
            not is_within(source, target)
            or not is_real_within(source_boundary, target)
        ):
            raise RuntimeError("Invalid source path in report: {}".format(operation["source"]))
        if (
            not is_within(destination, run_dir)
            or not is_real_within(destination, run_dir)
        ):
            raise RuntimeError("Invalid quarantine path in report: {}".format(operation["destination"]))
    else:
        raise RuntimeError("Unknown operation type: {}".format(operation.get("type")))


def restore_markdown_report(result):
    lines = [
        "# FiveM 小哈/HGAdmin 文件恢复报告",
        "",
        "- 状态：`{}`".format(result.get("status", "unknown")),
        "- 源报告：`{}`".format(markdown_value(result.get("source_report"))),
        "- 目标：`{}`".format(markdown_value(result.get("target"))),
        "- 完成时间：{}".format(result.get("restored_at", "")),
        "",
        "## 恢复操作",
        "",
    ]
    operation_results = result.get("operation_results") or []
    if operation_results:
        for index, item in enumerate(operation_results, 1):
            operation = item.get("operation") or {}
            lines.append("- {} — `{}`".format(
                markdown_operation(operation, index), item.get("status", "unknown")
            ))
            if item.get("error"):
                lines.append("  - 错误：{}".format(item["error"]))
    else:
        lines.append("- 无")

    if result.get("errors"):
        lines.extend(["", "## 错误", ""])
        for error in result["errors"]:
            lines.append("- {}".format(error))
    lines.extend(["", "## 注意事项", ""])
    for notice in result.get("notices") or []:
        lines.append("- {}".format(notice))
    lines.append("")
    return "\n".join(lines)


def write_restore_reports(run_dir, result):
    run_dir = Path(run_dir)
    restore_path = run_dir / "restore-report.json"
    markdown_path = run_dir / "restore-report.md"
    result["reports"] = {
        "json": str(restore_path.absolute()),
        "markdown": str(markdown_path.absolute()),
    }
    restore_path.write_bytes((json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    markdown_path.write_bytes(restore_markdown_report(result).encode("utf-8"))
    return restore_path, markdown_path


def restore_report(report_path):
    report_path = Path(report_path).absolute()
    run_dir = report_path.parent.absolute()
    target = ""
    operations = []
    try:
        if report_path.name.lower() != "run-report.json":
            raise RuntimeError("Restore requires a run-report.json file")
        if is_root_path(run_dir):
            raise RuntimeError("Restore report directory cannot be a filesystem root")
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        if payload.get("tool") != "fivem-xiaoha-cleaner":
            raise RuntimeError("Report was not created by fivem-xiaoha-cleaner")
        if not payload.get("version"):
            raise RuntimeError("Report is missing its tool version")
        if payload.get("operation") not in (None, "clean"):
            raise RuntimeError("Only clean execution reports can be restored")
        allowed_statuses = {
            "cleaned",
            "filesystem-cleaned-database-not-started",
            "filesystem-cleaned-database-pending",
            "filesystem-cleaned-database-failed",
            "cleaned-database-applied",
            "failed-rollback-incomplete",
        }
        if payload.get("status") not in allowed_statuses:
            raise RuntimeError(
                "Report status is not restorable: {}".format(payload.get("status"))
            )
        raw_target = Path(payload["target"])
        if not raw_target.is_absolute():
            raise RuntimeError("Report target must be an absolute path")
        target = raw_target.absolute()
        if is_root_path(target) or not target.is_dir():
            raise RuntimeError("Report target must be an existing non-root directory")
        if is_within(run_dir, target) or is_real_within(run_dir, target):
            raise RuntimeError("Restore report directory must be outside the target")
        operations = payload.get("operations")
        if payload.get("status") == "failed-rollback-incomplete":
            rollback = payload.get("rollback") or {}
            pending_operations = rollback.get("pending_restore_operations")
            if isinstance(pending_operations, list):
                operations = pending_operations
        if not isinstance(operations, list) or not operations:
            raise RuntimeError("Report contains no completed operations: {}".format(report_path))
        for operation in operations:
            validate_restore_operation(operation, target, run_dir)
    except Exception as exc:
        message = "{}".format(exc)
        finished_at = now_iso()
        result = {
            "tool": "fivem-xiaoha-cleaner",
            "version": VERSION,
            "status": "restore-failed-validation",
            "operation": "restore",
            "phase": "validation",
            "restored_at": finished_at,
            "report_updated_at": finished_at,
            "terminal": True,
            "finished_at": finished_at,
            "source_report": str(report_path),
            "target": str(target),
            "operations": len(operations) if isinstance(operations, list) else 0,
            "operation_results": [],
            "successful_operations": 0,
            "failed_operations": 0,
            "conflict_operations": 0,
            "errors": [message],
            "error": message,
            "filesystem_partial_changes_possible": False,
            "database_partial_changes_possible": False,
            "partial_changes_possible": False,
            "database_execution": {
                "requested": False,
                "status": "not-applicable",
                "applied": False,
                "partial_changes_possible": False,
            },
            "notices": [
                "恢复报告校验失败，尚未开始修改文件。",
                "文件恢复命令不会恢复数据库 DROP/ALTER 操作。",
            ],
            "database_note": "Database DROP operations are not reversible by this restore command.",
        }
        restore_path, _ = write_restore_reports(run_dir, result)
        raise ExecutionReportError(
            message, report_path=restore_path, report_dir=run_dir
        )

    errors, operation_results = rollback_operations(operations, include_results=True)
    failed_operations = len([
        item for item in operation_results if item.get("status") == "failed"
    ])
    conflict_operations = len([
        item for item in operation_results if item.get("status") == "conflict"
    ])
    status = "restored"
    if failed_operations:
        status = "restore-failed"
    elif conflict_operations:
        status = "restore-conflict"
    finished_at = now_iso()
    result = {
        "tool": "fivem-xiaoha-cleaner",
        "version": VERSION,
        "status": status,
        "operation": "restore",
        "phase": "rollback",
        "restored_at": finished_at,
        "report_updated_at": finished_at,
        "terminal": True,
        "finished_at": finished_at,
        "source_report": str(report_path),
        "target": str(target),
        "operations": len(operations),
        "operation_results": operation_results,
        "successful_operations": (
            len(operation_results) - failed_operations - conflict_operations
        ),
        "failed_operations": failed_operations,
        "conflict_operations": conflict_operations,
        "errors": errors,
        "filesystem_partial_changes_possible": bool(errors),
        "database_partial_changes_possible": False,
        "partial_changes_possible": bool(errors),
        "database_execution": {
            "requested": False,
            "status": "not-applicable",
            "applied": False,
            "partial_changes_possible": False,
        },
        "notices": [
            "恢复操作仅覆盖 run-report.json 中记录的文件修改。",
            "文件恢复命令不会恢复数据库 DROP/ALTER 操作。",
        ],
        "database_note": "Database DROP operations are not reversible by this restore command.",
    }
    if errors:
        result["error"] = "Restore completed with errors:\n- " + "\n- ".join(errors)
        result["notices"].insert(
            0, "部分文件恢复失败；请根据逐项结果处理冲突并复核服务器目录。"
        )
    restore_path, _ = write_restore_reports(run_dir, result)
    if errors:
        raise ExecutionReportError(
            "Restore completed with errors:\n- " + "\n- ".join(errors),
            report_path=restore_path, report_dir=run_dir,
        )
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
        stderr = redact_sensitive_text(
            stderr, [mysql_uri, connection.get("password", "")]
        )
        raise RuntimeError("MySQL cleanup failed (exit {}): {}".format(
            completed.returncode, stderr
        ))
    return decode_bytes(completed.stdout)[0]


def database_report_markdown(payload):
    database = payload["database_execution"]
    lines = [
        "# FiveM 小哈/HGAdmin 数据库 SQL 执行报告",
        "",
        "- 状态：`{}`".format(payload["status"]),
        "- SQL 文件：`{}`".format(markdown_value(database.get("sql_file"))),
        "- 数据库：`{}`".format(markdown_value(database.get("database"))),
        "- 已确认应用：{}".format("是" if database.get("applied") else "否"),
        "- 报告终态：{}".format("是" if payload["terminal"] else "否"),
        "- 开始时间：{}".format(payload["started_at"]),
        "- 完成时间：{}".format(payload.get("finished_at") or "尚未完成"),
        "",
        "## 注意事项",
        "",
    ]
    for notice in payload["notices"]:
        lines.append("- {}".format(notice))
    if payload.get("error"):
        lines.extend(["", "## 错误", ""])
        for error_line in str(payload["error"]).splitlines() or [""]:
            lines.append("    " + error_line)
    lines.append("")
    return "\n".join(lines)


def write_database_apply_report(
    sql_file, status, database="", error=None, partial_changes_possible=False,
    terminal=True, started_at=None, report_dir=None, secrets=None,
):
    sql_path = Path(sql_file).absolute()
    if report_dir is None:
        base = (
            sql_path.parent if sql_path.parent.is_dir()
            else Path(__file__).absolute().parent / "reports" / "database"
        )
        report_dir = unique_run_dir(base / ("database-report_" + now_stamp()))
        report_dir.mkdir(parents=True, exist_ok=False)
    else:
        report_dir = Path(report_dir).absolute()
        report_dir.mkdir(parents=True, exist_ok=True)

    sql_sha256 = ""
    try:
        sql_sha256 = sha256_bytes(sql_path.read_bytes())
    except OSError:
        pass
    safe_error = redact_sensitive_text(error, secrets)
    updated_at = now_iso()
    database_execution = {
        "requested": True,
        "status": status.replace("database-", ""),
        "applied": status == "database-applied",
        "partial_changes_possible": bool(partial_changes_possible),
        "sql_file": str(sql_path),
        "sql_sha256": sql_sha256,
        "database": database,
    }
    if safe_error:
        database_execution["error"] = safe_error
    notices = []
    if status == "database-pending":
        notices.append("SQL 已交给数据库客户端执行，当前报告不是最终结论。")
    elif status == "database-applied":
        notices.append("SQL 已成功执行；数据库变更只能从数据库备份恢复。")
    elif partial_changes_possible:
        notices.append("数据库客户端未成功完成，数据库可能已部分变更；请立即核对并准备从备份恢复。")
    else:
        notices.append("数据库执行在校验阶段失败，尚未开始执行 SQL。")
    payload = {
        "tool": "fivem-xiaoha-cleaner",
        "version": VERSION,
        "operation": "apply-sql",
        "phase": "database",
        "status": status,
        "started_at": started_at or updated_at,
        "report_updated_at": updated_at,
        "terminal": bool(terminal),
        "finished_at": updated_at if terminal else None,
        "operations": [{
            "type": "database-sql",
            "sql_file": str(sql_path),
            "sql_sha256": sql_sha256,
            "status": database_execution["status"],
        }],
        "database_execution": database_execution,
        "filesystem_partial_changes_possible": False,
        "database_partial_changes_possible": bool(partial_changes_possible),
        "partial_changes_possible": bool(partial_changes_possible),
        "notices": notices,
    }
    if safe_error:
        payload["error"] = safe_error
    json_path = report_dir / "database-report.json"
    markdown_path = report_dir / "database-report.md"
    payload["reports"] = {
        "json": str(json_path.absolute()),
        "markdown": str(markdown_path.absolute()),
    }
    json_path.write_bytes((json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    markdown_path.write_bytes(database_report_markdown(payload).encode("utf-8"))
    return json_path, markdown_path, report_dir


def default_scan_dir(target):
    script_dir = Path(__file__).absolute().parent
    return script_dir / "reports" / "scan_{}_{}".format(Path(target).name, now_stamp())


def empty_failure_plan(target, include_review=False):
    return {
        "tool": "fivem-xiaoha-cleaner",
        "version": VERSION,
        "created_at": now_iso(),
        "target": str(Path(target).absolute()),
        "include_review": bool(include_review),
        "resources": {
            "all_count": 0,
            "owned": [],
            "review": [],
        },
        "injection_files": [],
        "edits": {
            "manifests": [],
            "configs": [],
            "sql_files": [],
            "manual_manifests": [],
        },
        "sql": {
            "safe_tables": [],
            "review_tables": [],
            "created_tables": [],
            "added_columns": [],
            "sample_catalog_applied": False,
            "scanned_files": 0,
        },
        "external_references": [],
        "external_references_truncated": False,
        "summary": {
            "owned_resources": 0,
            "review_resources": 0,
            "resource_files": 0,
            "resource_lua_files": 0,
            "resource_bytes": 0,
            "injection_files": 0,
            "manifest_edits": 0,
            "config_edits": 0,
            "external_sql_edits": 0,
            "safe_sql_tables": 0,
            "review_sql_tables": 0,
            "external_references": 0,
            "added_sql_columns": 0,
        },
    }


def write_scan_failure_report(target, output_dir, error, include_review=False):
    plan = empty_failure_plan(target, include_review)
    database_execution = {
        "requested": False,
        "status": "not-started",
        "applied": False,
        "partial_changes_possible": False,
        "sql_file": "",
        "tables": [],
        "added_columns": [],
    }
    return write_reports(
        plan, output_dir, status="scan-failed", operation="scan", phase="scan",
        operations=[], error=str(error), database_execution=database_execution,
        notices=[
            "扫描失败，没有修改服务器文件或数据库。",
            "本次没有生成可执行的 cleanup_database.sql；请先处理错误并重新扫描。",
        ],
        include_sql=False, filesystem_partial_changes_possible=False,
    )


def write_clean_setup_failure_report(
    target, quarantine_root, error, include_review=False, database_requested=False,
    database_name="", secrets=None,
):
    target = Path(target).absolute()
    requested_root = Path(quarantine_root).absolute() if quarantine_root else None
    if is_root_path(target):
        report_root = Path(__file__).absolute().parent / "reports" / "failed-clean"
    elif (
        requested_root
        and not is_within(requested_root, target)
        and not is_real_within(requested_root, target)
    ):
        report_root = requested_root
    else:
        report_root = target.parent / "_xiaoha_quarantine"
    run_dir = unique_run_dir(
        report_root / "{}_{}".format(target.name or "server", now_stamp())
    )
    run_dir.mkdir(parents=True, exist_ok=False)
    plan = empty_failure_plan(target, include_review)
    database_execution = {
        "requested": bool(database_requested),
        "status": "not-started",
        "applied": False,
        "partial_changes_possible": False,
        "sql_file": "",
        "database": database_name,
        "tables": [],
        "added_columns": [],
    }
    reports = write_reports(
        plan, run_dir, status="failed-setup", operation="clean", phase="setup",
        operations=[], error=str(error), database_execution=database_execution,
        notices=[
            "清理在参数、环境或扫描准备阶段失败，尚未修改文件或数据库。",
            "请处理报告中的错误后重新执行。",
        ],
        include_sql=False, filesystem_partial_changes_possible=False,
        secrets=secrets,
    )
    return run_dir, reports


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
            output = Path(args.output).absolute() if args.output else default_scan_dir(args.target)
            try:
                plan = build_plan(args.target, include_review=args.include_review)
            except Exception as exc:
                reports = write_scan_failure_report(
                    args.target, output, exc, args.include_review
                )
                print("JSON report: {}".format(reports[0]))
                print("Markdown report: {}".format(reports[1]))
                raise
            reports = write_reports(
                plan, output, status="scan", operation="scan", operations=[]
            )
            print_summary(plan)
            print("JSON report: {}".format(reports[0]))
            print("Markdown report: {}".format(reports[1]))
            print("Database SQL: {}".format(reports[2]))
            return 0

        if args.command == "clean":
            if not args.yes:
                print("Refusing to modify files without --yes. Running a read-only scan instead.")
                output = default_scan_dir(args.target)
                try:
                    plan = build_plan(args.target, include_review=args.include_review)
                except Exception as exc:
                    reports = write_scan_failure_report(
                        args.target, output, exc, args.include_review
                    )
                    print("Scan report: {}".format(reports[0]))
                    raise
                reports = write_reports(
                    plan, output, status="scan", operation="scan", operations=[]
                )
                print_summary(plan)
                print("Scan report: {}".format(reports[0]))
                return 2
            database_name = ""
            database_secrets = mysql_secret_values(args.mysql_uri)
            initial_database_execution = None
            try:
                target_path = Path(args.target).absolute()
                if args.quarantine_root and (
                    is_within(Path(args.quarantine_root).absolute(), target_path)
                    or is_real_within(
                        Path(args.quarantine_root).absolute(), target_path
                    )
                ):
                    raise ValueError(
                        "Quarantine directory must be outside the target directory"
                    )
                if args.apply_sql:
                    if not args.yes_drop_tables or not args.mysql_uri:
                        raise ValueError(
                            "--apply-sql requires --yes-drop-tables and --mysql-uri"
                        )
                    if (
                        shutil.which(args.mysql_command) is None
                        and not Path(args.mysql_command).is_file()
                    ):
                        raise RuntimeError(
                            "MySQL client was not found: {}".format(args.mysql_command)
                        )
                    database_name = parse_mysql_uri(args.mysql_uri)["database"]
                    initial_database_execution = {
                        "requested": True,
                        "status": "not-started",
                        "applied": False,
                        "partial_changes_possible": False,
                        "database": database_name,
                    }
                plan = build_plan(args.target, include_review=args.include_review)
            except Exception as exc:
                detail = redact_sensitive_text(exc, database_secrets)
                run_dir, reports = write_clean_setup_failure_report(
                    args.target, args.quarantine_root, detail, args.include_review,
                    args.apply_sql, database_name, database_secrets,
                )
                print("Quarantine/report: {}".format(run_dir))
                raise RuntimeError(detail)
            print_summary(plan)
            try:
                run_dir, operations, reports = clean_target(
                    plan, args.quarantine_root, initial_database_execution
                )
            except ExecutionReportError as exc:
                if exc.report_dir:
                    print("Quarantine/report: {}".format(exc.report_dir))
                raise
            print("Cleaned with {} reversible filesystem operations.".format(len(operations)))
            print("Quarantine/report: {}".format(run_dir))
            if args.apply_sql:
                marker = run_dir / "database-cleanup-applied.json"
                sql_sha256 = sha256_bytes(Path(reports[2]).read_bytes())
                database_execution = {
                    "requested": True,
                    "status": "pending",
                    "applied": False,
                    "partial_changes_possible": True,
                    "sql_file": str(reports[2]),
                    "sql_sha256": sql_sha256,
                    "database": database_name,
                    "tables": list(plan["sql"].get("safe_tables", [])),
                    "added_columns": list(plan["sql"].get("added_columns", [])),
                }
                reports = write_reports(
                    plan, run_dir,
                    status="filesystem-cleaned-database-pending",
                    operation="clean", phase="database",
                    operations=operations,
                    database_execution=database_execution,
                    rewrite_sql=False,
                    filesystem_partial_changes_possible=False,
                    secrets=database_secrets,
                )
                try:
                    apply_sql_file(reports[2], args.mysql_uri, args.mysql_command)
                except Exception as exc:
                    detail = redact_sensitive_text(exc, database_secrets)
                    database_execution.update({
                        "status": "failed",
                        "applied": False,
                        "partial_changes_possible": True,
                        "error": detail,
                    })
                    write_reports(
                        plan, run_dir,
                        status="filesystem-cleaned-database-failed",
                        operation="clean", phase="database",
                        operations=operations, error=detail,
                        database_execution=database_execution,
                        rewrite_sql=False,
                        filesystem_partial_changes_possible=False,
                        secrets=database_secrets,
                    )
                    raise RuntimeError(detail)

                applied_at = now_iso()
                database_execution.update({
                    "status": "applied",
                    "applied": True,
                    "partial_changes_possible": False,
                    "applied_at": applied_at,
                    "marker_status": "not-written",
                })
                reports = write_reports(
                    plan, run_dir, status="cleaned-database-applied",
                    operation="clean", phase="database",
                    operations=operations,
                    database_execution=database_execution,
                    rewrite_sql=False,
                    filesystem_partial_changes_possible=False,
                    secrets=database_secrets,
                )
                marker_payload = {
                    "status": "applied",
                    "applied_at": applied_at,
                    "sql_file": str(reports[2]),
                    "sql_sha256": sql_sha256,
                    "database": database_name,
                    "tables": list(plan["sql"].get("safe_tables", [])),
                    "added_columns": list(plan["sql"].get("added_columns", [])),
                    "partial_changes_possible": False,
                    "warning": "Database changes are not restored by the filesystem restore command.",
                }
                try:
                    marker.write_bytes((
                        json.dumps(marker_payload, ensure_ascii=False, indent=2) + "\n"
                    ).encode("utf-8"))
                except Exception as exc:
                    marker_error = redact_sensitive_text(exc, database_secrets)
                    database_execution.update({
                        "marker_status": "failed",
                        "marker_error": marker_error,
                    })
                    print(
                        "WARNING: database cleanup succeeded but the local marker could not be written: {}".format(
                            marker_error
                        ),
                        file=sys.stderr,
                    )
                else:
                    database_execution.update({
                        "marker_status": "written",
                        "marker": str(marker),
                    })
                reports = write_reports(
                    plan, run_dir, status="cleaned-database-applied",
                    operation="clean", phase="database",
                    operations=operations,
                    database_execution=database_execution,
                    rewrite_sql=False,
                    filesystem_partial_changes_possible=False,
                    secrets=database_secrets,
                )
                if database_execution["marker_status"] == "written":
                    print("Database cleanup applied. Marker: {}".format(marker))
                else:
                    print("Database cleanup applied; see run-report.json for marker details.")
            return 0

        if args.command == "restore":
            if not args.yes:
                raise ValueError("restore requires --yes")
            try:
                restore_path, result = restore_report(args.report)
            except ExecutionReportError as exc:
                if exc.report_path:
                    print("Restore report: {}".format(exc.report_path))
                raise
            print("Restored {} filesystem operations.".format(result["operations"]))
            print("Restore report: {}".format(restore_path))
            print("Note: database DROP operations require a database backup to restore.")
            return 0

        if args.command == "apply-sql":
            started_at = now_iso()
            database_name = ""
            database_secrets = mysql_secret_values(args.mysql_uri)
            try:
                if not args.yes_drop_tables:
                    raise ValueError("apply-sql requires --yes-drop-tables")
                sql_path = Path(args.sql_file).absolute()
                if not sql_path.is_file():
                    raise ValueError("SQL file does not exist: {}".format(sql_path))
                database_name = parse_mysql_uri(args.mysql_uri)["database"]
                if (
                    shutil.which(args.mysql_command) is None
                    and not Path(args.mysql_command).is_file()
                ):
                    raise RuntimeError(
                        "MySQL client was not found: {}".format(args.mysql_command)
                    )
            except Exception as exc:
                detail = redact_sensitive_text(exc, database_secrets)
                database_report, _, _ = write_database_apply_report(
                    args.sql_file, "database-failed-validation",
                    database=database_name, error=detail,
                    partial_changes_possible=False, terminal=True,
                    started_at=started_at, secrets=database_secrets,
                )
                print("Database report: {}".format(database_report))
                raise RuntimeError(detail)
            database_report, _, report_dir = write_database_apply_report(
                args.sql_file, "database-pending", database=database_name,
                partial_changes_possible=True, terminal=False,
                started_at=started_at, secrets=database_secrets,
            )
            print("Database report: {}".format(database_report))
            try:
                apply_sql_file(args.sql_file, args.mysql_uri, args.mysql_command)
            except Exception as exc:
                detail = redact_sensitive_text(exc, database_secrets)
                write_database_apply_report(
                    args.sql_file, "database-failed", database=database_name,
                    error=detail, partial_changes_possible=True, terminal=True,
                    started_at=started_at, report_dir=report_dir,
                    secrets=database_secrets,
                )
                raise RuntimeError(detail)
            database_report, _, _ = write_database_apply_report(
                args.sql_file, "database-applied", database=database_name,
                partial_changes_possible=False, terminal=True,
                started_at=started_at, report_dir=report_dir,
                secrets=database_secrets,
            )
            print("Database cleanup applied from {}".format(Path(args.sql_file).absolute()))
            print("Database report: {}".format(database_report))
            return 0
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print("ERROR: {}".format(redact_sensitive_text(exc)), file=sys.stderr)
        if os.environ.get("XIAOHA_CLEANER_DEBUG") == "1":
            traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
