#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Release launcher with automatic server.cfg MySQL discovery.

The SQL deletion confirmations remain mandatory.  When ``clean --apply-sql``
does not include ``--mysql-uri``, this launcher locates server.cfg, follows its
``exec`` chain, reads the final mysql_connection_string assignment, and passes
the normalized connection URI to the verified cleaner core without printing
credentials.
"""

from __future__ import print_function

import os
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import quote, urlparse

import XiaohaCleanerFinal  # installs the release detection/SQL policy
import xiaoha_cleaner as core


MYSQL_KEY = "mysql_connection_string"
SET_COMMANDS = {"set", "setr", "sets"}
ENV_VALUE_PATTERNS = (
    re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$"),
    re.compile(r"^\$\(([A-Za-z_][A-Za-z0-9_]*)\)$"),
    re.compile(r"^\$([A-Za-z_][A-Za-z0-9_]*)$"),
    re.compile(r"^%([A-Za-z_][A-Za-z0-9_]*)%$"),
)


class ConfigError(RuntimeError):
    pass


def cfg_tokens(line):
    """Tokenize a Cfx cfg line while preserving # inside quoted passwords."""
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError:
        return []


def expand_env_reference(value):
    value = value.strip()
    for pattern in ENV_VALUE_PATTERNS:
        match = pattern.match(value)
        if not match:
            continue
        name = match.group(1)
        resolved = os.environ.get(name)
        if resolved is None:
            raise ConfigError(
                "mysql_connection_string references unset environment variable {}".format(name)
            )
        return resolved
    return value


def parse_property_connection(value):
    properties = {}
    for segment in value.split(";"):
        if not segment.strip() or "=" not in segment:
            continue
        key, item = segment.split("=", 1)
        normalized = re.sub(r"[\s_-]+", "", key).lower()
        properties[normalized] = item.strip().strip("\"'")

    def first(*names):
        for name in names:
            normalized = re.sub(r"[\s_-]+", "", name).lower()
            if normalized in properties:
                return properties[normalized]
        return None

    host = first("host", "server", "data source", "datasource")
    database = first("database", "initial catalog", "initialcatalog")
    user = first("user", "username", "user id", "userid", "uid") or "root"
    password = first("password", "pwd") or ""
    port_value = first("port") or "3306"
    if not host or not database:
        raise ConfigError(
            "property-style mysql_connection_string must include host/server and database"
        )
    try:
        port = int(port_value)
    except ValueError:
        raise ConfigError("mysql_connection_string contains an invalid port")
    if not (1 <= port <= 65535):
        raise ConfigError("mysql_connection_string port is outside 1-65535")
    host_part = "[{}]".format(host) if ":" in host and not host.startswith("[") else host
    credentials = quote(user, safe="")
    if password:
        credentials += ":" + quote(password, safe="")
    return "mysql://{}@{}:{}/{}".format(
        credentials, host_part, port, quote(database, safe="")
    )


def normalize_connection_string(value):
    value = expand_env_reference(value.strip().strip("\"'"))
    parsed = urlparse(value)
    if parsed.scheme.lower() in {"mysql", "mariadb"}:
        if not parsed.hostname or not parsed.path.strip("/"):
            raise ConfigError("mysql URI must include host and database")
        return value, "uri"
    if "=" in value and ";" in value:
        return parse_property_connection(value), "properties"
    raise ConfigError(
        "unsupported mysql_connection_string format; expected mysql:// URI or key=value properties"
    )


def resolve_exec_path(raw_path, current_cfg, root_cfg):
    expanded = os.path.expandvars(raw_path.strip().strip("\"'"))
    if expanded.startswith("@"):
        return None
    candidate = Path(expanded)
    if candidate.is_absolute():
        return candidate
    local = current_cfg.parent / candidate
    if local.is_file():
        return local
    rooted = root_cfg.parent / candidate
    return rooted


def read_cfg_chain(root_cfg):
    root_cfg = Path(root_cfg).absolute()
    state = {"value": None, "source": None, "visited": []}
    visiting = set()

    def visit(path, depth):
        path = Path(path).absolute()
        key = core.path_key(path)
        if key in visiting or depth > 32 or not path.is_file():
            return
        visiting.add(key)
        state["visited"].append(str(path))
        try:
            text, _, _ = core.read_text_file(path)
        except OSError:
            visiting.remove(key)
            return
        for line in text.splitlines():
            tokens = cfg_tokens(line)
            if not tokens:
                continue
            command = tokens[0].lower()
            if command == "exec" and len(tokens) >= 2:
                include = resolve_exec_path(tokens[1], path, root_cfg)
                if include is not None:
                    visit(include, depth + 1)
                continue
            if (
                command in SET_COMMANDS
                and len(tokens) >= 3
                and tokens[1].lower() == MYSQL_KEY
            ):
                state["value"] = " ".join(tokens[2:]).strip()
                state["source"] = str(path)
        visiting.remove(key)

    visit(root_cfg, 0)
    return state


def add_candidate(candidates, seen, path, priority):
    path = Path(path).absolute()
    key = core.path_key(path)
    if key in seen or not path.is_file():
        return
    seen.add(key)
    candidates.append((path, priority))


def server_cfg_candidates(target, explicit_cfg=None):
    if explicit_cfg:
        path = Path(explicit_cfg).absolute()
        if not path.is_file():
            raise ConfigError("specified server.cfg does not exist: {}".format(path))
        return [(path, 0)]

    target = Path(target).absolute()
    candidates = []
    seen = set()
    if target.is_file() and target.name.lower() == "server.cfg":
        add_candidate(candidates, seen, target, 0)
        return candidates

    base = target if target.is_dir() else target.parent
    current = base
    for distance in range(0, 6):
        add_candidate(candidates, seen, current / "server.cfg", distance)
        if current.parent == current:
            break
        current = current.parent

    if base.is_dir():
        for current_text, dirs, files in os.walk(str(base), topdown=True, followlinks=False):
            current_path = Path(current_text)
            try:
                depth = len(current_path.relative_to(base).parts)
            except ValueError:
                continue
            if depth >= 5:
                dirs[:] = []
            else:
                dirs[:] = [
                    name for name in dirs
                    if name.lower() not in core.IGNORED_DIR_NAMES
                    and not name.lower().startswith("_xiaoha_quarantine")
                ]
            for name in files:
                if name.lower() == "server.cfg":
                    add_candidate(candidates, seen, current_path / name, 100 + depth)
            if len(candidates) >= 50:
                break
    return sorted(candidates, key=lambda item: (item[1], core.path_key(item[0])))


def discover_mysql_connection(target, explicit_cfg=None):
    candidates = server_cfg_candidates(target, explicit_cfg)
    if not candidates:
        raise ConfigError("server.cfg was not found under or above {}".format(Path(target).absolute()))

    matches = []
    for cfg_path, priority in candidates:
        state = read_cfg_chain(cfg_path)
        if not state["value"]:
            continue
        uri, style = normalize_connection_string(state["value"])
        matches.append({
            "uri": uri,
            "style": style,
            "server_cfg": str(cfg_path),
            "assignment_cfg": state["source"],
            "priority": priority,
        })

    if not matches:
        raise ConfigError(
            "mysql_connection_string was not found in server.cfg or its exec chain"
        )
    best_priority = min(item["priority"] for item in matches)
    best = [item for item in matches if item["priority"] == best_priority]
    unique_uris = {item["uri"] for item in best}
    if len(unique_uris) > 1:
        raise ConfigError(
            "multiple equally close server.cfg files use different databases; pass --server-cfg PATH"
        )
    return best[0]


def pop_option(arguments, option):
    output = []
    value = None
    index = 0
    prefix = option + "="
    while index < len(arguments):
        item = arguments[index]
        if item == option:
            if index + 1 >= len(arguments):
                raise ConfigError("{} requires a value".format(option))
            value = arguments[index + 1]
            index += 2
            continue
        if item.startswith(prefix):
            value = item[len(prefix):]
            index += 1
            continue
        output.append(item)
        index += 1
    return output, value


def has_option(arguments, option):
    return option in arguments or any(item.startswith(option + "=") for item in arguments)


def command_target(arguments, command):
    try:
        index = arguments.index(command)
    except ValueError:
        return None
    if index + 1 >= len(arguments) or arguments[index + 1].startswith("--"):
        return None
    return arguments[index + 1]


def prepare_arguments(argv):
    arguments, explicit_cfg = pop_option(list(argv), "--server-cfg")
    arguments, server_root = pop_option(arguments, "--server-root")
    command = next((item for item in arguments if item in {"clean", "apply-sql"}), None)
    needs_connection = command is not None and not has_option(arguments, "--mysql-uri")
    if command == "clean" and not has_option(arguments, "--apply-sql"):
        needs_connection = False
    if not needs_connection:
        return arguments, None

    target = server_root
    if target is None and command == "clean":
        target = command_target(arguments, "clean")
    if target is None and explicit_cfg:
        target = str(Path(explicit_cfg).absolute().parent)
    if target is None:
        target = os.getcwd()

    connection = discover_mysql_connection(target, explicit_cfg)
    arguments.extend(["--mysql-uri", connection["uri"]])
    return arguments, connection


def main(argv=None):
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        arguments, connection = prepare_arguments(raw_arguments)
        if connection:
            print("MySQL config: {}".format(connection["assignment_cfg"]))
            print("MySQL connection: loaded securely from server.cfg ({})".format(
                connection["style"]
            ))
        return core.main(arguments)
    except ConfigError as exc:
        command = next(
            (item for item in raw_arguments if item in {"clean", "apply-sql"}),
            None,
        )
        try:
            if command == "clean":
                target = command_target(raw_arguments, "clean")
                if target:
                    _, quarantine_root = pop_option(
                        raw_arguments, "--quarantine-root"
                    )
                    run_dir, _ = core.write_clean_setup_failure_report(
                        target, quarantine_root, exc,
                        include_review="--include-review" in raw_arguments,
                        database_requested="--apply-sql" in raw_arguments,
                    )
                    print("Quarantine/report: {}".format(run_dir))
            elif command == "apply-sql":
                sql_file = command_target(raw_arguments, "apply-sql")
                if sql_file:
                    report, _, _ = core.write_database_apply_report(
                        sql_file, "database-failed-config",
                        error=exc, partial_changes_possible=False,
                        terminal=True,
                    )
                    print("Database report: {}".format(report))
        except Exception as report_exc:
            print(
                "WARNING: failed to write execution report: {}".format(report_exc),
                file=sys.stderr,
            )
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
