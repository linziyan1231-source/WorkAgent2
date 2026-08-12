#!/usr/bin/env python3
"""Apply and verify WorkAgent2's managed per-user Skill policy.

The policy keeps an allow-list of AionCore built-ins, installs the six
project-local llm-wiki skills as self-contained user skills, and soft-deletes
the remaining built-ins from the SQLite catalog.  File removals are reversible:
source directories and a consistent SQLite backup are retained below the
SID-private data tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


POLICY_VERSION = 1
MANAGED_MARKER = ".workagent2-managed-skill.json"
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

KEEP_BUILTINS = frozenset(
    {
        "weixin-file-send",
        "workagent-help",
        "pdf",
        "officecli-xlsx",
        "officecli-word-form",
        "officecli-pptx",
        "officecli-financial-model",
        "officecli-docx",
        "officecli-data-dashboard",
        "aionui-webui-setup",
        "aionui-webui-public",
        "aionui-troubleshooting",
        "aionui-config",
    }
)

WIKI_SKILLS = (
    "wiki-setup",
    "wiki-ingest",
    "wiki-query",
    "wiki-edit",
    "wiki-lint",
    "wiki-dream",
)

SKILL_LIST_COLUMNS = (
    ("assistant_definitions", "id", "default_skill_ids"),
    ("assistant_definitions", "id", "default_disabled_builtin_skill_ids"),
    ("assistant_preferences", "assistant_definition_id", "last_skill_ids"),
    ("assistant_preferences", "assistant_definition_id", "last_disabled_builtin_skill_ids"),
    ("assistants", "id", "enabled_skills"),
    ("assistants", "id", "disabled_builtin_skills"),
)


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkspaceEntry:
    path: Path
    target: Path | None
    reparse: bool


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalized(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        absolute = absolute.resolve(strict=False)
    except OSError:
        pass
    return Path(os.path.normcase(str(absolute)))


def is_within(path: Path, root: Path) -> bool:
    try:
        normalized(path).relative_to(normalized(root))
        return True
    except ValueError:
        return False


def lstat_is_reparse(path: Path) -> bool:
    info = os.lstat(path)
    return bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT) or stat.S_ISLNK(info.st_mode)


def require_normal_directory(path: Path, label: str) -> Path:
    path = normalized(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise PolicyError(f"{label} is missing: {path}") from exc
    if not stat.S_ISDIR(info.st_mode) or lstat_is_reparse(path):
        raise PolicyError(f"{label} must be a normal directory: {path}")
    return path


def require_regular_file(path: Path, label: str) -> Path:
    path = normalized(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise PolicyError(f"{label} is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or lstat_is_reparse(path):
        raise PolicyError(f"{label} must be a regular file: {path}")
    return path


def iter_regular_files(root: Path) -> Iterable[tuple[str, Path]]:
    root = require_normal_directory(root, "source tree")
    stack = [root]
    while stack:
        current = stack.pop()
        with os.scandir(current) as entries:
            ordered = sorted(entries, key=lambda item: item.name.casefold(), reverse=True)
        for entry in ordered:
            path = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            if bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT) or stat.S_ISLNK(info.st_mode):
                raise PolicyError(f"reparse points are forbidden in managed Skill input: {path}")
            if stat.S_ISDIR(info.st_mode):
                stack.append(path)
            elif stat.S_ISREG(info.st_mode):
                yield path.relative_to(root).as_posix(), path
            else:
                raise PolicyError(f"non-regular file in managed Skill input: {path}")


def copy_tree_checked(source: Path, target: Path) -> None:
    source = require_normal_directory(source, "copy source")
    if target.exists():
        raise PolicyError(f"copy target already exists: {target}")
    target.mkdir(parents=True)
    for relative, path in iter_regular_files(source):
        destination = target / Path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)


def parse_frontmatter(skill_file: Path) -> tuple[str, str]:
    text = skill_file.read_text(encoding="utf-8")
    lines = text.splitlines()
    if len(lines) < 3 or lines[0].strip() != "---":
        raise PolicyError(f"invalid Skill frontmatter: {skill_file}")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise PolicyError(f"unterminated Skill frontmatter: {skill_file}") from exc
    metadata: dict[str, str] = {}
    index = 1
    while index < end:
        match = re.match(r"^([a-z_]+):\s*(.*)$", lines[index])
        if not match:
            index += 1
            continue
        key, value = match.group(1), match.group(2).strip()
        if value in {">", ">-", "|", "|-"}:
            parts: list[str] = []
            index += 1
            while index < end and (not lines[index].strip() or lines[index][:1].isspace()):
                if lines[index].strip():
                    parts.append(lines[index].strip())
                index += 1
            metadata[key] = " ".join(parts)
            continue
        metadata[key] = value.strip("\"'")
        index += 1
    name = metadata.get("name", "").strip()
    description = metadata.get("description", "").strip()
    if not name or not description:
        raise PolicyError(f"Skill name and description are required: {skill_file}")
    return name, description


def source_digest(plugin_root: Path, skill_name: str) -> str:
    digest = hashlib.sha256()
    sources = (
        (f"skill/{skill_name}", plugin_root / "skills" / skill_name),
        ("assets/workspace", plugin_root / "assets" / "workspace"),
    )
    for prefix, root in sources:
        for relative, path in sorted(iter_regular_files(root)):
            digest.update(f"{prefix}/{relative}\0".encode())
            digest.update(path.read_bytes())
            digest.update(b"\n")
    helper = require_regular_file(plugin_root / "scripts" / "wiki_tool.py", "wiki helper")
    digest.update(b"scripts/wiki_tool.py\0")
    digest.update(helper.read_bytes())
    digest.update(f"\nstandalone-layout-v{POLICY_VERSION}\n".encode())
    return digest.hexdigest()


def build_skill_stage(plugin_root: Path, skill_name: str, stage: Path, digest: str) -> tuple[str, str]:
    source = plugin_root / "skills" / skill_name
    copy_tree_checked(source, stage)
    scripts = stage / "scripts"
    scripts.mkdir()
    shutil.copyfile(plugin_root / "scripts" / "wiki_tool.py", scripts / "wiki_tool.py")
    copy_tree_checked(plugin_root / "assets" / "workspace", stage / "assets" / "workspace")
    skill_file = stage / "SKILL.md"
    text = skill_file.read_text(encoding="utf-8")
    if "<PLUGIN_ROOT>" not in text:
        raise PolicyError(f"Skill does not declare its plugin runtime placeholder: {source}")
    skill_file.write_text(text.replace("<PLUGIN_ROOT>", "<SKILL_DIR>"), encoding="utf-8", newline="\n")
    name, description = parse_frontmatter(skill_file)
    if name != skill_name:
        raise PolicyError(f"Skill folder/frontmatter mismatch: {skill_name} != {name}")
    marker = {
        "format_version": 1,
        "managed_by": "WorkAgent2",
        "policy_version": POLICY_VERSION,
        "skill": skill_name,
        "source_sha256": digest,
        "installed_at_utc": utc_now(),
    }
    write_json_atomic(stage / MANAGED_MARKER, marker)
    return name, description


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def read_marker(path: Path) -> dict[str, object] | None:
    marker_path = path / MANAGED_MARKER
    if not marker_path.is_file() or lstat_is_reparse(marker_path):
        return None
    try:
        value = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def scan_builtin_skills(builtin_root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for parent in (builtin_root, builtin_root / "auto-inject"):
        if not parent.is_dir():
            continue
        for entry in os.scandir(parent):
            path = Path(entry.path)
            if entry.name == "auto-inject" or not entry.is_dir(follow_symlinks=False) or lstat_is_reparse(path):
                continue
            if (path / "SKILL.md").is_file():
                name, _ = parse_frontmatter(path / "SKILL.md")
                if name in result:
                    raise PolicyError(f"duplicate built-in Skill name: {name}")
                result[name] = path
    return result


def restore_missing_builtins(builtin_root: Path, reference_root: Path, missing: set[str]) -> list[str]:
    restored: list[str] = []
    references = scan_builtin_skills(reference_root)
    for name in sorted(missing):
        source = references.get(name)
        if source is None:
            raise PolicyError(f"whitelisted built-in is missing from the reference corpus: {name}")
        target_parent = builtin_root / "auto-inject" if source.parent.name == "auto-inject" else builtin_root
        target = target_parent / source.name
        stage = target_parent / f".{source.name}.restore-{uuid.uuid4().hex}"
        copy_tree_checked(source, stage)
        os.replace(stage, target)
        restored.append(name)
    return restored


def table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}


def parse_string_list(value: object) -> list[str] | None:
    if value is None:
        return []
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        return None
    return parsed


def database_archived_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute("SELECT name FROM skills WHERE source = 'builtin'")
        if str(row[0]) not in KEEP_BUILTINS
    }


def list_columns_need_filter(connection: sqlite3.Connection, archived: set[str]) -> bool:
    for table, key, column in SKILL_LIST_COLUMNS:
        columns = table_columns(connection, table)
        if key not in columns or column not in columns:
            continue
        for _, value in connection.execute(f"SELECT {key}, {column} FROM {table}"):
            items = parse_string_list(value)
            if items is None:
                raise PolicyError(f"{table}.{column} contains malformed JSON")
            if any(item in archived for item in items):
                return True
    return False


def database_needs_change(connection: sqlite3.Connection, data_root: Path, archived: set[str]) -> bool:
    placeholders = ",".join("?" for _ in KEEP_BUILTINS)
    row = connection.execute(
        f"SELECT COUNT(*) FROM skills WHERE source='builtin' AND name NOT IN ({placeholders}) "
        "AND (enabled=1 OR deleted_at IS NULL)",
        tuple(sorted(KEEP_BUILTINS)),
    ).fetchone()
    if row and row[0]:
        return True
    active_keep = {
        str(row[0])
        for row in connection.execute(
            f"SELECT name FROM skills WHERE source='builtin' AND enabled=1 AND deleted_at IS NULL "
            f"AND name IN ({placeholders})",
            tuple(sorted(KEEP_BUILTINS)),
        )
    }
    if active_keep != set(KEEP_BUILTINS):
        return True
    for name in WIKI_SKILLS:
        target = normalized(data_root / "data" / "skills" / name)
        row = connection.execute(
            "SELECT source,enabled,deleted_at,path FROM skills WHERE name=?", (name,)
        ).fetchone()
        if row is None or row[0] != "user" or not row[1] or row[2] is not None or normalized(Path(row[3])) != target:
            return True
    return list_columns_need_filter(connection, archived)


def backup_database(connection: sqlite3.Connection, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    destination = sqlite3.connect(target)
    try:
        connection.backup(destination)
        check = destination.execute("PRAGMA integrity_check").fetchone()
        if check is None or check[0] != "ok":
            raise PolicyError(f"SQLite backup integrity check failed: {target}")
    finally:
        destination.close()


def stable_skill_id(name: str) -> str:
    return "skill_managed_" + hashlib.sha256(name.encode()).hexdigest()[:24]


def update_database(
    connection: sqlite3.Connection,
    data_root: Path,
    builtin_root: Path,
    archived: set[str],
) -> dict[str, int]:
    now = int(time.time() * 1000)
    counts = {"archived_rows": 0, "managed_rows": 0, "filtered_bindings": 0}
    connection.execute("BEGIN IMMEDIATE")
    try:
        placeholders = ",".join("?" for _ in KEEP_BUILTINS)
        cursor = connection.execute(
            f"UPDATE skills SET enabled=0, deleted_at=COALESCE(deleted_at,?), updated_at=? "
            f"WHERE source='builtin' AND name NOT IN ({placeholders})",
            (now, now, *sorted(KEEP_BUILTINS)),
        )
        counts["archived_rows"] = cursor.rowcount

        disk_builtins = scan_builtin_skills(builtin_root)
        for name in sorted(KEEP_BUILTINS):
            path = disk_builtins[name]
            _, description = parse_frontmatter(path / "SKILL.md")
            existing = connection.execute("SELECT source FROM skills WHERE name=?", (name,)).fetchone()
            if existing is not None and existing[0] != "builtin":
                raise PolicyError(f"whitelisted built-in collides with a non-built-in catalog row: {name}")
            connection.execute(
                "INSERT INTO skills(id,name,description,path,source,enabled,deleted_at,created_at,updated_at) "
                "VALUES(?,?,?,?, 'builtin',1,NULL,?,?) ON CONFLICT(name) DO UPDATE SET "
                "description=excluded.description,path=excluded.path,source='builtin',enabled=1,deleted_at=NULL,updated_at=excluded.updated_at",
                (stable_skill_id(name), name, description, str(path), now, now),
            )

        for name in WIKI_SKILLS:
            path = normalized(data_root / "data" / "skills" / name)
            marker = read_marker(path)
            if marker is None or marker.get("skill") != name:
                raise PolicyError(f"managed wiki Skill marker is missing: {path}")
            _, description = parse_frontmatter(path / "SKILL.md")
            existing = connection.execute("SELECT source,path FROM skills WHERE name=?", (name,)).fetchone()
            if existing is not None and (existing[0] != "user" or normalized(Path(existing[1])) != path):
                raise PolicyError(f"managed wiki Skill collides with an existing catalog row: {name}")
            connection.execute(
                "INSERT INTO skills(id,name,description,path,source,enabled,deleted_at,created_at,updated_at) "
                "VALUES(?,?,?,?, 'user',1,NULL,?,?) ON CONFLICT(name) DO UPDATE SET "
                "description=excluded.description,path=excluded.path,source='user',enabled=1,deleted_at=NULL,updated_at=excluded.updated_at",
                (stable_skill_id(name), name, description, str(path), now, now),
            )
            counts["managed_rows"] += 1

        for table, key, column in SKILL_LIST_COLUMNS:
            columns = table_columns(connection, table)
            if key not in columns or column not in columns:
                continue
            for identity, value in connection.execute(f"SELECT {key}, {column} FROM {table}").fetchall():
                items = parse_string_list(value)
                if items is None:
                    raise PolicyError(f"{table}.{column} contains malformed JSON")
                filtered = [item for item in items if item not in archived]
                if filtered != items:
                    connection.execute(
                        f"UPDATE {table} SET {column}=? WHERE {key} IS ?",
                        (json.dumps(filtered, ensure_ascii=False, separators=(",", ":")), identity),
                    )
                    counts["filtered_bindings"] += 1
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return counts


def walk_workspace_skill_entries(workspace: Path, archived: set[str]) -> tuple[list[WorkspaceEntry], list[WorkspaceEntry]]:
    links: list[WorkspaceEntry] = []
    copies: list[WorkspaceEntry] = []
    if not workspace.is_dir():
        return links, copies
    stack = [workspace]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if current.name == "skills" and current.parent.name in {".codex", ".kimi", ".claude"}:
            for entry in entries:
                if entry.name not in archived:
                    continue
                path = Path(entry.path)
                try:
                    reparse = lstat_is_reparse(path)
                except FileNotFoundError:
                    continue
                if reparse:
                    try:
                        target = path.resolve(strict=False)
                    except OSError:
                        target = None
                    links.append(WorkspaceEntry(path, target, True))
                elif entry.is_dir(follow_symlinks=False):
                    copies.append(WorkspaceEntry(path, None, False))
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                info = entry.stat(follow_symlinks=False)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT) or stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISDIR(info.st_mode):
                stack.append(path)
    return links, copies


def remove_managed_workspace_links(entries: list[WorkspaceEntry], builtin_root: Path) -> list[str]:
    removed: list[str] = []
    for entry in entries:
        if entry.target is None or not is_within(entry.target, builtin_root):
            raise PolicyError(f"refusing to remove workspace Skill link with an unexpected target: {entry.path}")
        if not lstat_is_reparse(entry.path):
            raise PolicyError(f"workspace Skill link changed during policy application: {entry.path}")
        os.rmdir(entry.path)
        removed.append(str(entry.path))
    return removed


def validate_inputs(
    data_root: Path,
    plugin_root: Path,
    reference_root: Path,
    *,
    create_user_skills: bool = False,
    allow_missing_user_skills: bool = False,
) -> tuple[Path, Path, Path, Path, Path]:
    data_root = require_normal_directory(data_root, "SID data root")
    if not re.fullmatch(r"S-[0-9-]+", data_root.name, re.IGNORECASE):
        raise PolicyError(f"data root leaf must be a Windows SID: {data_root}")
    plugin_root = require_normal_directory(plugin_root, "llm-wiki plugin root")
    reference_root = require_normal_directory(reference_root, "built-in reference root")
    require_regular_file(plugin_root / ".codex-plugin" / "plugin.json", "llm-wiki manifest")
    data_directory = require_normal_directory(data_root / "data", "AionCore data directory")
    builtin_root = require_normal_directory(data_directory / "builtin-skills", "built-in Skill root")
    skills_root = data_directory / "skills"
    if create_user_skills and not skills_root.exists():
        skills_root.mkdir()
    if skills_root.exists():
        require_normal_directory(skills_root, "user Skill root")
    elif not allow_missing_user_skills:
        raise PolicyError(f"user Skill root is missing: {skills_root}")
    database = require_regular_file(data_root / "data" / "aionui-backend.db", "AionCore database")
    for name in WIKI_SKILLS:
        require_regular_file(plugin_root / "skills" / name / "SKILL.md", f"{name} source")
    return data_root, plugin_root, reference_root, builtin_root, database


def plan_policy(data_root: Path, plugin_root: Path, reference_root: Path) -> dict[str, object]:
    data_root, plugin_root, reference_root, builtin_root, database = validate_inputs(
        data_root,
        plugin_root,
        reference_root,
        allow_missing_user_skills=True,
    )
    skills_root = data_root / "data" / "skills"
    disk = scan_builtin_skills(builtin_root)
    reference = scan_builtin_skills(reference_root)
    missing_keep = set(KEEP_BUILTINS) - disk.keys()
    unavailable_keep = sorted(name for name in missing_keep if name not in reference)
    archive_disk = sorted(set(disk) - KEEP_BUILTINS)
    collisions: list[str] = []
    stale_wiki: list[str] = []
    for name in WIKI_SKILLS:
        target = skills_root / name
        if not target.exists():
            stale_wiki.append(name)
            continue
        if lstat_is_reparse(target) or not target.is_dir():
            collisions.append(str(target))
            continue
        marker = read_marker(target)
        if marker is None:
            collisions.append(str(target))
        elif marker.get("source_sha256") != source_digest(plugin_root, name):
            stale_wiki.append(name)

    connection = sqlite3.connect(database, timeout=30)
    try:
        connection.execute("PRAGMA busy_timeout=30000")
        archived = database_archived_names(connection) | set(archive_disk)
        for name in WIKI_SKILLS:
            row = connection.execute("SELECT source,path FROM skills WHERE name=?", (name,)).fetchone()
            expected = normalized(skills_root / name)
            if row is not None and (row[0] != "user" or normalized(Path(row[1])) != expected):
                collisions.append(f"catalog:{name}:{row[0]}:{row[1]}")
        db_change = database_needs_change(connection, data_root, archived)
    finally:
        connection.close()
    links, copies = walk_workspace_skill_entries(data_root / "workspace", archived)
    errors: list[str] = []
    if unavailable_keep:
        errors.append("whitelisted built-ins are unavailable from both live and reference trees: " + ", ".join(unavailable_keep))
    if collisions:
        errors.append("managed wiki Skill collisions: " + ", ".join(collisions))
    if copies:
        errors.append("non-link workspace copies use archived names: " + ", ".join(str(item.path) for item in copies[:5]))
    return {
        "status": "READY" if not errors else "BLOCKED",
        "policy_version": POLICY_VERSION,
        "data_root": str(data_root),
        "managed_available_count_after": len(KEEP_BUILTINS) + len(WIKI_SKILLS),
        "archive_builtin_names": archive_disk,
        "archive_builtin_count": len(archive_disk),
        "restore_builtin_names": sorted(missing_keep),
        "install_or_update_wiki_names": stale_wiki,
        "workspace_link_removal_count": len(links),
        "workspace_copy_conflict_count": len(copies),
        "database_change": db_change,
        "errors": errors,
    }


def verify_policy(data_root: Path, plugin_root: Path, reference_root: Path) -> dict[str, object]:
    data_root, plugin_root, reference_root, builtin_root, database = validate_inputs(
        data_root, plugin_root, reference_root
    )
    disk = scan_builtin_skills(builtin_root)
    missing_keep = sorted(KEEP_BUILTINS - disk.keys())
    unexpected = sorted(disk.keys() - KEEP_BUILTINS)
    errors: list[str] = []
    if missing_keep:
        errors.append("missing whitelisted built-ins: " + ", ".join(missing_keep))
    if unexpected:
        errors.append("non-whitelisted built-ins remain: " + ", ".join(unexpected))

    for name in WIKI_SKILLS:
        target = data_root / "data" / "skills" / name
        marker = read_marker(target)
        expected_digest = source_digest(plugin_root, name)
        if marker is None or marker.get("source_sha256") != expected_digest:
            errors.append(f"managed wiki Skill is missing or stale: {name}")
            continue
        for required in (
            target / "SKILL.md",
            target / "scripts" / "wiki_tool.py",
            target / "assets" / "workspace" / "index.md",
            target / "assets" / "workspace" / "log.md",
            target / "assets" / "workspace" / "contract.md",
        ):
            if not required.is_file():
                errors.append(f"managed wiki Skill file is missing: {required}")

    connection = sqlite3.connect(database, timeout=30)
    try:
        connection.execute("PRAGMA busy_timeout=30000")
        archived = database_archived_names(connection) | (set(disk) - KEEP_BUILTINS)
        active_builtins = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM skills WHERE source='builtin' AND enabled=1 AND deleted_at IS NULL"
            )
        }
        if active_builtins != set(KEEP_BUILTINS):
            errors.append(
                "active built-in catalog mismatch: "
                + json.dumps(sorted(active_builtins), ensure_ascii=False)
            )
        active_wiki = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM skills WHERE source='user' AND enabled=1 AND deleted_at IS NULL "
                f"AND name IN ({','.join('?' for _ in WIKI_SKILLS)})",
                WIKI_SKILLS,
            )
        }
        if active_wiki != set(WIKI_SKILLS):
            errors.append("managed wiki catalog mismatch: " + json.dumps(sorted(active_wiki), ensure_ascii=False))
        if list_columns_need_filter(connection, archived):
            errors.append("assistant skill bindings still reference archived built-ins")
    finally:
        connection.close()

    links, copies = walk_workspace_skill_entries(data_root / "workspace", archived)
    if links:
        errors.append(f"{len(links)} workspace links still reference archived built-ins")
    if copies:
        errors.append(f"{len(copies)} unmanaged workspace copies use archived built-in names")
    result = {
        "status": "OK" if not errors else "INVALID",
        "policy_version": POLICY_VERSION,
        "data_root": str(data_root),
        "managed_available_count": len(KEEP_BUILTINS) + len(WIKI_SKILLS),
        "active_builtin_count": len(active_builtins),
        "active_wiki_count": len(active_wiki),
        "errors": errors,
    }
    if errors:
        raise PolicyError(json.dumps(result, ensure_ascii=False))
    return result


def apply_policy(data_root: Path, plugin_root: Path, reference_root: Path) -> dict[str, object]:
    data_root, plugin_root, reference_root, builtin_root, database = validate_inputs(
        data_root, plugin_root, reference_root, create_user_skills=True
    )
    skills_root = data_root / "data" / "skills"
    disk = scan_builtin_skills(builtin_root)
    missing_keep = set(KEEP_BUILTINS) - disk.keys()
    archive_disk = {name: path for name, path in disk.items() if name not in KEEP_BUILTINS}
    digests = {name: source_digest(plugin_root, name) for name in WIKI_SKILLS}

    connection = sqlite3.connect(database, timeout=30)
    connection.execute("PRAGMA busy_timeout=30000")
    archived = database_archived_names(connection) | set(archive_disk)
    links, copies = walk_workspace_skill_entries(data_root / "workspace", archived)
    if copies:
        connection.close()
        raise PolicyError(
            "refusing to overwrite non-link workspace Skill directories with archived names: "
            + ", ".join(str(item.path) for item in copies[:5])
        )

    stale_wiki: list[str] = []
    for name in WIKI_SKILLS:
        target = skills_root / name
        if not target.exists():
            stale_wiki.append(name)
            continue
        if lstat_is_reparse(target) or not target.is_dir():
            connection.close()
            raise PolicyError(f"managed wiki target must be a normal directory: {target}")
        marker = read_marker(target)
        if marker is None:
            connection.close()
            raise PolicyError(f"refusing to overwrite an unmanaged user Skill: {target}")
        if marker.get("source_sha256") != digests[name]:
            stale_wiki.append(name)

    db_change = database_needs_change(connection, data_root, archived)
    if not missing_keep and not archive_disk and not stale_wiki and not links and not db_change:
        connection.close()
        result = verify_policy(data_root, plugin_root, reference_root)
        result.update({"changed": False, "archive_root": None})
        return result

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    archive_root = data_root / "data" / "skill-policy-archive" / run_id
    archive_root.mkdir(parents=True)
    backup_database(connection, archive_root / "aionui-backend.db")
    moved: list[tuple[Path, Path]] = []
    installed_new: list[Path] = []
    restored_new: list[Path] = []
    removed_links: list[str] = []
    database_committed = False
    try:
        restored = restore_missing_builtins(builtin_root, reference_root, missing_keep)
        for name in restored:
            restored_new.append(scan_builtin_skills(builtin_root)[name])

        for name, source in sorted(archive_disk.items()):
            relative = source.relative_to(builtin_root)
            destination = archive_root / "builtin-skills" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
            moved.append((destination, source))

        for name in stale_wiki:
            target = skills_root / name
            stage = skills_root / f".{name}.stage-{uuid.uuid4().hex}"
            build_skill_stage(plugin_root, name, stage, digests[name])
            if target.exists():
                previous = archive_root / "managed-skills" / name
                previous.parent.mkdir(parents=True, exist_ok=True)
                os.replace(target, previous)
                moved.append((previous, target))
            os.replace(stage, target)
            installed_new.append(target)

        removed_links = remove_managed_workspace_links(links, builtin_root)
        counts = update_database(connection, data_root, builtin_root, archived)
        database_committed = True
        manifest = {
            "format_version": 1,
            "policy_version": POLICY_VERSION,
            "run_id": run_id,
            "applied_at_utc": utc_now(),
            "data_root": str(data_root),
            "kept_builtins": sorted(KEEP_BUILTINS),
            "archived_builtins": sorted(archive_disk),
            "restored_builtins": sorted(missing_keep),
            "installed_wiki_skills": sorted(stale_wiki),
            "removed_workspace_links": removed_links,
            "database_changes": counts,
            "rollback_database": "aionui-backend.db",
        }
        write_json_atomic(archive_root / "manifest.json", manifest)
    except Exception as exc:
        if not database_committed:
            connection.rollback()
            for target in reversed(installed_new):
                if target.is_dir() and not lstat_is_reparse(target):
                    shutil.rmtree(target)
            for archived_path, original_path in reversed(moved):
                if archived_path.exists() and not original_path.exists():
                    original_path.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(archived_path, original_path)
            for target in reversed(restored_new):
                if target.is_dir() and not lstat_is_reparse(target):
                    shutil.rmtree(target)
        try:
            write_json_atomic(
                archive_root / "failed.json",
                {
                    "failed_at_utc": utc_now(),
                    "error": str(exc),
                    "database_committed": database_committed,
                    "removed_workspace_links": removed_links,
                },
            )
        except OSError:
            pass
        connection.close()
        raise
    connection.close()

    result = verify_policy(data_root, plugin_root, reference_root)
    result.update(
        {
            "changed": True,
            "archive_root": str(archive_root),
            "archived_builtin_count": len(archive_disk),
            "installed_wiki_count": len(stale_wiki),
            "removed_workspace_link_count": len(removed_links),
        }
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply", "verify"))
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--plugin-root", type=Path, required=True)
    parser.add_argument("--builtin-reference-root", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "plan":
            result = plan_policy(args.data_root, args.plugin_root, args.builtin_reference_root)
        elif args.command == "apply":
            result = apply_policy(args.data_root, args.plugin_root, args.builtin_reference_root)
        else:
            result = verify_policy(args.data_root, args.plugin_root, args.builtin_reference_root)
    except (PolicyError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
