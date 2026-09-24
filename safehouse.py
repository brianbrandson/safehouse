#!/usr/bin/env python3
"""Create a lightweight pentest/lab Safehouse scaffold.

Examples:
  safehouse defaults show
  safehouse defaults set lab --path "$HOME/safehouse/labs"
  safehouse doctor
  safehouse new lab "City Council"
"""
from __future__ import annotations

import argparse
import configparser
import datetime as dt
import hashlib
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import getpass
from dataclasses import dataclass
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

__version__ = "0.1.0-alpha"

ABOUT_TEXT = """Safehouse

local-first workspaces for pentest labs and encrypted engagement work

Safehouse creates a consistent local scaffold for lab notes and VeraCrypt-backed
engagement workspaces.

Author: Brian Brandson
License: MIT
"""

FOLDERS = [
    "01_scans",
    "02_notes",
    "03_leads",
    "04_primitives",
    "05_findings",
    "08_reports",
    "99_archive",
]

RUN_NOTE_LOG_SECTION = """# Log

## {created}

HH:mm — action summary

Result:
Evidence:
Refs:
Next:
"""

NOTE_TEMPLATES = {
    "_safehouse/templates/lab-log-entry.md": """HH:mm — action summary

Result:
Evidence:
Refs:
Next:
""",
    "_safehouse/templates/engagement-log-entry.md": """YYYY-MM-DD HH:mm TZ — action summary

Result:
Evidence:
Refs:
Next:
""",
}

@dataclass(frozen=True)
class SafehouseRoots:
    container_dir: Path
    mount_dir: Path


@dataclass(frozen=True)
class SafehousePaths:
    display_name: str
    slug: str
    safehouse_id: str
    container_path: Path
    mount_path: Path


@dataclass(frozen=True)
class VeraCryptCall:
    argv: list[str]
    stdin: str | None = None

    def safe_display(self) -> str:
        return " ".join(self.argv)


VeraCryptRunner = Callable[[VeraCryptCall], str]


@dataclass(frozen=True)
class StatusLine:
    status: str
    record: SafehouseRecord
    path: str
    warning: str = ""


@dataclass(frozen=True)
class ResizeResult:
    record: SafehouseRecord
    old_container: Path
    file_count: int
    directory_count: int
    total_bytes: int
    manifest_sha256: str


SAFEHOUSE_ID_RE = re.compile(r"^sh-[0-9a-f]{8}$")
CATEGORIES = {"lab", "engagement"}
CATEGORY_DEFAULT_FIELDS = {"path", "storage", "container-size", "obsidian-profile"}
CATEGORY_DEFAULT_FLAG_DESTS = {
    "path": "path",
    "storage": "storage",
    "container_size": "container-size",
    "obsidian_profile": "obsidian-profile",
}
STORAGE_MODES = {"plain", "encrypted"}
SIZE_RE = re.compile(r"^[1-9][0-9]*[KMGTP]$")
SIZE_UNITS = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}
OBSIDIAN_IMPORT_MAX_FILES = 1000
OBSIDIAN_IMPORT_MAX_BYTES = 50 * 1024 * 1024



class SafehouseHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=34, width=100)
OBSIDIAN_IMPORT_ALLOWED_TOP_FILES = {
    "app.json",
    "appearance.json",
    "community-plugins.json",
    "core-plugins.json",
    "graph.json",
    "hotkeys.json",
    "templates.json",
}
OBSIDIAN_IMPORT_ALLOWED_DIRS = {"plugins", "snippets", "themes"}
OBSIDIAN_IMPORT_EXCLUDED_TOP = {"workspace.json", "workspace-mobile.json", "cache", "logs"}
SAFEHOUSE_PHASES = {
    "creating",
    "container_created",
    "mounted",
    "scaffolded",
    "profile_applied",
    "ready",
    "closed",
    "failed_setup",
}
STATE_ALLOWED_KEYS = {
    "safehouse_id",
    "display_name",
    "slug",
    "category",
    "storage",
    "container_path",
    "mount_path",
    "size",
    "filesystem",
    "phase",
    "created_at",
    "last_opened_at",
}
SECRET_FIELD_NAMES = {"password", "passphrase", "pim", "pin", "token", "secret", "keyfile"}


@dataclass(frozen=True)
class AppPaths:
    config_dir: Path
    config_file: Path
    state_file: Path
    profile_dir: Path

    @classmethod
    def from_home(cls, home: Path | None = None) -> "AppPaths":
        root = (home or Path.home()).expanduser()
        config_dir = root / ".config" / "safehouse"
        return cls(
            config_dir=config_dir,
            config_file=config_dir / "config.ini",
            state_file=config_dir / "state.json",
            profile_dir=config_dir / "obsidian-profiles",
        )


class ConfigStore:
    def __init__(self, paths: AppPaths | None = None) -> None:
        self.paths = paths or AppPaths.from_home()

    def home_root(self) -> Path:
        return self.paths.config_dir.parent.parent

    def builtin_category_defaults(self) -> dict[str, dict[str, str]]:
        base = self.home_root() / "safehouse"
        common = {"container-size": "512M", "obsidian-profile": "minimal"}
        return {
            "lab": {**common, "path": str(base / "labs"), "storage": "plain"},
            "engagement": {**common, "path": str(base / "engagements"), "storage": "encrypted"},
        }

    def configured_categories(self) -> set[str]:
        config = self._read()
        categories = set(self.builtin_category_defaults())
        for section in config.sections():
            if section.startswith("category."):
                category = section.removeprefix("category.")
                self._validate_category(category)
                categories.add(category)
        return categories

    def category_defaults(self, category: str) -> dict[str, str]:
        self._validate_category(category)
        config = self._read()
        section = f"category.{category}"
        if not config.has_section(section):
            return {}
        return dict(config.items(section))

    def effective_category_defaults(self, category: str) -> dict[str, str]:
        self._validate_category(category)
        base = self.home_root() / "safehouse"
        effective = {"path": str(base / category), "storage": "encrypted", "container-size": "512M", "obsidian-profile": "minimal"}
        effective.update(self.builtin_category_defaults().get(category, {}))
        effective.update(self.category_defaults(category))
        return effective

    def get_category_default(self, category: str, field: str) -> str:
        self._validate_category_default(category, field, "dummy", validate_value=False)
        return self.effective_category_defaults(category)[field]

    def set_category_default(self, category: str, field: str, value: str) -> None:
        self._validate_category_default(category, field, value)
        config = self._read()
        section = f"category.{category}"
        if not config.has_section(section):
            config.add_section(section)
        config.set(section, field, value)
        self._write(config)

    def clear_category_default(self, category: str, field: str) -> bool:
        self._validate_category(category)
        if field not in CATEGORY_DEFAULT_FIELDS:
            raise ValueError(f"unknown category default field: {field}")
        config = self._read()
        section = f"category.{category}"
        removed = config.has_section(section) and config.remove_option(section, field)
        self._write(config)
        return removed

    def clear_defaults(self) -> bool:
        config = self._read()
        removed = config.remove_section("defaults")
        for section in list(config.sections()):
            if section.startswith("category."):
                removed = config.remove_section(section) or removed
        self._write(config)
        return removed

    def _validate_category_default(self, category: str, field: str, value: str, validate_value: bool = True) -> None:
        self._validate_category(category)
        if field not in CATEGORY_DEFAULT_FIELDS:
            raise ValueError(f"unknown category default field: {field}")
        if validate_value and not value.strip():
            raise ValueError(f"{category}.{field} must not be empty")
        if validate_value and field == "storage" and value not in STORAGE_MODES:
            raise ValueError(f"{category}.storage must be plain or encrypted")
        if validate_value and field == "container-size" and not SIZE_RE.fullmatch(value):
            raise ValueError("container-size must look like 512M, 1G, or 2048M")
        if validate_value and field == "obsidian-profile":
            validate_profile_name(value)

    def _validate_category(self, category: str) -> None:
        normalized = slug_name(category)
        if normalized != category:
            raise ValueError("Safehouse category must be a lowercase hyphen identifier")


    def _read(self) -> configparser.ConfigParser:
        self._refuse_symlink(self.paths.config_dir)
        self._refuse_symlink(self.paths.config_file)
        config = configparser.ConfigParser()
        if self.paths.config_file.exists():
            config.read(self.paths.config_file, encoding="utf-8")
        return config

    def _write(self, config: configparser.ConfigParser) -> None:
        self._refuse_symlink(self.paths.config_dir)
        self._refuse_symlink(self.paths.config_file)
        self.paths.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.paths.config_dir.chmod(0o700)
        tmp = self.paths.config_file.with_suffix(".ini.tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            config.write(handle)
        tmp.chmod(0o600)
        tmp.replace(self.paths.config_file)
        self.paths.config_file.chmod(0o600)

    def _refuse_symlink(self, path: Path) -> None:
        if path.is_symlink():
            raise RuntimeError(f"refusing symlinked Safehouse config path: {path}")


@dataclass(frozen=True)
class SafehouseRecord:
    safehouse_id: str
    display_name: str
    slug: str
    category: str
    container_path: str
    mount_path: str
    size: str
    filesystem: str
    phase: str
    storage: str = "encrypted"
    created_at: str = ""
    last_opened_at: str = ""

    def __post_init__(self) -> None:
        if not SAFEHOUSE_ID_RE.fullmatch(self.safehouse_id):
            raise ValueError("invalid safehouse id")
        ConfigStore()._validate_category(self.category)
        if self.storage not in STORAGE_MODES:
            raise ValueError("storage must be plain or encrypted")
        if self.phase not in SAFEHOUSE_PHASES:
            raise ValueError(f"invalid safehouse phase: {self.phase}")

    def to_dict(self) -> dict[str, str]:
        return {
            "safehouse_id": self.safehouse_id,
            "display_name": self.display_name,
            "slug": self.slug,
            "category": self.category,
            "storage": self.storage,
            "container_path": self.container_path,
            "mount_path": self.mount_path,
            "size": self.size,
            "filesystem": self.filesystem,
            "phase": self.phase,
            "created_at": self.created_at,
            "last_opened_at": self.last_opened_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SafehouseRecord":
        data = dict(data)
        unknown = set(data) - STATE_ALLOWED_KEYS
        if unknown:
            raise ValueError(f"unknown state field(s): {', '.join(sorted(unknown))}")
        for key, value in data.items():
            if not isinstance(value, str):
                raise ValueError(f"state field must be a string: {key}")
        fields = {key: data.get(key, "") for key in STATE_ALLOWED_KEYS}
        if not fields.get("storage"):
            fields["storage"] = "plain" if not fields.get("container_path") else "encrypted"
        return cls(**fields)

    def with_phase(self, phase: str) -> "SafehouseRecord":
        data = self.to_dict()
        data["phase"] = phase
        return SafehouseRecord.from_dict(data)

    def with_opened_phase(self, phase: str = "ready") -> "SafehouseRecord":
        data = self.to_dict()
        data["phase"] = phase
        data["last_opened_at"] = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
        return SafehouseRecord.from_dict(data)


class StateStore:
    def __init__(self, paths: AppPaths | None = None) -> None:
        self.paths = paths or AppPaths.from_home()

    def records(self) -> list[SafehouseRecord]:
        raw = self._read_raw()
        safehouses = raw.get("safehouses", [])
        if not isinstance(safehouses, list):
            raise ValueError("state safehouses must be a list")
        return [SafehouseRecord.from_dict(cast(dict[str, Any], item)) for item in safehouses]

    def upsert(self, record: SafehouseRecord) -> None:
        records = [item for item in self.records() if item.safehouse_id != record.safehouse_id]
        records.append(record)
        self.write_raw({"safehouses": [item.to_dict() for item in records]})

    def replace(self, old_safehouse_id: str, record: SafehouseRecord) -> None:
        records = self.records()
        if not any(item.safehouse_id == old_safehouse_id for item in records):
            raise RuntimeError(f"missing Safehouse record to replace: {old_safehouse_id}")
        updated = [record if item.safehouse_id == old_safehouse_id else item for item in records]
        self.write_raw({"safehouses": [item.to_dict() for item in updated]})

    def remove(self, safehouse_id: str) -> None:
        records = self.records()
        remaining = [record for record in records if record.safehouse_id != safehouse_id]
        if len(remaining) == len(records):
            raise RuntimeError(f"missing Safehouse record to remove: {safehouse_id}")
        self.write_raw({"safehouses": [item.to_dict() for item in remaining]})

    def write_raw(self, payload: dict[str, object]) -> None:
        self._validate_no_secret_fields(payload)
        safehouses = payload.get("safehouses", [])
        if not isinstance(safehouses, list):
            raise ValueError("state safehouses must be a list")
        normalized: dict[str, object] = {
            "safehouses": [SafehouseRecord.from_dict(cast(dict[str, Any], item)).to_dict() for item in safehouses]
        }
        self._write_raw(normalized)

    def _read_raw(self) -> dict[str, object]:
        self._refuse_symlink(self.paths.config_dir)
        self._refuse_symlink(self.paths.state_file)
        if not self.paths.state_file.exists():
            return {"safehouses": []}
        with self.paths.state_file.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write_raw(self, payload: dict[str, object]) -> None:
        self._refuse_symlink(self.paths.config_dir)
        self._refuse_symlink(self.paths.state_file)
        self.paths.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.paths.config_dir.chmod(0o700)
        tmp = self.paths.state_file.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        tmp.chmod(0o600)
        tmp.replace(self.paths.state_file)
        self.paths.state_file.chmod(0o600)

    def _refuse_symlink(self, path: Path) -> None:
        if path.is_symlink():
            raise RuntimeError(f"refusing symlinked Safehouse state path: {path}")

    def _validate_no_secret_fields(self, value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key.lower() in SECRET_FIELD_NAMES:
                    raise ValueError(f"secret-like field is not allowed in state: {key}")
                self._validate_no_secret_fields(item)
        elif isinstance(value, list):
            for item in value:
                self._validate_no_secret_fields(item)


def app_paths_from_env() -> AppPaths:
    home = os.environ.get("SAFEHOUSE_HOME")
    return AppPaths.from_home(Path(home) if home else None)


def print_defaults(store: ConfigStore, category: str | None = None) -> None:
    categories = [category] if category else sorted(store.configured_categories())
    for category_name in categories:
        category_configured = store.category_defaults(category_name)
        category_effective = store.effective_category_defaults(category_name)
        for field in ("path", "storage", "container-size", "obsidian-profile"):
            source = "configured" if field in category_configured else "built-in"
            print(f"{category_name}.{field} = {category_effective[field]} ({source})")


def category_default_updates_from_args(args: argparse.Namespace) -> list[tuple[str, str, str]]:
    if not getattr(args, "category", None):
        return []
    updates: list[tuple[str, str, str]] = []
    for attr, field in CATEGORY_DEFAULT_FLAG_DESTS.items():
        value = getattr(args, attr, None)
        if value is not None:
            updates.append((args.category, field, value))
    return updates


def validate_profile_name(name: str) -> str:
    normalized = slug_name(name)
    if normalized != name:
        raise ValueError("obsidian profile name must be a lowercase hyphen identifier")
    return normalized


def obsidian_source_dir(source: str) -> Path:
    root = Path(source).expanduser()
    if root.is_symlink():
        raise RuntimeError(f"refusing symlinked obsidian profile source directory: {root}")
    candidate = root if root.name == ".obsidian" else root / ".obsidian"
    if candidate.is_symlink():
        raise RuntimeError(f"refusing symlinked obsidian profile source directory: {candidate}")
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise RuntimeError(f"missing .obsidian source directory: {resolved}")
    return resolved


def profile_path(paths: AppPaths, name: str) -> Path:
    return paths.profile_dir / validate_profile_name(name)


def profile_manifest_path(paths: AppPaths, name: str) -> Path:
    return paths.profile_dir / f"{validate_profile_name(name)}.import-manifest.json"


def should_copy_obsidian_profile_path(rel: Path) -> bool:
    parts = rel.parts
    if not parts:
        return False
    if parts[0] in OBSIDIAN_IMPORT_EXCLUDED_TOP:
        return False
    if len(parts) == 1:
        return parts[0] in OBSIDIAN_IMPORT_ALLOWED_TOP_FILES
    return parts[0] in OBSIDIAN_IMPORT_ALLOWED_DIRS


def inspect_obsidian_profile_source(source_dir: Path) -> tuple[list[Path], list[str]]:
    included: list[Path] = []
    excluded: list[str] = []
    for item in sorted(source_dir.rglob("*")):
        rel = item.relative_to(source_dir)
        if item.is_symlink():
            raise RuntimeError(f"refusing symlink in obsidian profile source: {rel}")
        if item.is_dir():
            if rel.parts and rel.parts[0] in OBSIDIAN_IMPORT_EXCLUDED_TOP:
                excluded.append(str(rel))
            continue
        if not item.is_file():
            raise RuntimeError(f"refusing special file in obsidian profile source: {rel}")
        if should_copy_obsidian_profile_path(rel):
            included.append(rel)
        else:
            excluded.append(str(rel))
    total_bytes = sum((source_dir / rel).stat().st_size for rel in included)
    if len(included) > OBSIDIAN_IMPORT_MAX_FILES:
        raise RuntimeError(f"obsidian profile import has too many files: {len(included)}")
    if total_bytes > OBSIDIAN_IMPORT_MAX_BYTES:
        raise RuntimeError(f"obsidian profile import is too large: {total_bytes} bytes")
    return included, sorted(set(excluded))


def copy_imported_obsidian_profile(source_dir: Path, dest: Path, files: list[Path]) -> list[dict[str, object]]:
    manifest_files: list[dict[str, object]] = []
    for rel in files:
        source = source_dir / rel
        target = dest / rel
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(source, target)
        data = source.read_bytes()
        manifest_files.append({
            "path": str(rel),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return manifest_files


def write_obsidian_import_manifest(paths: AppPaths, name: str, source_dir: Path, files: list[dict[str, object]], excluded: list[str]) -> Path:
    manifest = {
        "profile": validate_profile_name(name),
        "source": str(source_dir),
        "imported_files": files,
        "excluded": excluded,
        "warning": "community plugin code is user-supplied executable code; review it before reuse",
    }
    target = profile_manifest_path(paths, name)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    target.chmod(0o600)
    return target


def copy_obsidian_profile(paths: AppPaths, name: str, source: str, replace: bool = False) -> Path:
    dest = profile_path(paths, name)
    if dest.exists() and not replace:
        raise RuntimeError(f"obsidian profile already exists: {name}")
    if not dest.exists() and replace:
        raise RuntimeError(f"obsidian profile does not exist: {name}")
    if dest.is_symlink():
        raise RuntimeError(f"refusing symlinked obsidian profile: {dest}")
    source_dir = obsidian_source_dir(source)
    included, excluded = inspect_obsidian_profile_source(source_dir)
    paths.profile_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = paths.profile_dir / f".{validate_profile_name(name)}.tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(mode=0o700)
    manifest_files = copy_imported_obsidian_profile(source_dir, tmp, included)
    if replace:
        shutil.rmtree(dest)
    tmp.replace(dest)
    write_obsidian_import_manifest(paths, name, source_dir, manifest_files, excluded)
    return dest


def list_obsidian_profiles(paths: AppPaths) -> list[str]:
    if not paths.profile_dir.is_dir():
        return []
    return sorted(path.name for path in paths.profile_dir.iterdir() if path.is_dir() and not path.name.startswith("."))


def obsidian_profile_list_lines(paths: AppPaths, verbose: bool = False) -> list[str]:
    profiles = list_obsidian_profiles(paths)
    if not verbose:
        lines = ["Built-in Obsidian profiles:"]
        lines.append("  minimal    Minimal local Obsidian settings; no community plugins")
        lines.append("Imported Obsidian profiles:")
        if profiles:
            lines.extend(f"  {name}" for name in profiles)
        else:
            lines.append("  none")
        return lines
    lines = ["NAME       SOURCE     STATUS"]
    lines.append("minimal    built-in   available")
    for name in profiles:
        manifest = profile_manifest_path(paths, name)
        status = "imported" if manifest.is_file() else "manifest-missing"
        lines.append(f"{name:<10} imported   {status}")
    return lines


def community_plugins_from_profile(profile_root: Path) -> list[str]:
    plugin_list = profile_root / "community-plugins.json"
    if plugin_list.is_file():
        try:
            loaded = json.loads(plugin_list.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = []
        if isinstance(loaded, list):
            return sorted(item for item in loaded if isinstance(item, str))
    plugin_dir = profile_root / "plugins"
    if plugin_dir.is_dir():
        return sorted(path.name for path in plugin_dir.iterdir() if path.is_dir())
    return []


def show_obsidian_profile(paths: AppPaths, name: str) -> list[str]:
    if name == "minimal":
        return [
            "Profile: minimal",
            "Source: built-in",
            f"Imported files: {len(builtin_minimal_profile())}",
            "Excluded paths: 0",
            "Community plugins: none",
            "Manifest: built-in profile has no import manifest",
        ]
    dest = profile_path(paths, name)
    if not dest.is_dir():
        raise RuntimeError(f"obsidian profile does not exist: {name}")
    manifest_path = profile_manifest_path(paths, name)
    manifest: dict[str, object] = {}
    if manifest_path.is_file():
        with manifest_path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            manifest = loaded
    files = manifest.get("imported_files")
    excluded = manifest.get("excluded")
    file_count = len(files) if isinstance(files, list) else len([path for path in dest.rglob("*") if path.is_file()])
    excluded_count = len(excluded) if isinstance(excluded, list) else 0
    source = manifest.get("source") if isinstance(manifest.get("source"), str) else "unknown"
    warning = manifest.get("warning") if isinstance(manifest.get("warning"), str) else "community plugin code is user-supplied executable code; review it before reuse"
    plugins = community_plugins_from_profile(dest)
    return [
        f"Profile: {name}",
        "Source: imported",
        f"Source path: {source}",
        f"Imported files: {file_count}",
        f"Excluded paths: {excluded_count}",
        f"Community plugins: {', '.join(plugins) if plugins else 'none'}",
        f"Manifest: {manifest_path if manifest_path.is_file() else 'missing'}",
        f"Warning: {warning}",
    ]


def verify_obsidian_profile(paths: AppPaths, name: str) -> tuple[int, list[str]]:
    if name == "minimal":
        return 0, [
            "Profile: minimal",
            "OK built-in profile available",
        ]
    dest = profile_path(paths, name)
    if not dest.is_dir():
        raise RuntimeError(f"obsidian profile does not exist: {name}")
    manifest_path = profile_manifest_path(paths, name)
    if not manifest_path.is_file():
        return 1, [
            f"Profile: {name}",
            f"FAIL missing manifest: {manifest_path}",
            f"NEXT re-import with `safehouse obsidian-profile replace {name} --from SOURCE`",
        ]
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    imported_files = manifest.get("imported_files") if isinstance(manifest, dict) else None
    if not isinstance(imported_files, list):
        return 1, [
            f"Profile: {name}",
            f"Manifest: {manifest_path}",
            "FAIL manifest imported_files is missing or invalid",
            f"NEXT re-import with `safehouse obsidian-profile replace {name} --from SOURCE`",
        ]
    lines = [
        f"Profile: {name}",
        f"Manifest: {manifest_path}",
    ]
    failures = 0
    verified = 0
    for entry in imported_files:
        if not isinstance(entry, dict):
            failures += 1
            lines.append("FAIL invalid manifest entry")
            continue
        rel_text = entry.get("path")
        expected_hash = entry.get("sha256")
        expected_size = entry.get("size")
        if not isinstance(rel_text, str) or not isinstance(expected_hash, str) or not isinstance(expected_size, int):
            failures += 1
            lines.append("FAIL invalid manifest entry")
            continue
        rel = Path(rel_text)
        if rel.is_absolute() or ".." in rel.parts:
            failures += 1
            lines.append(f"FAIL unsafe manifest path: {rel_text}")
            continue
        target = dest / rel
        if target.is_symlink():
            failures += 1
            lines.append(f"FAIL symlink file: {rel_text}")
            continue
        if not target.is_file():
            failures += 1
            lines.append(f"FAIL missing file: {rel_text}")
            continue
        data = target.read_bytes()
        actual_hash = hashlib.sha256(data).hexdigest()
        drifted = False
        if len(data) != expected_size:
            failures += 1
            drifted = True
            lines.append(f"FAIL size mismatch: {rel_text}")
        if actual_hash != expected_hash:
            failures += 1
            drifted = True
            lines.append(f"FAIL hash mismatch: {rel_text}")
            continue
        if drifted:
            continue
        verified += 1
    if failures:
        lines.append(f"NEXT re-import with `safehouse obsidian-profile replace {name} --from SOURCE`")
        return 1, lines
    lines.append(f"OK imported files verified: {verified}")
    return 0, lines


def ensure_stored_obsidian_profile_safe(profile_root: Path) -> None:
    if profile_root.is_symlink():
        raise RuntimeError(f"refusing symlinked stored obsidian profile: {profile_root}")
    for item in sorted(profile_root.rglob("*")):
        rel = item.relative_to(profile_root)
        if item.is_symlink():
            raise RuntimeError(f"refusing symlink in stored obsidian profile: {rel}")
        if item.is_dir():
            continue
        if not item.is_file():
            raise RuntimeError(f"refusing special file in stored obsidian profile: {rel}")


def verify_all_obsidian_profiles(paths: AppPaths) -> tuple[int, list[str]]:
    names = ["minimal", *list_obsidian_profiles(paths)]
    exit_code = 0
    lines: list[str] = []
    for index, name in enumerate(names):
        profile_exit, profile_lines = verify_obsidian_profile(paths, name)
        if index:
            lines.append("")
        lines.extend(profile_lines)
        exit_code = max(exit_code, profile_exit)
    return exit_code, lines


def builtin_minimal_profile() -> dict[str, str]:
    return {
        "app.json": '{"alwaysUpdateLinks": true}\n',
        "appearance.json": '{"theme": "obsidian"}\n',
        "core-plugins.json": "[]\n",
        "hotkeys.json": "{}\n",
        "templates.json": json.dumps({"folder": "_safehouse/templates", "dateFormat": "YYYY-MM-DD", "timeFormat": "HH:mm"}, sort_keys=True) + "\n",
        "snippets/safehouse.css": "/* Safehouse local snippet hook. Keep reusable profiles client-free. */\n",
    }


def prepare_obsidian_profile_target(dest: Path) -> None:
    if dest.exists() and dest.is_symlink():
        raise RuntimeError(f"refusing symlinked .obsidian directory: {dest}")
    if dest.exists() and not dest.is_dir():
        raise RuntimeError(f"refusing existing non-directory .obsidian path: {dest}")
    if dest.exists() and any(dest.iterdir()):
        shutil.rmtree(dest)
    elif dest.exists():
        dest.rmdir()


def write_builtin_minimal_profile(dest: Path) -> Path:
    prepare_obsidian_profile_target(dest)
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    for rel, content in builtin_minimal_profile().items():
        target = dest / rel
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return dest


def apply_obsidian_profile(paths: AppPaths, name: str, target: str) -> Path:
    dest = Path(target).expanduser().resolve() / ".obsidian"
    if name == "minimal":
        return write_builtin_minimal_profile(dest)
    source = profile_path(paths, name)
    if not source.is_dir():
        raise RuntimeError(f"obsidian profile does not exist: {name}")
    ensure_stored_obsidian_profile_safe(source)
    verify_exit, verify_lines = verify_obsidian_profile(paths, name)
    if verify_exit != 0:
        detail = "; ".join(line for line in verify_lines if line.startswith("FAIL "))
        raise RuntimeError(f"obsidian profile failed verification before apply: {name}: {detail}")
    prepare_obsidian_profile_target(dest)
    shutil.copytree(source, dest, symlinks=False)
    return dest


def registered_obsidian_profile_target(paths: AppPaths, target: str) -> Path:
    root = Path(target).expanduser().resolve()
    for record in StateStore(paths).records():
        if Path(record.mount_path).expanduser().resolve() == root:
            if record.storage == "encrypted" and record.phase != "mounted":
                raise RuntimeError(f"refusing closed encrypted Safehouse target: {root}; mount it first")
            return root
    raise RuntimeError(f"refusing unregistered Safehouse root: {root}")


def dry_run_apply_obsidian_profile(paths: AppPaths, name: str, target: str) -> tuple[int, list[str]]:
    dest = Path(target).expanduser().resolve() / ".obsidian"
    if name != "minimal" and not profile_path(paths, name).is_dir():
        raise RuntimeError(f"obsidian profile does not exist: {name}")
    if dest.exists() and dest.is_symlink():
        return 1, [f"DRY-RUN refusing symlinked .obsidian directory: {dest}"]
    if dest.exists() and not dest.is_dir():
        return 1, [f"DRY-RUN refusing existing non-directory .obsidian path: {dest}"]
    if dest.exists() and any(dest.iterdir()):
        return 0, [f"DRY-RUN would replace existing .obsidian directory with obsidian profile {name}: {dest}"]
    return 0, [f"DRY-RUN would apply obsidian profile {name} to {dest}"]


def ensure_empty_dir(path: Path, label: str) -> None:
    if path.exists() and not path.is_dir():
        raise RuntimeError(f"{label} exists but is not a directory: {path}")
    if path.exists() and any(path.iterdir()):
        raise RuntimeError(f"refusing non-empty {label}: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def veracrypt_command_from_env() -> str:
    return os.environ.get("SAFEHOUSE_VERACRYPT", "veracrypt")


def mkfs_ext4_command_from_env() -> str:
    return os.environ.get("SAFEHOUSE_MKFS_EXT4", "mkfs.ext4")


def check_veracrypt(command: str) -> tuple[bool, str]:
    resolved = command if Path(command).is_file() else shutil.which(command)
    if not resolved:
        return False, "not found"
    try:
        result = subprocess.run(
            [resolved, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except OSError as exc:
        return False, str(exc)
    except subprocess.TimeoutExpired:
        return False, "version check timed out"
    output = (result.stdout or result.stderr).strip().splitlines()
    version = output[0] if output else resolved
    return result.returncode == 0, version


def check_mkfs_ext4(command: str) -> tuple[bool, str]:
    resolved = command if Path(command).is_file() else shutil.which(command)
    if not resolved:
        return False, "not found"
    try:
        result = subprocess.run(
            [resolved, "-V"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except OSError as exc:
        return False, str(exc)
    except subprocess.TimeoutExpired:
        return False, "version check timed out"
    output = (result.stdout or result.stderr).strip().splitlines()
    version = output[0] if output else resolved
    return result.returncode == 0, version


def obsidian_profile_exists(paths: AppPaths, name: str) -> bool:
    if name == "minimal":
        return True
    return profile_path(paths, name).is_dir()


def doctor_lines(paths: AppPaths, store: ConfigStore) -> tuple[int, list[str]]:
    lines: list[str] = []
    failures = 0

    try:
        category_defaults = {category: store.effective_category_defaults(category) for category in sorted(CATEGORIES)}
        lines.append(f"OK config {paths.config_file}")
    except (RuntimeError, ValueError, configparser.Error) as exc:
        lines.append(f"FAIL config {exc}")
        return 1, lines

    for category, fields in category_defaults.items():
        key = f"{category}.path"
        value = fields.get("path")
        if not value:
            failures += 1
            lines.append(f"FAIL default {key} is empty")
            lines.append(f"NEXT safehouse defaults {category} --path PATH")
        elif not Path(value).exists():
            lines.append(f"OK default {key} {value} (will create on first use)")
        elif not Path(value).is_dir():
            failures += 1
            lines.append(f"FAIL default {key} is not a directory: {value}")
        else:
            lines.append(f"OK default {key} {value}")
        storage = fields.get("storage")
        if storage not in STORAGE_MODES:
            failures += 1
            lines.append(f"FAIL default {category}.storage must be plain or encrypted")
            lines.append(f"NEXT safehouse defaults {category} --storage plain|encrypted")
        else:
            lines.append(f"OK default {category}.storage {storage}")
        size = fields.get("container-size")
        if not size or not SIZE_RE.fullmatch(size):
            failures += 1
            lines.append(f"FAIL default {category}.container-size must look like 512M, 1G, or 2048M")
            lines.append(f"NEXT safehouse defaults set {category} --container-size SIZE")
        else:
            lines.append(f"OK default {category}.container-size {size}")

        profile = fields.get("obsidian-profile") or "minimal"
        try:
            validate_profile_name(profile)
            if obsidian_profile_exists(paths, profile):
                profile_exit, profile_lines = verify_obsidian_profile(paths, profile)
                if profile_exit == 0:
                    lines.append(f"OK default {category}.obsidian-profile {profile}")
                else:
                    failures += 1
                    lines.append(f"FAIL default {category}.obsidian-profile {profile} manifest drift")
                    lines.extend(line for line in profile_lines if not line.startswith("Profile:"))
                    lines.append(f"NEXT safehouse obsidian-profile verify {profile}")
            else:
                failures += 1
                lines.append(f"FAIL default {category}.obsidian-profile {profile} does not exist")
                lines.append(f"NEXT safehouse obsidian-profile import {profile} --from SOURCE_PATH")
        except (ValueError, json.JSONDecodeError) as exc:
            failures += 1
            lines.append(f"FAIL default {category}.obsidian-profile {exc}")
            lines.append(f"NEXT safehouse defaults set {category} --obsidian-profile minimal")

    try:
        StateStore(paths).records()
        lines.append(f"OK state {paths.state_file}")
    except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
        failures += 1
        lines.append(f"FAIL state {exc}")


    ok, detail = check_veracrypt(veracrypt_command_from_env())
    if ok:
        lines.append(f"OK veracrypt {detail}")
    else:
        failures += 1
        lines.append(f"FAIL veracrypt {detail}")
        lines.append("NEXT install VeraCrypt or set SAFEHOUSE_VERACRYPT, then rerun: safehouse doctor")

    ok, detail = check_mkfs_ext4(mkfs_ext4_command_from_env())
    if ok:
        lines.append(f"OK mkfs.ext4 {detail}")
    else:
        failures += 1
        lines.append(f"FAIL mkfs.ext4 {detail}")
        lines.append("NEXT install e2fsprogs or set SAFEHOUSE_MKFS_EXT4, then rerun: safehouse doctor")

    return (0 if failures == 0 else 1), lines


def doctor_check_from_line(line: str) -> dict[str, str] | None:
    if line.startswith("OK "):
        parts = line.split(" ", 2)
        return {
            "status": "OK",
            "check": parts[1] if len(parts) > 1 else "",
            "detail": parts[2] if len(parts) > 2 else "",
        }
    if line.startswith("FAIL "):
        parts = line.split(" ", 2)
        return {
            "status": "FAIL",
            "check": parts[1] if len(parts) > 1 else "",
            "detail": parts[2] if len(parts) > 2 else "",
        }
    if line.startswith("MISSING default "):
        return {"status": "MISSING", "check": "default", "detail": line.removeprefix("MISSING default ")}
    return None


def json_doctor_report(exit_code: int, lines: list[str]) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    next_steps: list[str] = []
    info: list[str] = []
    for line in lines:
        if line.startswith("NEXT "):
            next_steps.append(line.removeprefix("NEXT "))
            continue
        if line.startswith("INFO "):
            info.append(line.removeprefix("INFO "))
            continue
        check = doctor_check_from_line(line)
        if check is not None:
            checks.append(check)
    return {"exit_code": exit_code, "checks": checks, "next": next_steps, "info": info}


def print_doctor(paths: AppPaths, store: ConfigStore, json_output: bool = False) -> int:
    exit_code, lines = doctor_lines(paths, store)
    if json_output:
        print(json.dumps(json_doctor_report(exit_code, lines), indent=2, sort_keys=True))
        return exit_code
    for line in lines:
        print(line)
    return exit_code


class VeraCryptAdapter:
    def __init__(self, command: str = "veracrypt", runner: VeraCryptRunner | None = None) -> None:
        self.command = command
        self.runner = runner or self._run

    def create_volume(self, container_path: Path, size: str, filesystem: str, password: str) -> str:
        if not SIZE_RE.fullmatch(size):
            raise ValueError("container size must look like 512M, 1G, or 2048M")
        container_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        argv = [
            self.command,
            "-t",
            "-c",
            str(container_path),
            f"--size={size}",
            "--volume-type=normal",
            "--encryption=AES",
            "--hash=SHA-512",
            f"--filesystem={filesystem}",
            "--stdin",
            "--non-interactive",
        ]
        return self._call(VeraCryptCall(argv=argv, stdin=f"{password}\n"), secrets=[password])

    def mount_volume(self, container_path: Path, mount_path: Path, password: str, read_only: bool = False) -> str:
        mount_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        argv = [
            self.command,
            "-t",
            str(container_path),
            str(mount_path),
            "--stdin",
            "--non-interactive",
            "--pim=0",
            "--protect-hidden=no",
        ]
        if read_only:
            argv.append("--mount-options=ro")
        output = self._call(VeraCryptCall(argv=argv, stdin=f"{password}\n"), secrets=[password])
        if not read_only:
            self._ensure_mount_writable_by_user(mount_path)
        return output

    def _ensure_mount_writable_by_user(self, mount_path: Path) -> None:
        if os.access(mount_path, os.W_OK):
            return
        argv = ["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(mount_path)]
        result = subprocess.run(argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(
                "mounted Safehouse is not writable by the current user and ownership fix failed: "
                f"{detail}\n"
                "NEXT run sudo -v first, then rerun Safehouse as your normal user."
            )

    def unmount(self, mount_path: Path) -> str:
        return self._call(
            VeraCryptCall(argv=[self.command, "-t", "--non-interactive", "--unmount", str(mount_path)]),
            secrets=[],
        )

    def list_mounted(self) -> str:
        return self._call(VeraCryptCall(argv=[self.command, "-t", "--list"]), secrets=[])

    def mounted(self) -> dict[Path, Path]:
        return parse_veracrypt_mounts(self.list_mounted())

    def _call(self, call: VeraCryptCall, secrets: list[str]) -> str:
        try:
            return self.runner(call)
        except RuntimeError as exc:
            raise RuntimeError(redact_text(str(exc), secrets)) from None

    def _run(self, call: VeraCryptCall) -> str:
        try:
            result = subprocess.run(
                call.argv,
                input=call.stdin,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
            )
        except OSError as exc:
            raise RuntimeError(f"failed to run VeraCrypt command: {call.safe_display()}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"VeraCrypt command timed out: {call.safe_display()}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            secrets = [call.stdin.strip()] if call.stdin else []
            if "Failed to obtain administrator privileges" in detail:
                detail = (
                    f"{detail}\n"
                    "NEXT run sudo -v first so VeraCrypt can use cached admin privileges; "
                    "do not run Safehouse itself with sudo, or config/state and created files may become root-owned."
                )
            raise RuntimeError(redact_text(f"VeraCrypt command failed: {call.safe_display()}: {detail}", secrets))
        return result.stdout


def redact_text(text: str, secrets: list[str]) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def parse_veracrypt_mounts(output: str) -> dict[Path, Path]:
    mounted: dict[Path, Path] = {}
    current_volume = ""
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            current_volume = ""
            continue
        lowered = line.lower()
        if lowered.startswith("volume:"):
            current_volume = line.split(":", 1)[1].strip()
            continue
        if lowered.startswith("mount directory:"):
            mount = line.split(":", 1)[1].strip()
            if current_volume and mount:
                mounted[Path(current_volume)] = Path(mount)
            continue
        if re.match(r"^\d+:", line):
            try:
                parts = shlex.split(line.split(":", 1)[1].strip())
            except ValueError:
                continue
            if len(parts) >= 3:
                volume = next((part for part in parts[:-1] if part.endswith(".hc")), parts[-2])
                mounted[Path(volume)] = Path(parts[-1])
    return mounted


def live_mounts_from_backend(backend: Any) -> dict[Path, Path] | None:
    mounted = getattr(backend, "mounted", None)
    if not callable(mounted):
        return None
    try:
        live_mounts = cast(dict[Path, Path], mounted())
    except RuntimeError:
        return None
    if backend.__class__.__name__ == "FakeVeraCryptBackend" and not live_mounts:
        return None
    return live_mounts


class FakeVeraCryptBackend:
    def __init__(self) -> None:
        self._mounted: dict[Path, Path] = {}
        self._volume_files: dict[Path, dict[Path, bytes | None]] = {}

    def create_volume(self, container_path: Path, size: str, filesystem: str, password: str) -> str:
        if container_path.exists():
            raise RuntimeError(f"refusing to overwrite existing container: {container_path}")
        if not SIZE_RE.fullmatch(size):
            raise ValueError("container size must look like 512M, 1G, or 2048M")
        container_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        container_path.write_text(f"fake veracrypt volume\nsize={size}\nfilesystem={filesystem}\n", encoding="utf-8")
        self._volume_files[container_path] = {}
        return "created"

    def mount_volume(self, container_path: Path, mount_path: Path, password: str, read_only: bool = False) -> str:
        if not container_path.is_file():
            raise RuntimeError(f"container does not exist: {container_path}")
        if mount_path.exists() and any(mount_path.iterdir()):
            raise RuntimeError(f"refusing non-empty mount path: {mount_path}")
        mount_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        for rel, content in self._volume_files.get(container_path, {}).items():
            target = mount_path / rel
            if content is None:
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.write_bytes(content)
        self._mounted[container_path] = mount_path
        return "mounted"

    def unmount(self, mount_path: Path) -> str:
        for container, mounted_at in list(self._mounted.items()):
            if mounted_at == mount_path:
                self._volume_files[container] = self._snapshot_mount_view(mount_path)
                del self._mounted[container]
                self._clear_mount_view(mount_path)
                return "unmounted"
        if path_has_safehouse_scaffold(mount_path):
            self._clear_mount_view(mount_path)
            return "unmounted"
        raise RuntimeError(f"mount path is not mounted: {mount_path}")

    def mounted(self) -> dict[Path, Path]:
        return dict(self._mounted)

    def _clear_mount_view(self, mount_path: Path) -> None:
        if not mount_path.is_dir():
            return
        for item in mount_path.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    def _snapshot_mount_view(self, mount_path: Path) -> dict[Path, bytes | None]:
        snapshot: dict[Path, bytes | None] = {}
        for item in sorted(mount_path.rglob("*")):
            rel = item.relative_to(mount_path)
            if item.is_dir():
                snapshot[rel] = None
            elif item.is_file():
                snapshot[rel] = item.read_bytes()
            else:
                raise RuntimeError(f"fake VeraCrypt mount contains unsupported entry: {rel}")
        return snapshot


def storage_mode_for(config: ConfigStore, category: str, storage_override: str | None = None) -> str:
    config._validate_category(category)
    if storage_override is not None:
        if storage_override not in STORAGE_MODES:
            raise ValueError("storage must be plain or encrypted")
        return storage_override
    return config.get_category_default(category, "storage")


def roots_from_defaults(store: ConfigStore, category: str, path: str | None = None) -> SafehouseRoots:
    category_root = Path(path or store.get_category_default(category, "path")).expanduser().resolve()
    return SafehouseRoots(
        container_dir=category_root,
        mount_dir=category_root,
    )


def plain_safehouse_paths(store: ConfigStore, category: str, display_name: str, safehouse_id: str, path: str | None = None) -> SafehousePaths:
    root = Path(path or store.get_category_default(category, "path")).expanduser().resolve()
    slug = slug_name(display_name)
    return SafehousePaths(
        display_name=display_name.strip(),
        slug=slug,
        safehouse_id=safehouse_id,
        container_path=Path(""),
        mount_path=root / slug,
    )


def plain_lab_paths(store: ConfigStore, display_name: str, safehouse_id: str) -> SafehousePaths:
    return plain_safehouse_paths(store, "lab", display_name, safehouse_id)


def slug_name(name: str) -> str:
    if any(ord(ch) < 32 for ch in name):
        raise ValueError("safehouse name must not contain control characters")
    raw = name.strip()
    if not raw or raw in {".", ".."}:
        raise ValueError("safehouse name must not be empty, '.' or '..'")
    if "/" in raw or "\\" in raw:
        raise ValueError("safehouse name must not contain path separators")
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", raw.lower()).strip("-")
    cleaned = re.sub(r"-+", "-", cleaned)
    if not cleaned or cleaned in {".", ".."}:
        raise ValueError("safehouse name must contain letters or numbers")
    return cleaned


def new_safehouse_id(rng: Callable[[int], bytes] = secrets.token_bytes) -> str:
    return f"sh-{rng(4).hex()}"


def container_filename(safehouse_id: str) -> str:
    if not SAFEHOUSE_ID_RE.fullmatch(safehouse_id):
        raise ValueError("safehouse id must look like sh-7f3a9c21")
    return f"{safehouse_id}.hc"


def size_to_bytes(size: str) -> int:
    if not SIZE_RE.fullmatch(size):
        raise ValueError("container size must look like 512M, 1G, or 2048M")
    return int(size[:-1]) * SIZE_UNITS[size[-1]]


def derive_safehouse_paths(roots: SafehouseRoots, display_name: str, safehouse_id: str | None = None) -> SafehousePaths:
    chosen_id = safehouse_id or new_safehouse_id()
    slug = slug_name(display_name)
    safehouse_root = roots.container_dir / slug
    return SafehousePaths(
        display_name=display_name.strip(),
        slug=slug,
        safehouse_id=chosen_id,
        container_path=safehouse_root / container_filename(chosen_id),
        mount_path=safehouse_root / "mount",
    )


def record_for_paths(
    paths: SafehousePaths,
    category: str,
    size: str,
    filesystem: str,
    phase: str,
    storage: str = "encrypted",
) -> SafehouseRecord:
    now = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
    return SafehouseRecord(
        safehouse_id=paths.safehouse_id,
        display_name=paths.display_name,
        slug=paths.slug,
        category=category,
        storage=storage,
        container_path="" if storage == "plain" and paths.container_path == Path("") else str(paths.container_path),
        mount_path=str(paths.mount_path),
        size=size,
        filesystem=filesystem,
        phase=phase,
        created_at=now,
        last_opened_at="",
    )


def today() -> str:
    return dt.date.today().isoformat()


def run_note(name: str, category: str, real: bool) -> str:
    created = today()
    tags = "engagement, pentest" if real else "lab"
    return f"""---
category: {category}
status: in-progress
created: {created}
tags: [{tags}]
---

# {name}

**Status:** In Progress

## Current State

Current access:
Next safe test:
Open question / blocker:
Cleanup needed: none known yet

## Description

Short description.

## Scope

- Target IP / CIDR:
- Domain:
- Web app:
- Other assets:

{RUN_NOTE_LOG_SECTION.format(created=created).rstrip()}
"""


def access_note(real: bool) -> str:
    created = today()
    warning = (
        "For real engagements: this file is expected to live inside the encrypted Safehouse container. Plaintext secrets may live here only while this encrypted Safehouse is mounted and the engagement storage policy allows it. Do not paste secrets into chat, tickets, reports, reusable notes, or unencrypted exports. Close the Safehouse when not in use."
        if real else
        "For labs: credentials, hashes, tokens, tickets, sessions, and loot references may live here directly. Keep them out of reusable notes, chat, public screenshots, and reports unless intentionally sanitized."
    )
    return f"""---
type: access-ledger
status: active
created: {created}
tags: [access-ledger]
---

# Access Ledger

{warning}

| Username / Principal | Secret / Hash / Token              | Realm / Host            | Type                                                  | Source / Evidence      | Validated On                                        | Access / Privilege | Notes                     | Status |
| -------------------- | ---------------------------------- | ----------------------- | ----------------------------------------------------- | ---------------------- | --------------------------------------------------- | ------------------ | ------------------------- | ------ |
| user                 | password / hash / token or ref     | domain / host / app     | password / hash / ticket / cert / session / account   | where it came from     | SMB / LDAP / WinRM / RDP / Kerberos / HTTP / host   | unknown            | caveat / next use         | active |

## Cleanup / Rotation

| Item | Action Needed | Owner | Status |
|---|---|---|---|
|  |  |  |  |
"""


def readme(name: str, real: bool) -> str:
    container_note = "\nThis Safehouse is intended to live inside a mounted VeraCrypt container for real engagements. Close it when not in use.\n" if real else ""
    return f"""# {name}
{container_note}
## Structure

- `00_run.md` — main heading-based path/story and session handoffs
- `00_access.md` — access/credential/capability ledger
- `01_scans/` — raw discovery/enumeration output
- `02_notes/` — interpreted notes and larger command notes
- `03_leads/` — durable hypotheses only
- `04_primitives/` — confirmed capabilities only
- `05_findings/` — finding drafts
- `08_reports/` — reports and exports
- `99_archive/` — clutter, duplicates, superseded material
"""


def build_parser(prog: str = "safehouse") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        allow_abbrev=False,
        formatter_class=SafehouseHelpFormatter,
        description="Safehouse is a personal local operator tool for lab and engagement Safehouses.",
        epilog="""Config/state: ~/.config/safehouse/
No passwords in argv, env, config, state, or logs.

Examples:
  safehouse defaults show
  safehouse defaults set lab --path "$HOME/safehouse/labs"
  safehouse defaults set engagement --path "$HOME/safehouse/engagements"
  safehouse defaults set engagement --container-size 2G
  safehouse new lab "PortSwigger SQLi"
  safehouse new engagement "ACME External"
  safehouse status
  safehouse doctor""",
    )
    parser.add_argument("--version", action="version", version=f"{prog} {__version__}")
    parser.add_argument("--about", action="store_true", help="show Safehouse identity, purpose, author, and license")
    sub = parser.add_subparsers(dest="cmd", metavar="COMMAND")
    new = sub.add_parser(
        "new",
        help="create a new Safehouse",
        formatter_class=SafehouseHelpFormatter,
        description="Create a lab or engagement Safehouse from configured defaults.",
        epilog="""Defaults:
  lab: plain Safehouse created under lab.path
  engagement: opaque encrypted .hc container file created under engagement.path/SLUG/;
              readable Safehouse mounted at engagement.path/SLUG/mount/

For example, "ACME External" becomes:
  category root: engagement.path
  container file: acme-external/sh-7f3a9c21.hc
  mounted Safehouse: acme-external/mount/
  Obsidian profile: configured obsidian-profile, or built-in minimal

One-time overrides:
  --path, --storage, --container-size, and --obsidian-profile affect only this new Safehouse;
  defaults stay unchanged.

Secrets:
  Prompts for VeraCrypt password; never pass it as an argument.

Examples:
  safehouse defaults show
  safehouse new lab --dry-run "PortSwigger SQLi"
  safehouse new lab "PortSwigger SQLi"
  safehouse new engagement --dry-run "ACME External"
  safehouse new engagement --path "$HOME/client-safehouses" "ACME External"
  safehouse new engagement "ACME External"
  safehouse status""",
    )
    new.add_argument("--dry-run", action="store_true", help="preview derived paths and checks without creating files, containers, mounts, or state")
    new.add_argument("--json", action="store_true", help="with --dry-run, print a scriptable creation plan")
    new.add_argument("--path", metavar="PATH", help="one-time category root for this Safehouse; does not change defaults")
    new.add_argument("--storage", choices=sorted(STORAGE_MODES), metavar="MODE", help="one-time storage mode for this Safehouse; does not change defaults")
    new.add_argument("--container-size", metavar="SIZE", help="one-time encrypted container size, such as 512M or 2G; does not change defaults")
    new.add_argument("--obsidian-profile", metavar="PROFILE", help="one-time Obsidian profile for this Safehouse; does not change defaults")
    new.add_argument("category", choices=sorted(CATEGORIES), help="Safehouse category")
    new.add_argument("name", help="display name stored in local state; filesystem artifacts use opaque IDs")
    defaults = sub.add_parser(
        "defaults",
        help="manage Safehouse local defaults",
        formatter_class=SafehouseHelpFormatter,
        description="Show or change non-secret local defaults used by routine Safehouse commands.",
        epilog="""Config/state: ~/.config/safehouse/
Built-in category defaults work without setup. Use flags here to override only what you want to change per category.

Available settings:
  CATEGORY.path             category root for future Safehouses
  CATEGORY.storage          storage mode for future Safehouses
  CATEGORY.container-size   size for future encrypted containers, such as 512M or 2G
  CATEGORY.obsidian-profile Obsidian profile copied into each new Safehouse

Examples:
  safehouse defaults show
  safehouse defaults set lab --path "$HOME/safehouse/labs" --storage plain --obsidian-profile minimal
  safehouse defaults set engagement --path "$HOME/safehouse/engagements" --storage encrypted --container-size 2G
  safehouse defaults clear lab --path --container-size
  safehouse defaults clear --all""",
    )
    defaults_sub = defaults.add_subparsers(dest="defaults_cmd", metavar="[command]")
    defaults_show = defaults_sub.add_parser("show", help="show configured and built-in defaults")
    defaults_show.add_argument("category", nargs="?", choices=sorted(CATEGORIES), metavar="CATEGORY", help="show defaults for lab or engagement")
    defaults_set = defaults_sub.add_parser(
        "set",
        help="set category-specific defaults",
        formatter_class=SafehouseHelpFormatter,
        epilog="""Available settings:
  CATEGORY --path PATH              category root for future Safehouses in that category
  CATEGORY --storage MODE           storage mode for future Safehouses in that category
  CATEGORY --container-size SIZE    size for future encrypted containers, such as 512M or 2G
  CATEGORY --obsidian-profile NAME  Obsidian profile copied into each new Safehouse in that category

Examples:
  safehouse defaults set lab --path "$HOME/safehouse/labs" --storage plain
  safehouse defaults set engagement --path "$HOME/safehouse/engagements" --storage encrypted --container-size 2G
  safehouse defaults clear lab --obsidian-profile
  safehouse defaults clear --all""",
    )
    defaults_set.add_argument("category", choices=sorted(CATEGORIES), metavar="CATEGORY", help="lab or engagement category to configure")
    defaults_set.add_argument("--path", metavar="PATH", help="set root path for future Safehouses in CATEGORY")
    defaults_set.add_argument("--storage", choices=sorted(STORAGE_MODES), metavar="MODE", help="set storage mode for future Safehouses in CATEGORY")
    defaults_set.add_argument("--container-size", metavar="SIZE", help="set size for future encrypted containers, such as 512M or 2G")
    defaults_set.add_argument("--obsidian-profile", metavar="PROFILE", help="set Obsidian profile copied into each new Safehouse")
    defaults_clear = defaults_sub.add_parser("clear", help="revert category settings, or all settings with --all, to built-in defaults")
    defaults_clear.add_argument("target", nargs="?", choices=sorted(CATEGORIES), metavar="CATEGORY", help="lab or engagement category to revert when used with field flags")
    defaults_clear.add_argument("--path", action="store_true", help="clear the category path override")
    defaults_clear.add_argument("--storage", action="store_true", help="clear the category storage override")
    defaults_clear.add_argument("--container-size", action="store_true", help="clear the category container-size override")
    defaults_clear.add_argument("--obsidian-profile", action="store_true", help="clear the category obsidian-profile override")
    defaults_clear.add_argument("--all", action="store_true", help="revert all configured settings to built-in defaults")
    profile = sub.add_parser(
        "obsidian-profile",
        help="manage local Obsidian profiles",
        formatter_class=SafehouseHelpFormatter,
        description="Manage local reusable Obsidian settings profiles; import stores a reusable copy; apply writes it to a Safehouse.",
        epilog="""Profile store: ~/.config/safehouse/obsidian-profiles/NAME
Names must be lowercase hyphen identifiers. Import/replace copies reusable .obsidian config only, not vault notes.

Workflow:
  import   stores a named local copy under the Safehouse profile store; it does not touch Safehouses
  show     summarizes the stored copy without dumping config contents
  verify   checks the stored copy still matches its manifest before trust/apply
  apply    writes a stored profile into one Safehouse; safehouse new applies the configured default profile

Examples:
  safehouse obsidian-profile import work --from /path/to/vault
  safehouse obsidian-profile replace work --from /path/to/updated-vault
  safehouse obsidian-profile list
  safehouse obsidian-profile show minimal
  safehouse obsidian-profile verify work
  safehouse obsidian-profile verify --all
  safehouse obsidian-profile apply --dry-run work --to /path/to/safehouse
  safehouse obsidian-profile apply work --to /path/to/safehouse""",
    )
    profile_sub = profile.add_subparsers(dest="profile_cmd", required=True)
    profile_import = profile_sub.add_parser(
        "import",
        help="store a reusable copy from a vault .obsidian directory",
        formatter_class=SafehouseHelpFormatter,
        description="Copy only reusable .obsidian config into the Safehouse profile store.",
        epilog="""What it does:
  Reads SOURCE as either a vault root or a direct .obsidian directory.
  Copies allowlisted settings/snippets/themes/plugins into ~/.config/safehouse/obsidian-profiles/NAME.
  Writes NAME.import-manifest.json with file sizes and hashes.
  Does not apply the profile to any existing Safehouse.

Next:
  Then set it as a default or apply it explicitly.
  safehouse defaults set lab --obsidian-profile NAME
  safehouse obsidian-profile apply NAME --to /path/to/safehouse

Safety:
  Import refuses symlinks/special files and excludes volatile Obsidian layout/cache/log state.
  Community plugin code is copied as user-supplied executable code; review it before reuse.""",
    )
    profile_import.add_argument("name", help="profile name")
    profile_import.add_argument("--from", dest="source", required=True, help="vault root or .obsidian directory")
    profile_replace = profile_sub.add_parser(
        "replace",
        help="replace a stored imported profile from a fresh source",
        formatter_class=SafehouseHelpFormatter,
        description="Replace an existing stored imported profile with a fresh copy from SOURCE.",
        epilog="""Use this when verify reports drift or when you intentionally updated your sanitized source profile.
It rewrites the stored copy and import manifest, but still does not apply to Safehouses by itself.""",
    )
    profile_replace.add_argument("name", help="existing profile name")
    profile_replace.add_argument("--from", dest="source", required=True, help="vault root or .obsidian directory")
    profile_list = profile_sub.add_parser("list", help="list built-in and imported Obsidian profiles")
    profile_list.add_argument("--verbose", action="store_true", help="include source and manifest status without config contents")
    profile_show = profile_sub.add_parser("show", help="summarize a stored Obsidian profile safely")
    profile_show.add_argument("name", help="profile name, including built-in minimal")
    profile_verify = profile_sub.add_parser(
        "verify",
        help="check a stored imported profile against its manifest",
        formatter_class=SafehouseHelpFormatter,
        description="Check a stored imported profile against its import manifest.",
        epilog="""Why:
  Imported profiles are ordinary local files under ~/.config/safehouse.
  Verify detects missing files, edited files, hash/size drift, and unsafe manifest paths.
  Use this before trusting or applying a copied profile; apply runs this check automatically.

Examples:
  safehouse obsidian-profile verify work
  safehouse obsidian-profile verify --all

Recovery:
  safehouse obsidian-profile replace work --from SOURCE""",
    )
    profile_verify.add_argument("name", nargs="?", help="profile name, including built-in minimal")
    profile_verify.add_argument("--all", action="store_true", help="verify built-in minimal plus all imported profiles")
    profile_apply = profile_sub.add_parser(
        "apply",
        help="write a stored profile into one Safehouse",
        formatter_class=SafehouseHelpFormatter,
        description="Apply a stored Obsidian profile by creating .obsidian/ inside one Safehouse.",
        epilog="""Use this for an existing registered Safehouse. Encrypted targets must be mounted first.
New Safehouses get the configured default profile automatically. Replacing an existing
.obsidian/ directory requires --dry-run followed by --yes-replace.""",
    )
    profile_apply.add_argument("--dry-run", action="store_true", help="preview whether .obsidian would be created, replaced, or refused")
    profile_apply.add_argument("--yes-replace", action="store_true", help="confirm replacement of an existing .obsidian directory")
    profile_apply.add_argument("name", help="profile name")
    profile_apply.add_argument("--to", dest="to_target", required=True, help="registered Safehouse root that should receive .obsidian/")

    list_cmd = sub.add_parser(
        "list",
        help="list known Safehouses",
        formatter_class=SafehouseHelpFormatter,
        description="List known Safehouses. This is inventory only; use status for health.",
        epilog="""Safehouse types:
  lab         plain by default
  engagement  encrypted by default

Use `safehouse status` when you need filesystem and VeraCrypt health checks.

Examples:
  safehouse list
  safehouse list --lab
  safehouse list --engagement
  safehouse list --json
  safehouse status""",
    )
    list_filter = list_cmd.add_mutually_exclusive_group()
    list_filter.add_argument("--lab", action="store_true", help="show only lab Safehouses")
    list_filter.add_argument("--engagement", action="store_true", help="show only engagement Safehouses")
    list_filter.add_argument("--category", choices=sorted(CATEGORIES), metavar="CATEGORY", help="show only one Safehouse category")
    list_cmd.add_argument("--storage", choices=sorted(STORAGE_MODES), metavar="MODE", help="show only one storage mode")
    list_cmd.add_argument("--json", action="store_true", help="print scriptable JSON inventory instead of columns")
    status_cmd = sub.add_parser(
        "status",
        help="check known Safehouses against local filesystem state",
        formatter_class=SafehouseHelpFormatter,
        description="Check known Safehouses against filesystem and VeraCrypt health.",
        epilog="""Output uses OK/WARN/NEXT recovery guidance for mounted, closed, stale, missing, and blocked paths.
Status is local operational truth, not an encryption or scope attestation.

Examples:
  safehouse status
  safehouse status --lab
  safehouse status --engagement
  safehouse status --json
  safehouse list""",
    )
    status_filter = status_cmd.add_mutually_exclusive_group()
    status_filter.add_argument("--lab", action="store_true", help="check only lab Safehouses")
    status_filter.add_argument("--engagement", action="store_true", help="check only engagement Safehouses")
    status_filter.add_argument("--category", choices=sorted(CATEGORIES), metavar="CATEGORY", help="check only one Safehouse category")
    status_cmd.add_argument("--storage", choices=sorted(STORAGE_MODES), metavar="MODE", help="check only one storage mode")
    status_cmd.add_argument("--json", action="store_true", help="print scriptable JSON health instead of columns")
    mount = sub.add_parser(
        "mount",
        help="mount an encrypted Safehouse",
        formatter_class=SafehouseHelpFormatter,
        description="Mount a known encrypted Safehouse by id, exact name, or slug.",
        epilog="""Safety:
  Prompts once for VeraCrypt password.
  Refuses plain labs and occupied mount paths.
  If blocked, run safehouse status before manual recovery.

Examples:
  safehouse status
  safehouse mount "ACME External"
  safehouse mount sh-7f3a9c21""",
    )
    mount.add_argument("selector", help="safehouse id, exact display name, or slug")
    unmount = sub.add_parser(
        "unmount",
        help="unmount an encrypted Safehouse",
        formatter_class=SafehouseHelpFormatter,
        description="Unmount a known encrypted Safehouse with normal VeraCrypt unmount.",
        epilog="""Safety:
  Manual unmount only. No force unmount or auto-unmount in Stage 1.

Examples:
  safehouse status
  safehouse unmount "ACME External"
  safehouse unmount sh-7f3a9c21""",
    )
    unmount.add_argument("selector", help="safehouse id, exact display name, or slug")
    remove = sub.add_parser(
        "remove",
        help="permanently remove a closed Safehouse",
        formatter_class=SafehouseHelpFormatter,
        description="Permanently remove a known Safehouse and its active local artifact.",
        epilog="""Safety:
  Start with --dry-run. Real removal requires --yes.
  Encrypted Safehouses must be unmounted first. No force removal exists.
  Recognized encrypted Safehouse directories remove their active and superseded .hc files together.
  Unexpected directory contents cause a refusal instead of deletion.

Examples:
  safehouse remove "Old Lab" --dry-run
  safehouse remove "Old Lab" --yes
  safehouse unmount "Old Client"
  safehouse remove "Old Client" --dry-run
  safehouse remove "Old Client" --yes""",
    )
    remove.add_argument("selector", help="safehouse id, exact display name, or slug")
    remove.add_argument("--dry-run", action="store_true", help="preview removal without deleting artifacts or state")
    remove.add_argument("--yes", action="store_true", help="explicitly confirm permanent removal after reviewing --dry-run")
    resize = sub.add_parser(
        "resize",
        help="resize an encrypted Safehouse by verified copy-forward replacement",
        formatter_class=SafehouseHelpFormatter,
        description="Create and switch to a verified no-overwrite replacement VeraCrypt container.",
        epilog="""Safety:
  --dry-run previews only. Without it, Safehouse copy-forwards into a new container,
  verifies every path/hash/total, and keeps the old container by default.
  Supports growth and archive shrink; shrink preflights payload and filesystem margin.

Examples:
  safehouse resize "ACME External" --to-size 2G --dry-run
  safehouse resize sh-7f3a9c21 --to-size 256M --dry-run""",
    )
    resize.add_argument("selector", help="encrypted safehouse id, exact display name, or slug")
    resize.add_argument("--to-size", required=True, help="replacement container size such as 256M, 1G, or 2048M")
    resize.add_argument("--dry-run", action="store_true", help="preview only; do not create, mount, copy, or write state")
    resize.add_argument("--json", action="store_true", help="print scriptable dry-run resize plan")
    resize.add_argument("--delete-old", action="store_true", help="delete the superseded source container only after verified state switch")
    doctor = sub.add_parser(
        "doctor",
        help="check Safehouse local health",
        formatter_class=SafehouseHelpFormatter,
        description="Check Safehouse config, effective defaults, state readability, Obsidian profile, VeraCrypt CLI, and mkfs.ext4.",
        epilog="""Prints copy-pasteable NEXT lines for VeraCrypt setup and recovery work.

Examples:
  safehouse doctor
  safehouse doctor --json""",
    )
    doctor.add_argument("--json", action="store_true", help="print scriptable JSON checks instead of lines")
    return parser


def create_safehouse_scaffold(category: str, name: str, base: str) -> Path:
    root = Path(base).expanduser().resolve() / slug_name(name)
    return scaffold_safehouse_root(root, category, name)


def write_note_templates(root: Path) -> None:
    for rel, content in NOTE_TEMPLATES.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def scaffold_root_is_available(root: Path) -> bool:
    if not root.exists():
        return True
    entries = list(root.iterdir())
    if not entries:
        return True
    return len(entries) == 1 and entries[0].name == "lost+found" and entries[0].is_dir()


def scaffold_safehouse_root(root: Path, category: str, name: str) -> Path:
    real = category == "engagement"
    if not scaffold_root_is_available(root):
        raise SystemExit(f"Refusing to write into non-empty directory: {root}")
    root.mkdir(parents=True, exist_ok=True)

    for folder in FOLDERS:
        d = root / folder
        d.mkdir(exist_ok=True)
        (d / ".gitkeep").touch(exist_ok=True)

    files = {
        "00_run.md": run_note(name, category, real),
        "00_access.md": access_note(real),
        "README.md": readme(name, real),
    }
    for rel, content in files.items():
        p = root / rel
        if p.exists() and p.stat().st_size:
            raise SystemExit(f"Refusing to overwrite existing file: {p}")
        p.write_text(content, encoding="utf-8")
    write_note_templates(root)
    return root


def backend_from_env() -> Any:
    if os.environ.get("SAFEHOUSE_BACKEND") == "fake":
        return FakeVeraCryptBackend()
    return VeraCryptAdapter(command=veracrypt_command_from_env())


def refresh_admin_credentials_for_backend(backend: Any) -> None:
    if not isinstance(backend, VeraCryptAdapter) or os.getuid() == 0:
        return
    print("Enter your sudo password for this VeraCrypt operation.", file=sys.stderr)
    try:
        result = subprocess.run(["sudo", "-v"], check=False, timeout=120)
    except OSError as exc:
        raise RuntimeError(f"failed to refresh sudo credentials before VeraCrypt: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("timed out refreshing sudo credentials before VeraCrypt") from exc
    if result.returncode != 0:
        raise RuntimeError(
            "sudo credential refresh failed before VeraCrypt; run Safehouse as your normal user, "
            "but enter the sudo prompt when using encrypted Safehouses"
        )


def read_new_password() -> str:
    if not sys.stdin.isatty():
        raise RuntimeError("VeraCrypt input requires an interactive terminal")
    first = getpass.getpass("VeraCrypt encryption password: ")
    second = getpass.getpass("Confirm VeraCrypt encryption password: ")
    if not first:
        raise ValueError("VeraCrypt input must not be empty")
    if first != second:
        raise ValueError("VeraCrypt confirmation did not match")
    return first


def read_mount_password() -> str:
    if not sys.stdin.isatty():
        raise RuntimeError("VeraCrypt input requires an interactive terminal")
    password = getpass.getpass("VeraCrypt encryption password: ")
    if not password:
        raise ValueError("VeraCrypt input must not be empty")
    return password


def inventory_path(record: SafehouseRecord) -> str:
    return record.mount_path or record.container_path


def category_filter_from_flags(lab_only: bool = False, engagement_only: bool = False, category: str | None = None) -> str | None:
    if category:
        if lab_only or engagement_only:
            raise ValueError("use either --category or --lab/--engagement, not both")
        return category
    if lab_only:
        return "lab"
    if engagement_only:
        return "engagement"
    return None


def filter_records(records: list[SafehouseRecord], category: str | None = None, storage: str | None = None) -> list[SafehouseRecord]:
    filtered = list(records)
    if category is not None:
        filtered = [record for record in filtered if record.category == category]
    if storage is not None:
        filtered = [record for record in filtered if record.storage == storage]
    return filtered


def format_empty_safehouses() -> list[str]:
    return [
        "No Safehouses yet.",
        "",
        "Create one:",
        "  safehouse new lab \"Dogfood Lab\"",
        "  safehouse new engagement \"Client Name\"",
    ]


def format_inventory(records: list[SafehouseRecord], state_path: Path | None = None, category: str | None = None, storage: str | None = None) -> list[str]:
    del state_path
    records = filter_records(records, category=category, storage=storage)
    if not records:
        return format_empty_safehouses()
    lines = ["ID          CATEGORY    STORAGE    PHASE   NAME         PATH"]
    for record in sorted(records, key=lambda item: (item.category, item.display_name.lower(), item.safehouse_id)):
        lines.append(
            f"{record.safehouse_id:<11} "
            f"{record.category:<11} "
            f"{record.storage:<10} "
            f"{record.phase:<7} "
            f"{record.display_name:<12} "
            f"{inventory_path(record)}"
        )
    return lines


def sorted_inventory_records(records: list[SafehouseRecord]) -> list[SafehouseRecord]:
    return sorted(records, key=lambda item: (item.category, item.display_name.lower(), item.safehouse_id))


def json_inventory(records: list[SafehouseRecord], category: str | None = None, storage: str | None = None) -> dict[str, object]:
    safehouses: list[dict[str, str]] = []
    for record in sorted_inventory_records(filter_records(records, category=category, storage=storage)):
        item = record.to_dict()
        item["safehouse_path"] = inventory_path(record)
        safehouses.append(item)
    return {"count": len(safehouses), "safehouses": safehouses}


def print_inventory(state: StateStore, json_output: bool = False, category: str | None = None, storage: str | None = None) -> None:
    records = state.records()
    if json_output:
        print(json.dumps(json_inventory(records, category=category, storage=storage), indent=2, sort_keys=True))
        return
    for line in format_inventory(records, state.paths.state_file, category=category, storage=storage):
        print(line)


def path_has_safehouse_scaffold(path: Path) -> bool:
    return (path / "00_run.md").is_file() and (path / "00_access.md").is_file()


def encrypted_mount_present(path: Path) -> bool:
    return path.is_dir() and (os.path.ismount(path) or path_has_safehouse_scaffold(path))


def live_mount_matches(path: Path, live_mounts: dict[Path, Path] | None, container_path: Path | None = None) -> bool:
    if live_mounts is None:
        return False
    if container_path is not None and container_path in live_mounts:
        return True
    return path in live_mounts.values()


def mount_path_state(path: Path, live_mounts: dict[Path, Path] | None = None, container_path: Path | None = None) -> str:
    if live_mount_matches(path, live_mounts, container_path):
        return "known_mounted"
    if not path.exists():
        return "absent"
    if not path.is_dir():
        return "blocked"
    if live_mounts is not None and path_has_safehouse_scaffold(path):
        return "stale_scaffold"
    if encrypted_mount_present(path):
        return "known_mounted"
    if any(path.iterdir()):
        return "blocked"
    return "empty"


def ensure_mount_path_available(path: Path, live_mounts: dict[Path, Path] | None = None, container_path: Path | None = None) -> None:
    state = mount_path_state(path, live_mounts=live_mounts, container_path=container_path)
    if state in {"absent", "empty"}:
        return
    if state == "known_mounted":
        raise RuntimeError(f"already appears mounted as a Safehouse: {path}; run: safehouse status")
    if state == "stale_scaffold":
        raise RuntimeError(f"stale Safehouse scaffold at mount path but VeraCrypt does not list it as mounted: {path}; run: safehouse status")
    raise RuntimeError(f"refusing unknown/external mount path contents: {path}; inspect or move it manually; do not delete anything automatically")


def recovery_step_for_status(item: StatusLine) -> str:
    record = item.record
    if item.status == "MISSING":
        return f"{record.safehouse_id} inspect or restore lab Safehouse: {record.mount_path}"
    if item.status == "STALE_STATE":
        return f"{record.safehouse_id} run veracrypt -t --list, then mount or unmount after confirming actual mount state: {record.mount_path}"
    if item.status == "MOUNT_BLOCKED":
        return f"{record.safehouse_id} inspect mount path before moving anything: {record.mount_path}"
    if item.status == "NEEDS_RECOVERY":
        return f"{record.safehouse_id} inspect state, backups, or category path before editing state: {record.container_path}"
    return ""


def status_order_key(item: StatusLine) -> tuple[int, str, str]:
    status_order = {"MOUNTED": 0, "READY": 1, "STALE_STATE": 2, "MOUNT_BLOCKED": 3, "NEEDS_RECOVERY": 4, "MISSING": 5, "CLOSED": 6}
    return (status_order.get(item.status, 99), item.record.display_name.lower(), item.record.safehouse_id)


def status_for_record(record: SafehouseRecord, live_mounts: dict[Path, Path] | None = None) -> StatusLine:
    safehouse_path = Path(record.mount_path) if record.mount_path else Path("")
    if record.storage == "plain":
        if safehouse_path.is_dir():
            return StatusLine("READY", record, str(safehouse_path))
        return StatusLine("MISSING", record, str(safehouse_path), f"{record.safehouse_id} missing lab Safehouse: {safehouse_path}")

    container_path = Path(record.container_path) if record.container_path else Path("")
    if not container_path.is_file():
        return StatusLine("NEEDS_RECOVERY", record, str(safehouse_path), f"{record.safehouse_id} missing container: {container_path}")
    mount_state = mount_path_state(safehouse_path, live_mounts=live_mounts, container_path=container_path)
    if mount_state == "known_mounted":
        return StatusLine("MOUNTED", record, str(safehouse_path))
    if mount_state == "blocked":
        return StatusLine("MOUNT_BLOCKED", record, str(safehouse_path), f"{record.safehouse_id} mount path contains unknown/external files: {safehouse_path}")
    if mount_state == "stale_scaffold" or record.phase in {"mounted", "scaffolded", "profile_applied", "ready"}:
        return StatusLine("STALE_STATE", record, str(safehouse_path), f"{record.safehouse_id} registry says {record.phase} but mount is not present: {safehouse_path}")
    return StatusLine("CLOSED", record, str(safehouse_path))


def format_status(records: list[SafehouseRecord], live_mounts: dict[Path, Path] | None = None, category: str | None = None, storage: str | None = None) -> tuple[int, list[str]]:
    records = filter_records(records, category=category, storage=storage)
    if not records:
        return 0, format_empty_safehouses()
    status_lines = [status_for_record(record, live_mounts=live_mounts) for record in records]
    status_lines.sort(key=status_order_key)
    lines = ["STATUS          ID          CATEGORY    STORAGE    PHASE   NAME         PATH"]
    for item in status_lines:
        record = item.record
        lines.append(
            f"{item.status:<15} "
            f"{record.safehouse_id:<11} "
            f"{record.category:<11} "
            f"{record.storage:<10} "
            f"{record.phase:<7} "
            f"{record.display_name:<12} "
            f"{item.path}"
        )
    warnings = [item.warning for item in status_lines if item.warning]
    if warnings:
        lines.append("")
        lines.extend(f"WARN {warning}" for warning in warnings)
    recovery_steps = [recovery_step_for_status(item) for item in status_lines]
    recovery_steps = [step for step in recovery_steps if step]
    if recovery_steps:
        lines.append("")
        lines.extend(f"NEXT {step}" for step in recovery_steps)
    problem_statuses = {"STALE_STATE", "MOUNT_BLOCKED", "NEEDS_RECOVERY", "MISSING"}
    exit_code = 1 if any(item.status in problem_statuses for item in status_lines) else 0
    return exit_code, lines


def json_status(records: list[SafehouseRecord], live_mounts: dict[Path, Path] | None = None, category: str | None = None, storage: str | None = None) -> dict[str, object]:
    status_lines = [status_for_record(record, live_mounts=live_mounts) for record in filter_records(records, category=category, storage=storage)]
    status_lines.sort(key=status_order_key)
    problem_statuses = {"STALE_STATE", "MOUNT_BLOCKED", "NEEDS_RECOVERY", "MISSING"}
    exit_code = 1 if any(item.status in problem_statuses for item in status_lines) else 0
    safehouses: list[dict[str, str]] = []
    for item in status_lines:
        record = item.record
        entry = record.to_dict()
        entry["status"] = item.status
        entry["safehouse_path"] = item.path
        entry["warning"] = item.warning
        entry["next"] = recovery_step_for_status(item)
        safehouses.append(entry)
    return {"exit_code": exit_code, "count": len(safehouses), "safehouses": safehouses}


def print_status(state: StateStore, backend: Any | None = None, json_output: bool = False, category: str | None = None, storage: str | None = None) -> int:
    live_mounts = live_mounts_from_backend(backend) if backend is not None else None
    if json_output:
        payload = json_status(state.records(), live_mounts=live_mounts, category=category, storage=storage)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return cast(int, payload["exit_code"])
    exit_code, lines = format_status(state.records(), live_mounts=live_mounts, category=category, storage=storage)
    for line in lines:
        print(line)
    return exit_code


def selector_matches(record: SafehouseRecord, selector: str) -> bool:
    normalized = selector.strip()
    slug = slug_name(normalized)
    return normalized == record.safehouse_id or slug == record.slug or normalized.casefold() == record.display_name.casefold()


def select_record(records: list[SafehouseRecord], selector: str) -> SafehouseRecord:
    matches = [record for record in records if selector_matches(record, selector)]
    if not matches:
        raise RuntimeError(f"unknown safehouse selector: {selector}")
    if len(matches) > 1:
        ids = ", ".join(record.safehouse_id for record in matches)
        raise RuntimeError(f"ambiguous safehouse selector: {selector}; matches: {ids}")
    return matches[0]


def unmount_safehouse(state: StateStore, backend: Any, selector: str) -> SafehouseRecord:
    record = select_record(state.records(), selector)
    if record.storage == "plain":
        raise RuntimeError(f"plain lab has no VeraCrypt mount to unmount: {record.display_name}")
    mount_path = Path(record.mount_path)
    try:
        backend.unmount(mount_path)
    except RuntimeError as exc:
        raise RuntimeError(f"failed to unmount {record.safehouse_id}; exit Obsidian, shells, and file managers using {mount_path}, then retry: {exc}") from None
    closed = record.with_phase("closed")
    state.upsert(closed)
    return closed


def preflight_remove_safehouse(state: StateStore, backend: Any, selector: str) -> SafehouseRecord:
    record = select_record(state.records(), selector)
    safehouse_path = Path(record.mount_path)
    if safehouse_path.is_symlink():
        raise RuntimeError(f"refusing symlinked Safehouse path: {safehouse_path}")
    if record.storage == "plain":
        if not safehouse_path.is_dir():
            raise RuntimeError(f"missing Safehouse directory for {record.safehouse_id}: {safehouse_path}")
        safehouse_tree_manifest(safehouse_path)
        return record

    container_path = Path(record.container_path)
    if container_path.is_symlink():
        raise RuntimeError(f"refusing symlinked Safehouse container: {container_path}")
    if not container_path.is_file():
        raise RuntimeError(f"missing Safehouse container for {record.safehouse_id}: {container_path}")
    live_mounts = live_mounts_from_backend(backend)
    mount_state = mount_path_state(safehouse_path, live_mounts=live_mounts, container_path=container_path)
    if mount_state in {"known_mounted", "stale_scaffold"}:
        raise RuntimeError(f"Safehouse is mounted or has a stale mount view; unmount it before removal: {safehouse_path}")
    if mount_state == "blocked":
        raise RuntimeError(f"refusing non-empty mount path during removal; inspect or move it manually: {safehouse_path}")
    encrypted_safehouse_removal_root(record)
    return record


def encrypted_safehouse_removal_root(record: SafehouseRecord) -> Path | None:
    container_path = Path(record.container_path)
    mount_path = Path(record.mount_path)
    root = container_path.parent
    if mount_path.parent != root or root.name != record.slug:
        return None
    if root.is_symlink():
        raise RuntimeError(f"refusing symlinked encrypted Safehouse directory: {root}")
    for item in root.iterdir():
        if item == mount_path:
            if item.is_symlink() or not item.is_dir() or any(item.iterdir()):
                raise RuntimeError(f"refusing unexpected encrypted Safehouse mount directory: {item}")
            continue
        if item.is_symlink() or not item.is_file() or item.suffix != ".hc" or not SAFEHOUSE_ID_RE.fullmatch(item.stem):
            raise RuntimeError(f"refusing unexpected file in encrypted Safehouse directory: {item}")
    return root


def plan_remove_safehouse(state: StateStore, backend: Any, selector: str) -> list[str]:
    record = preflight_remove_safehouse(state, backend, selector)
    lines = [f"DRY-RUN safehouse remove {record.display_name}", f"ID: {record.safehouse_id}", f"Storage: {record.storage}"]
    if record.storage == "plain":
        lines.append(f"Safehouse path: {record.mount_path}")
        lines.append(f"Would delete Safehouse directory tree: {record.mount_path}")
    else:
        lines.append(f"Container path: {record.container_path}")
        lines.append(f"Mount path: {record.mount_path}")
        root = encrypted_safehouse_removal_root(record)
        if root is not None:
            lines.append(f"Would delete encrypted Safehouse directory tree: {root}")
        else:
            lines.append(f"Would delete VeraCrypt container: {record.container_path}")
            if Path(record.mount_path).is_dir():
                lines.append(f"Would remove empty mount directory: {record.mount_path}")
    lines.append(f"Would remove registry record: {record.safehouse_id}")
    lines.append("No files changed; no registry records removed.")
    return lines


def remove_safehouse(state: StateStore, backend: Any, selector: str) -> SafehouseRecord:
    record = preflight_remove_safehouse(state, backend, selector)
    safehouse_path = Path(record.mount_path)
    if record.storage == "plain":
        shutil.rmtree(safehouse_path)
    else:
        root = encrypted_safehouse_removal_root(record)
        if root is not None:
            shutil.rmtree(root)
        else:
            if safehouse_path.is_dir():
                safehouse_path.rmdir()
            Path(record.container_path).unlink()
    state.remove(record.safehouse_id)
    return record


def mount_safehouse(
    state: StateStore,
    backend: Any,
    selector: str,
    password: str,
    live_mounts: dict[Path, Path] | None = None,
) -> SafehouseRecord:
    record = preflight_mount_safehouse(state, backend, selector, live_mounts=live_mounts)
    container_path = Path(record.container_path)
    mount_path = Path(record.mount_path)
    try:
        backend.mount_volume(container_path, mount_path, password=password)
    except RuntimeError as exc:
        raise RuntimeError(f"failed to mount {record.safehouse_id}; inspect {mount_path} and retry: {exc}") from None
    mounted = record.with_opened_phase("ready")
    state.upsert(mounted)
    return mounted


def preflight_mount_safehouse(
    state: StateStore,
    backend: Any,
    selector: str,
    live_mounts: dict[Path, Path] | None = None,
) -> SafehouseRecord:
    record = select_record(state.records(), selector)
    if record.storage == "plain":
        raise RuntimeError(f"plain lab does not need VeraCrypt mounting: {record.display_name}")
    container_path = Path(record.container_path)
    mount_path = Path(record.mount_path)
    if not container_path.is_file():
        raise RuntimeError(f"missing container for {record.safehouse_id}: {container_path}")
    if live_mounts is None:
        live_mounts = live_mounts_from_backend(backend)
    ensure_mount_path_available(mount_path, live_mounts=live_mounts, container_path=container_path)
    return record


def create_safehouse(
    category: str,
    name: str,
    config: ConfigStore,
    state: StateStore,
    backend: Any,
    password: str,
    id_rng: Callable[[int], bytes] = secrets.token_bytes,
    path: str | None = None,
    storage_override: str | None = None,
    container_size: str | None = None,
    obsidian_profile: str | None = None,
) -> SafehousePaths:
    storage = storage_mode_for(config, category, storage_override=storage_override)
    safehouse_id = new_safehouse_id(id_rng)
    profile = obsidian_profile or config.get_category_default(category, "obsidian-profile") or "minimal"
    if profile != "minimal" and not profile_path(config.paths, profile).is_dir():
        raise RuntimeError(f"obsidian profile does not exist: {profile}")
    if storage == "plain":
        paths = plain_safehouse_paths(config, category, name, safehouse_id, path=path)
        record = record_for_paths(paths, category, "", "", "creating", storage=storage)
        state.upsert(record)
        try:
            scaffold_safehouse_root(paths.mount_path, category, name)
            record = record.with_phase("scaffolded")
            state.upsert(record)
            apply_obsidian_profile(config.paths, profile, str(paths.mount_path))
            record = record.with_phase("profile_applied")
            state.upsert(record)
            record = record.with_phase("ready")
            state.upsert(record)
            return paths
        except Exception:
            state.upsert(record.with_phase("failed_setup"))
            raise

    roots = roots_from_defaults(config, category, path=path)
    size = container_size or config.get_category_default(category, "container-size") or "512M"
    if not SIZE_RE.fullmatch(size):
        raise ValueError("container-size must look like 512M, 1G, or 2048M")
    filesystem = "ext4"
    paths = derive_safehouse_paths(roots, name, safehouse_id=safehouse_id)
    record = record_for_paths(paths, category, size, filesystem, "creating", storage=storage)
    if paths.container_path.exists():
        raise RuntimeError(f"refusing to overwrite existing container: {paths.container_path}")
    ensure_mount_path_available(paths.mount_path)
    state.upsert(record)
    try:
        backend.create_volume(paths.container_path, size=size, filesystem=filesystem, password=password)
        record = record.with_phase("container_created")
        state.upsert(record)
        backend.mount_volume(paths.container_path, paths.mount_path, password=password)
        record = record.with_phase("mounted")
        state.upsert(record)
        scaffold_safehouse_root(paths.mount_path, category, name)
        record = record.with_phase("scaffolded")
        state.upsert(record)
        apply_obsidian_profile(config.paths, profile, str(paths.mount_path))
        record = record.with_phase("profile_applied")
        state.upsert(record)
        record = record.with_phase("ready")
        state.upsert(record)
        return paths
    except Exception:
        state.upsert(record.with_phase("failed_setup"))
        raise


def safehouse_tree_manifest(root: Path) -> tuple[dict[str, tuple[str, int, str]], int, int, int, str]:
    entries: dict[str, tuple[str, int, str]] = {}
    file_count = 0
    directory_count = 0
    total_bytes = 0
    for item in sorted(root.rglob("*")):
        rel = item.relative_to(root)
        if rel.parts and rel.parts[0] == "lost+found":
            continue
        if rel.is_absolute() or ".." in rel.parts:
            raise RuntimeError(f"refusing unsafe Safehouse relative path: {rel}")
        if item.is_symlink():
            raise RuntimeError(f"refusing symlink in Safehouse resize source: {rel}")
        if item.is_dir():
            entries[str(rel)] = ("directory", 0, "")
            directory_count += 1
            continue
        if not item.is_file():
            raise RuntimeError(f"refusing special file in Safehouse resize source: {rel}")
        data = item.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        entries[str(rel)] = ("file", len(data), digest)
        file_count += 1
        total_bytes += len(data)
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return entries, file_count, directory_count, total_bytes, hashlib.sha256(encoded).hexdigest()


def copy_safehouse_tree(source: Path, target: Path, manifest: dict[str, tuple[str, int, str]]) -> None:
    for rel_text, (kind, _size, _digest) in sorted(manifest.items()):
        rel = Path(rel_text)
        destination = target / rel
        if kind == "directory":
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copy2(source / rel, destination, follow_symlinks=False)


def resize_required_bytes(payload_bytes: int) -> int:
    filesystem_overhead = 64 * 1024 * 1024
    safety_margin = max(64 * 1024 * 1024, (payload_bytes + 3) // 4)
    return payload_bytes + filesystem_overhead + safety_margin


def resize_safehouse(
    state: StateStore,
    backend: Any,
    selector: str,
    to_size: str,
    password: str,
    id_rng: Callable[[int], bytes] = secrets.token_bytes,
) -> ResizeResult:
    target_bytes = size_to_bytes(to_size)
    record = select_record(state.records(), selector)
    if record.storage != "encrypted":
        raise RuntimeError(f"plain lab has no VeraCrypt container to resize: {record.display_name}")
    if not record.size:
        raise RuntimeError(f"missing current container size for {record.safehouse_id}")
    if target_bytes == size_to_bytes(record.size):
        raise ValueError("target size must differ from current size")
    source_container = Path(record.container_path)
    source_mount = Path(record.mount_path)
    if source_container.is_symlink():
        raise RuntimeError(f"refusing symlinked source container: {source_container}")
    if not source_container.is_file():
        raise RuntimeError(f"missing source container: {source_container}")
    live_mounts = live_mounts_from_backend(backend)
    if live_mounts and source_container in live_mounts:
        raise RuntimeError(f"source Safehouse is mounted; unmount it before resize: {source_mount}")
    ensure_mount_path_available(source_mount, live_mounts=live_mounts, container_path=source_container)
    target_id = new_safehouse_id(id_rng)
    target_container = source_container.parent / container_filename(target_id)
    target_mount = source_mount.parent / target_id
    if target_container.exists():
        raise RuntimeError(f"refusing existing target container path: {target_container}")
    ensure_mount_path_available(target_mount, live_mounts=live_mounts)

    source_mounted = False
    target_mounted = False
    try:
        backend.mount_volume(source_container, source_mount, password=password, read_only=True)
        source_mounted = True
        source_manifest, file_count, directory_count, total_bytes, manifest_sha256 = safehouse_tree_manifest(source_mount)
        required_bytes = resize_required_bytes(total_bytes)
        if target_bytes < required_bytes:
            raise RuntimeError(
                f"target size is too small for copied data and ext4 safety margin: requires at least {required_bytes} bytes"
            )
        backend.create_volume(target_container, size=to_size, filesystem=record.filesystem or "ext4", password=password)
        backend.mount_volume(target_container, target_mount, password=password)
        target_mounted = True
        copy_safehouse_tree(source_mount, target_mount, source_manifest)
        target_manifest, target_files, target_directories, target_bytes_used, target_digest = safehouse_tree_manifest(target_mount)
        if target_manifest != source_manifest or (target_files, target_directories, target_bytes_used, target_digest) != (
            file_count, directory_count, total_bytes, manifest_sha256
        ):
            raise RuntimeError("copy verification failed; source remains authoritative and target was retained for inspection")
        backend.unmount(target_mount)
        target_mounted = False
        target_mount.rmdir()
        backend.unmount(source_mount)
        source_mounted = False
        backend.mount_volume(target_container, source_mount, password=password)
        updated = SafehouseRecord(
            safehouse_id=record.safehouse_id,
            display_name=record.display_name,
            slug=record.slug,
            category=record.category,
            storage=record.storage,
            container_path=str(target_container),
            mount_path=record.mount_path,
            size=to_size,
            filesystem=record.filesystem or "ext4",
            phase="ready",
            created_at=record.created_at,
            last_opened_at=dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        )
        state.replace(record.safehouse_id, updated)
        return ResizeResult(updated, source_container, file_count, directory_count, total_bytes, manifest_sha256)
    except Exception:
        if target_mounted:
            try:
                backend.unmount(target_mount)
            except RuntimeError:
                pass
        if source_mounted:
            try:
                backend.unmount(source_mount)
            except RuntimeError:
                pass
        raise


def dry_run_new_safehouse(
    category: str,
    name: str,
    config: ConfigStore,
    paths: AppPaths,
    id_rng: Callable[[int], bytes] = secrets.token_bytes,
    path: str | None = None,
    storage_override: str | None = None,
    container_size: str | None = None,
    obsidian_profile: str | None = None,
) -> tuple[int, list[str]]:
    manual_recovery = "NEXT inspect or move the existing path manually before running without --dry-run"
    storage = storage_mode_for(config, category, storage_override=storage_override)
    safehouse_id = new_safehouse_id(id_rng)
    profile = obsidian_profile or config.get_category_default(category, "obsidian-profile") or "minimal"
    if profile != "minimal" and not profile_path(paths, profile).is_dir():
        raise RuntimeError(f"obsidian profile does not exist: {profile}")
    if storage == "plain":
        planned = plain_safehouse_paths(config, category, name, safehouse_id, path=path)
        lines = [
            f"DRY-RUN safehouse new {category} {planned.display_name}",
            f"ID: {planned.safehouse_id}",
            "Storage: plain",
            f"Safehouse path: {planned.mount_path}",
            f"Obsidian profile: {profile}",
            "Would prompt for VeraCrypt password: no",
            f"Would create scaffold: {planned.mount_path}",
            f"Would apply obsidian profile {profile} to {planned.mount_path / '.obsidian'}",
            "Would write state phase: ready",
        ]
        if planned.mount_path.exists() and not planned.mount_path.is_dir():
            return 1, [*lines, f"DRY-RUN refusing blocked Safehouse path: {planned.mount_path}", manual_recovery]
        if planned.mount_path.exists() and any(planned.mount_path.iterdir()):
            return 1, [*lines, f"DRY-RUN refusing non-empty Safehouse path: {planned.mount_path}", manual_recovery]
        return 0, lines

    roots = roots_from_defaults(config, category, path=path)
    size = container_size or config.get_category_default(category, "container-size") or "512M"
    if not SIZE_RE.fullmatch(size):
        raise ValueError("container-size must look like 512M, 1G, or 2048M")
    filesystem = "ext4"
    planned = derive_safehouse_paths(roots, name, safehouse_id=safehouse_id)
    lines = [
        f"DRY-RUN safehouse new {category} {planned.display_name}",
        f"ID: {planned.safehouse_id}",
        "Storage: encrypted",
        f"Container path: {planned.container_path}",
        f"Mount path: {planned.mount_path}",
        f"Size: {size}",
        f"Filesystem: {filesystem}",
        f"Obsidian profile: {profile}",
        "Would prompt for VeraCrypt password: yes",
        "Would create VeraCrypt container",
        "Would mount VeraCrypt container",
        f"Would create scaffold: {planned.mount_path}",
        f"Would apply obsidian profile {profile} to {planned.mount_path / '.obsidian'}",
        "Would write state phase: ready",
    ]
    if planned.container_path.exists():
        return 1, [*lines, f"DRY-RUN refusing existing container path: {planned.container_path}", manual_recovery]
    mount_state = mount_path_state(planned.mount_path)
    if mount_state not in {"absent", "empty"}:
        return 1, [*lines, f"DRY-RUN refusing unavailable mount path: {planned.mount_path}", manual_recovery]
    return 0, lines


def json_new_plan(
    category: str,
    name: str,
    config: ConfigStore,
    paths: AppPaths,
    id_rng: Callable[[int], bytes] = secrets.token_bytes,
    path: str | None = None,
    storage_override: str | None = None,
    container_size: str | None = None,
    obsidian_profile: str | None = None,
) -> dict[str, Any]:
    storage = storage_mode_for(config, category, storage_override=storage_override)
    safehouse_id = new_safehouse_id(id_rng)
    profile = obsidian_profile or config.get_category_default(category, "obsidian-profile") or "minimal"
    if profile != "minimal" and not profile_path(paths, profile).is_dir():
        raise RuntimeError(f"obsidian profile does not exist: {profile}")
    payload: dict[str, Any] = {
        "exit_code": 0,
        "safehouse_id": safehouse_id,
        "display_name": name,
        "category": category,
        "storage": storage,
        "safehouse_path": "",
        "container_path": "",
        "mount_path": "",
        "size": "",
        "filesystem": "",
        "obsidian_profile": profile,
        "will_prompt": storage == "encrypted",
        "will_write": False,
        "steps": [],
        "warning": "",
        "next": "",
    }
    manual_recovery = "inspect or move the existing path manually before running without --dry-run"
    if storage == "plain":
        planned = plain_safehouse_paths(config, category, name, safehouse_id, path=path)
        payload.update({
            "safehouse_path": str(planned.mount_path),
            "mount_path": str(planned.mount_path),
            "steps": [
                "create scaffold",
                "apply obsidian profile",
                "write state phase ready",
            ],
        })
        if planned.mount_path.exists() and not planned.mount_path.is_dir():
            payload["exit_code"] = 1
            payload["warning"] = f"blocked Safehouse path: {planned.mount_path}"
            payload["next"] = manual_recovery
        elif planned.mount_path.exists() and any(planned.mount_path.iterdir()):
            payload["exit_code"] = 1
            payload["warning"] = f"non-empty Safehouse path: {planned.mount_path}"
            payload["next"] = manual_recovery
        return payload

    roots = roots_from_defaults(config, category, path=path)
    planned = derive_safehouse_paths(roots, name, safehouse_id=safehouse_id)
    size = container_size or config.get_category_default(category, "container-size") or "512M"
    if not SIZE_RE.fullmatch(size):
        raise ValueError("container-size must look like 512M, 1G, or 2048M")
    filesystem = "ext4"
    payload.update({
        "safehouse_path": str(planned.mount_path),
        "container_path": str(planned.container_path),
        "mount_path": str(planned.mount_path),
        "size": size,
        "filesystem": filesystem,
        "steps": [
            "create VeraCrypt container",
            "mount VeraCrypt container",
            "create scaffold",
            "apply obsidian profile",
            "write state phase ready",
        ],
    })
    if planned.container_path.exists():
        payload["exit_code"] = 1
        payload["warning"] = f"existing container path: {planned.container_path}"
        payload["next"] = manual_recovery
    else:
        mount_state = mount_path_state(planned.mount_path)
        if mount_state not in {"absent", "empty"}:
            payload["exit_code"] = 1
            payload["warning"] = f"unavailable mount path: {planned.mount_path}"
            payload["next"] = manual_recovery
    return payload


def json_resize_plan(
    state: StateStore,
    selector: str,
    to_size: str,
    id_rng: Callable[[int], bytes] = secrets.token_bytes,
) -> dict[str, Any]:
    size_to_bytes(to_size)
    record = select_record(state.records(), selector)
    if record.storage == "plain":
        raise RuntimeError(f"plain lab has no VeraCrypt container to resize: {record.display_name}")
    if not record.size:
        raise RuntimeError(f"missing current container size for {record.safehouse_id}")


    source_container = Path(record.container_path)
    source_mount = Path(record.mount_path)
    if not source_container.is_file():
        raise RuntimeError(f"missing source container: {source_container}")

    target_id = new_safehouse_id(id_rng)
    target_container = source_container.parent / container_filename(target_id)
    target_mount = source_mount.parent / target_id
    payload: dict[str, Any] = {
        "exit_code": 0,
        "safehouse_id": record.safehouse_id,
        "display_name": record.display_name,
        "storage": record.storage,
        "source_container": str(source_container),
        "source_mount": str(source_mount),
        "target_id": target_id,
        "target_container": str(target_container),
        "target_mount": str(target_mount),
        "current_size": record.size,
        "target_size": to_size,
        "filesystem": record.filesystem or "ext4",
        "will_prompt": True,
        "will_write": False,
        "steps": [
            "create replacement VeraCrypt container",
            "mount old and new containers",
            "copy mounted Safehouse data to new container",
            "verify relative paths, content hashes, and totals before state switch",
            "preserve old container",
            "write state phase ready after verification",
        ],
        "warning": "",
        "next": "",
    }
    manual_recovery = "NEXT inspect or move the existing target path manually before real resize"
    if target_container.exists():
        payload["exit_code"] = 1
        payload["warning"] = f"DRY-RUN refusing existing target container path: {target_container}"
        payload["next"] = manual_recovery
        return payload
    mount_state = mount_path_state(target_mount)
    if mount_state not in {"absent", "empty"}:
        payload["exit_code"] = 1
        payload["warning"] = f"DRY-RUN refusing unavailable target mount path: {target_mount}"
        payload["next"] = manual_recovery
        return payload
    return payload


def confirm_resize_old_deletion(old_container: Path) -> bool:
    """Prompt only on a terminal; default to retaining the recovery container."""
    if not sys.stdin.isatty():
        return False
    answer = input(f"Verified resize complete. Delete superseded container {old_container}? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def format_resize_plan(payload: dict[str, Any]) -> list[str]:
    lines = [
        f"DRY-RUN safehouse resize {payload['display_name']} --to-size {payload['target_size']}",
        f"Source ID: {payload['safehouse_id']}",
        f"Source container: {payload['source_container']}",
        f"Source mount: {payload['source_mount']}",
        f"Target ID: {payload['target_id']}",
        f"New container path: {payload['target_container']}",
        f"New mount path: {payload['target_mount']}",
        f"Current size: {payload['current_size']}",
        f"Target size: {payload['target_size']}",
        f"Filesystem: {payload['filesystem']}",
        "Would prompt for VeraCrypt password: yes",
        "Would create replacement VeraCrypt container",
        "Would mount old and new containers",
        "Would copy mounted Safehouse data to new container",
        "Would verify relative paths, content hashes, and totals before state switch",
        f"Would preserve old container: {payload['source_container']}",
        "Would write state phase: ready after verification",
        "No files changed; no containers created; no mounts opened.",
    ]
    if payload.get("warning"):
        lines.append(str(payload["warning"]))
    if payload.get("next"):
        lines.append(str(payload["next"]))
    return lines


def dry_run_resize_safehouse(
    state: StateStore,
    selector: str,
    to_size: str,
    id_rng: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[int, list[str]]:
    payload = json_resize_plan(state, selector, to_size, id_rng=id_rng)
    return cast(int, payload["exit_code"]), format_resize_plan(payload)


def json_resize_error_payload(state: StateStore, selector: str, to_size: str, error: Exception) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "exit_code": 2,
        "safehouse_id": "",
        "display_name": selector,
        "storage": "",
        "source_container": "",
        "source_mount": "",
        "target_id": "",
        "target_container": "",
        "target_mount": "",
        "current_size": "",
        "target_size": to_size,
        "filesystem": "",
        "will_prompt": False,
        "will_write": False,
        "steps": [],
        "warning": str(error),
        "next": "inspect state, selector, source container, and requested target size before retrying",
    }
    try:
        record = select_record(state.records(), selector)
    except (RuntimeError, ValueError, json.JSONDecodeError):
        return payload
    payload.update({
        "safehouse_id": record.safehouse_id,
        "display_name": record.display_name,
        "storage": record.storage,
        "source_container": record.container_path,
        "source_mount": record.mount_path,
        "current_size": record.size,
        "filesystem": record.filesystem or "ext4",
    })
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = build_parser("safehouse")
    args = parser.parse_args(argv)
    if args.about:
        print(ABOUT_TEXT, end="")
        return 0
    if not args.cmd:
        parser.error("the following arguments are required: COMMAND")
    paths = app_paths_from_env()
    if args.cmd == "obsidian-profile":
        try:
            if args.profile_cmd == "import":
                copied = copy_obsidian_profile(paths, args.name, args.source, replace=False)
                print(f"imported obsidian profile {args.name} {copied}")
                print("warning: community plugin code is user-supplied executable code; review it before reuse")
                return 0
            if args.profile_cmd == "replace":
                copied = copy_obsidian_profile(paths, args.name, args.source, replace=True)
                print(f"replaced obsidian profile {args.name} {copied}")
                print("warning: community plugin code is user-supplied executable code; review it before reuse")
                return 0
            if args.profile_cmd == "list":
                for line in obsidian_profile_list_lines(paths, verbose=args.verbose):
                    print(line)
                return 0
            if args.profile_cmd == "show":
                for line in show_obsidian_profile(paths, args.name):
                    print(line)
                return 0
            if args.profile_cmd == "verify":
                if args.all and args.name:
                    raise ValueError("choose either a profile name or --all")
                if args.all:
                    exit_code, lines = verify_all_obsidian_profiles(paths)
                elif args.name:
                    exit_code, lines = verify_obsidian_profile(paths, args.name)
                else:
                    raise ValueError("verify requires a profile name or --all")
                for line in lines:
                    print(line)
                return exit_code
            if args.profile_cmd == "apply":
                if args.dry_run:
                    exit_code, lines = dry_run_apply_obsidian_profile(paths, args.name, args.to_target)
                    for line in lines:
                        print(line)
                    return exit_code
                safehouse_target = registered_obsidian_profile_target(paths, args.to_target)
                existing_profile = safehouse_target / ".obsidian"
                if existing_profile.is_dir() and any(existing_profile.iterdir()) and not args.yes_replace:
                    raise RuntimeError("existing .obsidian directory requires --yes-replace after reviewing --dry-run")
                applied = apply_obsidian_profile(paths, args.name, str(safehouse_target))
                print(f"applied obsidian profile {args.name} {applied}")
                return 0
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            parser.exit(2, f"safehouse: error: {exc}\n")

    if args.cmd == "defaults":
        store = ConfigStore(paths)
        try:
            if args.defaults_cmd == "show":
                print_defaults(store, category=args.category)
                return 0
            if args.defaults_cmd == "set":
                category_updates = category_default_updates_from_args(args)
                if (args.path is not None or args.storage is not None or args.container_size is not None or args.obsidian_profile is not None) and not args.category:
                    raise ValueError("defaults set requires CATEGORY")
                if not category_updates:
                    raise ValueError("defaults set requires at least one setting flag")
                for category, field, value in category_updates:
                    store.set_category_default(category, field, value)
                    print(f"{category}.{field} = {value}")
                return 0
            if args.defaults_cmd == "clear":
                category_fields = [field for attr, field in CATEGORY_DEFAULT_FLAG_DESTS.items() if getattr(args, attr)]
                target = args.target
                if args.all and (target or category_fields):
                    raise ValueError("use either clear CATEGORY field flags or clear --all, not both")
                if category_fields and not target:
                    raise ValueError("defaults clear field flags require CATEGORY")
                if args.all:
                    store.clear_defaults()
                    print("all configured defaults reverted to built-in defaults")
                elif category_fields:
                    for field in category_fields:
                        store.clear_category_default(target, field)
                        print(f"{target}.{field} reverted to built-in default")
                elif target:
                    raise ValueError("defaults clear requires CATEGORY plus field flags, or --all")
                else:
                    raise ValueError("clear requires CATEGORY plus field flags, or --all")
                return 0
            parser.parse_args(["defaults", "--help"])
            return 0
        except (RuntimeError, ValueError) as exc:
            parser.exit(2, f"safehouse: error: {exc}\n")
    if args.cmd == "doctor":
        return print_doctor(paths, ConfigStore(paths), json_output=args.json)
    if args.cmd == "list":
        try:
            print_inventory(
                StateStore(paths),
                json_output=args.json,
                category=category_filter_from_flags(args.lab, args.engagement, args.category),
                storage=args.storage,
            )
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            parser.exit(2, f"safehouse: error: {exc}\n")
        return 0
    if args.cmd == "status":
        try:
            return print_status(
                StateStore(paths),
                backend_from_env(),
                json_output=args.json,
                category=category_filter_from_flags(args.lab, args.engagement, args.category),
                storage=args.storage,
            )
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            parser.exit(2, f"safehouse: error: {exc}\n")
    if args.cmd == "unmount":
        try:
            state = StateStore(paths)
            backend = backend_from_env()
            refresh_admin_credentials_for_backend(backend)
            unmounted = unmount_safehouse(state, backend, args.selector)
        except KeyboardInterrupt:
            parser.exit(130, "safehouse: interrupted\n")
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            parser.exit(2, f"safehouse: error: {exc}\n")
        print(f"unmounted {unmounted.safehouse_id} {unmounted.display_name}")
        return 0
    if args.cmd == "mount":
        try:
            state = StateStore(paths)
            backend = backend_from_env()
            preflight_mount_safehouse(state, backend, args.selector)
            refresh_admin_credentials_for_backend(backend)
            password = read_mount_password()
            mounted = mount_safehouse(state, backend, args.selector, password)
        except KeyboardInterrupt:
            parser.exit(130, "safehouse: interrupted\n")
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            parser.exit(2, f"safehouse: error: {exc}\n")
        print(f"mounted {mounted.safehouse_id} {mounted.display_name} {mounted.mount_path}")
        return 0
    if args.cmd == "remove":
        try:
            state = StateStore(paths)
            backend = backend_from_env()
            if args.dry_run:
                if args.yes:
                    raise ValueError("--yes cannot be used with --dry-run")
                for line in plan_remove_safehouse(state, backend, args.selector):
                    print(line)
                return 0
            if not args.yes:
                raise ValueError("remove requires --yes after reviewing --dry-run")
            removed = remove_safehouse(state, backend, args.selector)
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            parser.exit(2, f"safehouse: error: {exc}\n")
        print(f"removed {removed.safehouse_id} {removed.display_name}")
        return 0
    if args.cmd == "resize":
        try:
            if args.json and not args.dry_run:
                raise ValueError("--json only works with --dry-run")
            if args.delete_old and args.dry_run:
                raise ValueError("--delete-old cannot be used with --dry-run")
            if args.dry_run and args.json:
                payload = json_resize_plan(StateStore(paths), args.selector, args.to_size)
                print(json.dumps(payload, indent=2, sort_keys=True))
                return cast(int, payload["exit_code"])
            if args.dry_run:
                exit_code, lines = dry_run_resize_safehouse(StateStore(paths), args.selector, args.to_size)
                for line in lines:
                    print(line)
                return exit_code
            backend = backend_from_env()
            refresh_admin_credentials_for_backend(backend)
            result = resize_safehouse(StateStore(paths), backend, args.selector, args.to_size, read_mount_password())
            print(f"resized {result.record.safehouse_id} {result.record.display_name} to {result.record.size}")
            print(f"Verified files: {result.file_count}; directories: {result.directory_count}; bytes: {result.total_bytes}")
            delete_old = args.delete_old or confirm_resize_old_deletion(result.old_container)
            if delete_old:
                result.old_container.unlink()
                print(f"Old container deleted: {result.old_container}")
            else:
                print(f"Old container retained: {result.old_container}")
                print("NEXT inspect the mounted replacement before manually deleting the retained old container, or answer yes to this prompt next time.")
            return 0
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            if args.json and args.dry_run:
                payload = json_resize_error_payload(StateStore(paths), args.selector, args.to_size, exc)
                print(json.dumps(payload, indent=2, sort_keys=True))
                return cast(int, payload["exit_code"])
            parser.exit(2, f"safehouse: error: {exc}\n")
    if args.cmd == "new":
        store = ConfigStore(paths)
        category = args.category
        path_arg = args.path
        storage = storage_mode_for(store, category, storage_override=args.storage)
        try:
            if args.json and not args.dry_run:
                raise ValueError("--json only works with --dry-run")
            if args.dry_run:
                if args.json:
                    payload = json_new_plan(
                        category,
                        args.name,
                        store,
                        paths,
                        path=path_arg,
                        storage_override=args.storage,
                        container_size=args.container_size,
                        obsidian_profile=args.obsidian_profile,
                    )
                    print(json.dumps(payload, indent=2, sort_keys=True))
                    return cast(int, payload["exit_code"])
                exit_code, lines = dry_run_new_safehouse(
                    category,
                    args.name,
                    store,
                    paths,
                    path=path_arg,
                    storage_override=args.storage,
                    container_size=args.container_size,
                    obsidian_profile=args.obsidian_profile,
                )
                for line in lines:
                    print(line)
                return exit_code
            backend = backend_from_env()
            if storage == "encrypted":
                refresh_admin_credentials_for_backend(backend)
            password = read_new_password() if storage == "encrypted" else ""
            created = create_safehouse(
                category=category,
                name=args.name,
                config=store,
                state=StateStore(paths),
                backend=backend,
                password=password,
                path=path_arg,
                storage_override=args.storage,
                container_size=args.container_size,
                obsidian_profile=args.obsidian_profile,
            )
        except KeyboardInterrupt:
            parser.exit(130, "safehouse: interrupted\n")
        except (RuntimeError, ValueError, SystemExit) as exc:
            parser.exit(2, f"safehouse: error: {exc}\n")
        print(created.mount_path)
        return 0
    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
