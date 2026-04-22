"""File loader: traverse directories and read skill content."""

from __future__ import annotations

import hashlib
import logging
import tempfile
import zipfile
from pathlib import Path
from typing import Generator

from scanner.excluded_dirs import load_excluded_patterns, path_has_excluded_component
from scanner.models import SkillFile, SkillFileSegment

logger = logging.getLogger(__name__)

# Known skill entry file names (case-insensitive matching)
SKILL_ENTRY_NAMES = {"skill.md", "skill.yaml", "skill.yml"}

SUPPORTED_EXTENSIONS = {".md", ".yaml", ".yml", ".txt", ".json", ".svg", ".html", ".htm", ".xml",
                        ".py", ".js", ".ts", ".sh", ".bash", ".mjs"}

# Extensionless build/config files that commonly contain executable commands.
SUPPORTED_FILENAMES = {
    "earthfile", "makefile", "dockerfile", "jenkinsfile",
    "vagrantfile", "rakefile", "gemfile", "procfile",
    "justfile", "taskfile", "brewfile",
}

# Maximum total bytes scanned across all auxiliary files per skill.
# Files that would push the total over this limit are skipped entirely (not truncated).
_MAX_TOTAL_SCAN_BYTES = 50 * 1024 * 1024  # 50 MB
# Maximum bytes per auxiliary file included in the combined LLM content (skill.content).
# This only affects Stage 2 input; Stage 1 always scans the full file.
_MAX_LLM_AUX_FILE_BYTES = 200 * 1024  # 200 KB
# Maximum number of auxiliary files per skill (guards against directory explosions).
_MAX_FILES = 100

# Files to ignore when scanning directories
IGNORED_FILES = {"detail.json"}

# Source detection by directory name
_SOURCE_KEYWORDS = {
    "clawhub": "clawhub",
    "smithery": "smithery",
    "skills_sh": "skills_sh",
    "skills.sh": "skills_sh",
}


def _hash_bytes(data: bytes) -> tuple[str, str]:
    """Return (md5_hex, sha1_hex) for the given bytes."""
    return hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest()


def _collect_file_hashes(root_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Walk *all* files under *root_dir* and return (file_md5s, file_sha1s).

    Keys are POSIX-style relative paths (e.g. ``bin/run.js``).
    """
    md5s: dict[str, str] = {}
    sha1s: dict[str, str] = {}
    for p in sorted(root_dir.rglob("*")):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
            rel = p.relative_to(root_dir).as_posix()
            if path_has_excluded_component(rel, load_excluded_patterns()):
                continue
            m, s = _hash_bytes(data)
            md5s[rel] = m
            sha1s[rel] = s
        except OSError:
            continue
    return md5s, sha1s


def detect_source(file_path: Path) -> str:
    """Detect source platform from path using substring matching.

    Matches keywords against individual path components using substring check,
    so 'clawhub_data' matches keyword 'clawhub'.
    """
    parts = [p.lower() for p in file_path.parts]
    for keyword, source in _SOURCE_KEYWORDS.items():
        for part in parts:
            if keyword in part:
                return source
    return "unknown"


def generate_id(file_path: Path) -> str:
    """Generate skill ID using directory name as prefix + short hash for uniqueness."""
    dir_name = file_path.name if file_path.is_dir() else file_path.stem
    # Sanitize: keep only alphanumeric, hyphen, underscore
    safe_name = "".join(
        c if c.isalnum() or c in "-_" else "-" for c in dir_name).strip("-")
    if not safe_name:
        safe_name = "unnamed"
    path_hash = hashlib.sha256(str(file_path).encode()).hexdigest()[:8]
    return f"{safe_name}-{path_hash}"


def _find_entry_file_direct(skill_dir: Path) -> Path | None:
    """Return the skill entry file only if it is a *direct* child of skill_dir.

    Used for the root-level flat-structure check in load_skills() to avoid
    spuriously re-yielding skills that have already been found in subdirectories.
    """
    for child in skill_dir.iterdir():
        if child.is_file() and child.name.lower() in SKILL_ENTRY_NAMES:
            return child
    return None


def _find_entry_file(skill_dir: Path) -> Path | None:
    """Find the skill entry file (SKILL.md etc.) in a directory.

    Search order:
    1) Direct children of ``skill_dir`` (preserves existing behaviour).
    2) Depth-first search of subdirectories in lexicographic order, returning
       the first directory that contains a matching entry file.

    This allows archives that contain multiple skills in nested directories to
    still pick a stable “first” SKILL.md as the logical entry point.
    """
    # First, preserve existing behaviour: look at direct children only.
    for child in skill_dir.iterdir():
        if child.is_file() and child.name.lower() in SKILL_ENTRY_NAMES:
            return child

    # If no direct entry file is found, search subdirectories recursively.
    subdirs = sorted([c for c in skill_dir.iterdir() if c.is_dir()], key=lambda p: p.name)
    for sub in subdirs:
        entry = _find_entry_file(sub)
        if entry is not None:
            return entry

    return None


def _collect_auxiliary_segments(
    skill_dir: Path, entry_file: Path
) -> list[SkillFileSegment]:
    """Read all auxiliary files and return as individual segments.

    Each file is read in full (no per-file truncation) so Stage 1 can scan the
    entire content.  A _MAX_TOTAL_SCAN_BYTES budget is applied across all files:
    if adding the next file would exceed the budget the file is skipped entirely
    and scanning stops — skipping whole files is safer than silently truncating
    them, and a warning is emitted so the operator can adjust the limit if needed.

    Stage 2 LLM content is built separately by _segments_to_combined_content()
    which applies its own per-file truncation (_MAX_LLM_AUX_FILE_BYTES).
    """
    segments: list[SkillFileSegment] = []
    total_bytes = 0
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file() or path == entry_file:
            continue
        if path.name.lower() in IGNORED_FILES:
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS and path.name.lower() not in SUPPORTED_FILENAMES:
            continue
        if len(segments) >= _MAX_FILES:
            logger.debug(
                "File count limit (%d) reached, skipping remaining aux files",
                _MAX_FILES,
            )
            break
        try:
            file_size = path.stat().st_size
            rel = path.relative_to(skill_dir).as_posix()
            if path_has_excluded_component(rel, load_excluded_patterns()):
                continue
            if total_bytes + file_size > _MAX_TOTAL_SCAN_BYTES:
                logger.warning(
                    "Total scan limit (%d MB) reached, skipping %s",
                    _MAX_TOTAL_SCAN_BYTES // (1024 * 1024),
                    rel,
                )
                break
            text = path.read_text(encoding="utf-8", errors="replace")
            segments.append(SkillFileSegment(rel_path=rel, content=text))
            total_bytes += file_size
        except OSError:
            continue
    return segments


def _segments_to_combined_content(
    entry_content: str,
    aux_segments: list[SkillFileSegment],
    max_aux_bytes: int = _MAX_LLM_AUX_FILE_BYTES,
) -> str:
    """Build the combined-content string used by Stage 2 LLM.

    Each auxiliary file is truncated to *max_aux_bytes* characters so that
    skill.content stays at a manageable size for the LLM context window.
    Stage 1 scanning uses SkillFileSegment.content directly and is unaffected.
    """
    parts = [entry_content]
    for s in aux_segments:
        if len(s.content) > max_aux_bytes:
            label = f"[{s.rel_path}] (truncated to {max_aux_bytes // 1024}KB)"
            snippet = s.content[:max_aux_bytes]
        else:
            label = f"[{s.rel_path}]"
            snippet = s.content
        parts.append(f"\n--- {label} ---\n{snippet}")
    return "".join(parts)


SKILL_ARCHIVE_EXTENSIONS = {".zip", ".skill"}


def _find_zip_files(directory: Path) -> list[Path]:
    """Find all .zip / .skill archive files in a directory."""
    return [
        f for f in sorted(directory.iterdir())
        if f.is_file() and f.suffix.lower() in SKILL_ARCHIVE_EXTENSIONS
    ]


def _normalize_zip_root(tmp: Path) -> Path:
    """Implement spec §4.1: unwrap single top-level directory if no top-level files exist.

    Ignores __MACOSX so that archives with macOS metadata still unwrap to the
    single content directory (e.g. 065bbc1dae4e4b53be9918251c064761/).
    """
    children = list(tmp.iterdir())
    top_dirs = [c for c in children if c.is_dir()]
    top_files = [c for c in children if c.is_file()]
    content_dirs = [c for c in top_dirs if c.name != "__MACOSX"]
    if len(content_dirs) == 1 and len(top_files) == 0:
        return content_dirs[0]
    return tmp


def _load_skill_from_zip(
    zip_path: Path,
    original_dir: Path,
) -> Generator[SkillFile, None, None]:
    """Extract a zip file to a temp directory and load the skill from it."""
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)

            # Normalize: unwrap single top-level directory per spec §4.1
            root = _normalize_zip_root(tmp)

            entry = _find_entry_file(root)
            if entry is None:
                logger.debug("No skill entry file in zip: %s", zip_path)
                return

            # Build SkillFile but use original_dir for source/id/path
            entry_content = entry.read_text(encoding="utf-8", errors="replace")
            aux_segments = _collect_auxiliary_segments(root, entry)
            full_content = _segments_to_combined_content(entry_content, aux_segments)
            source = detect_source(original_dir)

            file_md5s, file_sha1s = _collect_file_hashes(root)
            pkg_md5, pkg_sha1 = _hash_bytes(zip_path.read_bytes())

            entry_rel = entry.relative_to(root).as_posix()
            entry_seg = SkillFileSegment(rel_path=entry_rel, content=entry_content, is_entry=True)
            all_segments = [entry_seg] + aux_segments

            yield SkillFile(
                id=generate_id(original_dir),
                source=source,
                file_path=str(original_dir / zip_path.name),
                content=full_content,
                size_bytes=len(full_content.encode("utf-8")),
                name=original_dir.name,
                entry_file=entry_rel,
                skill_dir=str(original_dir),
                file_md5s=file_md5s,
                file_sha1s=file_sha1s,
                package_md5=pkg_md5,
                package_sha1=pkg_sha1,
                files=all_segments,
            )
    except (zipfile.BadZipFile, OSError) as e:
        logger.warning("Failed to process zip %s: %s", zip_path, e)


def load_skills(
    root_dir: str | Path,
    extensions: set[str] | None = None,
) -> Generator[SkillFile, None, None]:
    """Yield SkillFile objects from the given directory tree.

    Supports three layouts:
    1. Zip-based: <root>/<author>/<skill>/*.zip (clawhub_data style)
    2. Directory-based: directories containing SKILL.md
    3. Flat files: individual text files as fallback
    """
    root = Path(root_dir)

    if not root.exists():
        logger.error("Directory does not exist: %s", root)
        return

    visited_dirs: set[Path] = set()

    for skill_dir in sorted(root.iterdir()):
        if not skill_dir.is_dir():
            continue

        # Check if this directory directly contains zip files (flat zip layout)
        zips = _find_zip_files(skill_dir)
        if zips:
            for zp in zips:
                yield from _load_skill_from_zip(zp, skill_dir)
            visited_dirs.add(skill_dir)
            continue

        # Check if this is a skill directory with an entry file
        entry = _find_entry_file(skill_dir)
        if entry is not None:
            yield from _load_one_skill(skill_dir, entry)
            visited_dirs.add(skill_dir)
            continue

        # Not a direct skill dir — scan subdirectories (author/<skill>/ layout)
        for sub in sorted(skill_dir.rglob("*")):
            if not sub.is_dir():
                continue

            # Check for zips in subdirectory
            sub_zips = _find_zip_files(sub)
            if sub_zips:
                for zp in sub_zips:
                    yield from _load_skill_from_zip(zp, sub)
                visited_dirs.add(sub)
                continue

            # Check for entry file in subdirectory
            sub_entry = _find_entry_file(sub)
            if sub_entry:
                yield from _load_one_skill(sub, sub_entry)
                visited_dirs.add(sub)

    # If root itself has an entry file (flat structure) — direct children only.
    # Using _find_entry_file_direct (not recursive) prevents re-yielding skills
    # that were already discovered in subdirectories via the loop above.
    root_entry = _find_entry_file_direct(root)
    if root_entry:
        yield from _load_one_skill(root, root_entry)

    # Fallback: if root has no subdirectories with SKILL.md, treat individual
    # files as skills (backward compatibility for flat file collections)
    if not visited_dirs and not root_entry:
        exts = extensions or SUPPORTED_EXTENSIONS
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in exts:
                continue
            try:
                raw = path.read_bytes()
                content = raw.decode("utf-8", errors="replace")
                source = detect_source(path)
                m, s = _hash_bytes(raw)
                rel = path.name
                yield SkillFile(
                    id=generate_id(path),
                    source=source,
                    file_path=str(path),
                    content=content,
                    size_bytes=len(raw),
                    name=path.stem,
                    entry_file=path.name,
                    skill_dir=str(path.parent),
                    file_md5s={rel: m},
                    file_sha1s={rel: s},
                    files=[SkillFileSegment(rel_path=rel, content=content, is_entry=True)],
                )
            except OSError as e:
                logger.warning("Failed to read %s: %s", path, e)


def _load_one_skill(skill_dir: Path, entry: Path) -> Generator[SkillFile, None, None]:
    """Load a single skill directory as one SkillFile."""
    try:
        entry_content = entry.read_text(encoding="utf-8", errors="replace")
        aux_segments = _collect_auxiliary_segments(skill_dir, entry)
        full_content = _segments_to_combined_content(entry_content, aux_segments)
        source = detect_source(skill_dir)
        file_md5s, file_sha1s = _collect_file_hashes(skill_dir)

        entry_rel = entry.relative_to(skill_dir).as_posix()
        entry_seg = SkillFileSegment(rel_path=entry_rel, content=entry_content, is_entry=True)
        all_segments = [entry_seg] + aux_segments

        yield SkillFile(
            id=generate_id(skill_dir),
            source=source,
            file_path=str(entry),
            content=full_content,
            size_bytes=len(full_content.encode("utf-8")),
            name=skill_dir.name,
            entry_file=entry_rel,
            skill_dir=str(skill_dir),
            file_md5s=file_md5s,
            file_sha1s=file_sha1s,
            files=all_segments,
        )
    except OSError as e:
        logger.warning("Failed to read skill at %s: %s", skill_dir, e)
