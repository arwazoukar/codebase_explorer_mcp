"""
Codebase Explorer - a read-only MCP server for exploring any project
on your machine (list files, read files, search code, find definitions,
detect frameworks and build a Python import graph).

Requires: Python 3.10+ and mcp>=2   (optional: regex, for safe regex search)
"""

import ast
import fnmatch
import json
import os
import re
import sys
from pathlib import Path
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

# The optional "regex" package lets us put a time limit on regex searches,
# which protects the server from patterns that never finish (ReDoS).
try:
    import regex as regex_engine
    REGEX_HAS_TIMEOUT = True
except ImportError:
    regex_engine = re
    REGEX_HAS_TIMEOUT = False

mcp = MCPServer("Codebase Explorer")

READ_ONLY = ToolAnnotations(readOnlyHint=True)


# ==========================================
# Configuration
# ==========================================

# Leave EMPTY to let the server work on any project on this machine.
# To restrict it, add folders here, or set the environment variable
# MCP_ALLOWED_ROOTS (separate paths with ";" on Windows, ":" on Linux/macOS).
# Example: ALLOWED_ROOTS = {r"C:\path\to\your\projects"}
ALLOWED_ROOTS = set()

ALLOWED_ROOTS.update(
    path
    for path in os.environ.get("MCP_ALLOWED_ROOTS", "").split(os.pathsep)
    if path
)

IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    "dist",
    "build",
    ".idea",
    ".vscode",
}

SENSITIVE_FILES = {
    ".env",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
    "id_dsa",
    "id_dsa.pub",
    "id_ecdsa",
    "id_ecdsa.pub",
    "credentials",
    "secrets",
    "secret",
    "passwd",
    "password",
    ".htpasswd",
    ".netrc",
    ".npmrc",
}

SENSITIVE_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".crt",
    ".der",
    ".enc",
    ".gpg",
    ".asc",
}

BLOCKED_EXTENSIONS = {
    ".db",
    ".sqlite",
    ".sqlite3",
}

# Normal source-code files are never hidden just because their NAME contains
# a word like "password" or "secret" (e.g. password_utils.py is fine).
SOURCE_CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs",
    ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".hpp", ".dart", ".swift",
    ".html", ".css", ".scss", ".vue", ".svelte",
}

SENSITIVE_NAME_TOKENS = ("secret", "credential", "password", "passwd", "npmrc")

# id_rsa, id_ed25519.pub, id_rsa_backup ... but NOT id_generator.py
SSH_KEY_NAME_RE = re.compile(r"id_(rsa|dsa|ecdsa|ed25519)([._-].*)?")

MAX_DEPTH = 5
MAX_RESULTS = 300
MAX_FILE_SIZE = 500_000  # 500 KB
MAX_OUTPUT_LINES = 500          # cap for tree / definitions / dependency graph
MAX_PY_FILES_TO_PARSE = 2000    # cap for tools that parse Python files

MAX_REGEX_LINE_LENGTH = 2000    # longer lines are cut before regex matching
REGEX_TIMEOUT_SECONDS = 0.5     # per-line time limit (needs the "regex" package)

# Detects risky patterns like (a+)+ when the "regex" package is not installed.
NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d+,\d*\})"
)


# ==========================================
# Helper Functions
# ==========================================

def is_sensitive_file(filename: str) -> bool:
    name = filename.lower()
    suffix = Path(name).suffix

    if name in SENSITIVE_FILES:
        return True

    if name == ".env" or name.startswith(".env."):
        return True

    if SSH_KEY_NAME_RE.fullmatch(name):
        return True

    if suffix in SENSITIVE_SUFFIXES:
        return True

    # Names like "passwords.txt" or "secrets.json" are blocked,
    # but real source-code files (password_utils.py) are allowed.
    if suffix not in SOURCE_CODE_SUFFIXES:
        for token in SENSITIVE_NAME_TOKENS:
            if token in name:
                return True

    return False


def is_path_blocked(root: Path, path: Path) -> bool:
    """
    Return True if the path should be skipped or blocked:
    - Outside the project root
    - Inside an ignored directory (.git, node_modules, etc.)
    - A symbolic link
    - A sensitive file
    - A blocked file extension
    """

    try:
        relative = path.relative_to(root)
    except ValueError:
        return True

    for part in relative.parts:
        if part in IGNORED_DIRS:
            return True

    if path.is_symlink():
        return True

    if is_sensitive_file(path.name):
        return True

    if path.suffix.lower() in BLOCKED_EXTENSIONS:
        return True

    return False


def validate_project_path(project_path: str) -> Path:
    """Validate and resolve the project directory."""

    root = Path(project_path).expanduser().resolve(strict=True)

    if not root.is_dir():
        raise NotADirectoryError("Project path is not a directory.")

    if ALLOWED_ROOTS:
        allowed = False

        for allowed_root in ALLOWED_ROOTS:
            try:
                allowed_root_path = (
                    Path(allowed_root).expanduser().resolve(strict=False)
                )
                if root.is_relative_to(allowed_root_path):
                    allowed = True
                    break
            except (OSError, ValueError):
                continue

        if not allowed:
            raise PermissionError(
                "Project path is not within an allowed root directory."
            )

    return root


def validate_path_components(root: Path, relative_path: str) -> Path:
    """
    Validate a relative path and reject:
    - Parent directory traversal
    - Absolute paths
    - Symbolic links
    - Ignored directories (.git, node_modules, etc.)
    - Paths outside the project
    """

    requested = Path(relative_path)

    if requested.is_absolute() or requested.drive:
        raise ValueError("Absolute paths are not allowed.")

    if ".." in requested.parts:
        raise ValueError("Parent directory traversal is not allowed.")

    current = root

    for part in requested.parts:
        if part in ("", "."):
            continue

        if part in IGNORED_DIRS:
            raise ValueError(f"Access to '{part}' is not allowed.")

        current = current / part

        if current.is_symlink():
            raise ValueError("Symbolic links are not allowed.")

    resolved = current.resolve(strict=True)

    if not resolved.is_relative_to(root):
        raise ValueError("Requested path is outside the project.")

    return resolved



# ==========================================
# Tool 1: List Files
# ==========================================

@mcp.tool(annotations=READ_ONLY)
def list_files(project_path: str, relative_path: str = ".") -> str:
    """
    List files and folders recursively inside a project.

    project_path: Full path to the project directory.
    relative_path: Optional folder inside the project.
    """

    try:
        root = validate_project_path(project_path)

        start = validate_path_components(root, relative_path)

        if not start.is_dir():
            return "Error: The requested path is not a directory."

        results = [
            f"Project: {root}",
            f"Exploring: {start.relative_to(root)}",
            "-" * 40,
        ]

        for current, dirs, files in os.walk(
            start,
            topdown=True,
            followlinks=False,
        ):
            current_path = Path(current)

            # Ignore unwanted and symbolic-link directories
            dirs[:] = sorted(
                directory
                for directory in dirs
                if not is_path_blocked(root, current_path / directory)
            )

            depth = len(current_path.relative_to(start).parts)

            if depth >= MAX_DEPTH:
                dirs.clear()

            # List directories
            for directory in dirs:
                folder_path = current_path / directory

                results.append(
                    f"[DIR]  {folder_path.relative_to(root)}"
                )

                if len(results) >= MAX_RESULTS:
                    break

            if len(results) >= MAX_RESULTS:
                break

            # List files
            for filename in sorted(files):
                file_path = current_path / filename

                # Skip blocked files (sensitive, symlinks, ignored dirs, etc.)
                if is_path_blocked(root, file_path):
                    continue

                results.append(
                    f"[FILE] {file_path.relative_to(root)}"
                )

                if len(results) >= MAX_RESULTS:
                    break

            if len(results) >= MAX_RESULTS:
                break

        if len(results) >= MAX_RESULTS:
            results.append(
                f"\nResults limited to {MAX_RESULTS}."
            )

        return "\n".join(results)

    except FileNotFoundError:
        return "Error: Project or requested folder does not exist."

    except PermissionError:
        return "Error: Permission denied."

    except ValueError as error:
        return f"Error: {error}"

    except OSError as error:
        return f"Error accessing project: {error}"



# ==========================================
# Tool 2: Read File
# ==========================================

@mcp.tool(annotations=READ_ONLY)
def read_file(
    project_path: str,
    file_path: str,
    start_line: int | None = None,
    end_line: int | None = None,
) -> str:
    """
    Read a text or source-code file from a project.

    project_path: Full path to the project directory.
    file_path: File path relative to the project directory.
    start_line: Optional 1-based line number to start reading from.
    end_line: Optional 1-based line number to stop reading at (inclusive).
    """

    try:
        root = validate_project_path(project_path)

        target = validate_path_components(root, file_path)

        if not target.is_file():
            return "Error: The requested path is not a file."

        if is_path_blocked(root, target):
            return "Error: Reading this file is not allowed."

        file_size = target.stat().st_size

        if file_size > MAX_FILE_SIZE:
            return (
                f"Error: File is larger than {MAX_FILE_SIZE} bytes. "
                "Reading large files is not supported."
            )

        lines = target.read_text(encoding="utf-8").splitlines()

        total_lines = len(lines)

        if start_line is not None and start_line < 1:
            return "Error: start_line must be >= 1."

        if end_line is not None and end_line < 1:
            return "Error: end_line must be >= 1."

        if (
            start_line is not None
            and end_line is not None
            and end_line < start_line
        ):
            return "Error: end_line must be >= start_line."

        if (
            start_line is not None
            and total_lines > 0
            and start_line > total_lines
        ):
            return (
                f"Error: start_line ({start_line}) exceeds "
                f"total lines ({total_lines})."
            )

        # An end_line past the end of the file is simply clamped.
        first = start_line or 1
        last = min(end_line, total_lines) if end_line is not None else total_lines

        content = "\n".join(lines[first - 1:last])

        line_range = f"Lines {first}-{last}" if total_lines else "Empty file"

        return (
            f"File: {target.relative_to(root)}\n"
            f"Size: {file_size} bytes\n"
            f"Range: {line_range} of {total_lines}\n"
            f"{'-' * 40}\n"
            f"{content}"
        )

    except FileNotFoundError:
        return "Error: Project or file does not exist."

    except PermissionError:
        return "Error: Permission denied."

    except UnicodeDecodeError:
        return "Error: This file is not valid UTF-8 text."

    except ValueError as error:
        return f"Error: {error}"

    except OSError as error:
        return f"Error reading file: {error}"

# ==========================================
# Tool 3: Search Code
# ==========================================

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".css",
    ".scss",
    ".json",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".sql",
    ".xml",
    ".sh",
    ".bat",
    ".ps1",
}

TEXT_FILENAMES = {
    "dockerfile",
    "makefile",
    ".gitignore",
    ".dockerignore",
}

MAX_SEARCH_RESULTS = 100
MAX_SEARCH_LINE_LENGTH = 300


@mcp.tool(annotations=READ_ONLY)
def search_code(
    project_path: str,
    query: str,
    relative_path: str = ".",
    use_regex: bool = False,
    file_pattern: str | None = None,
) -> str:
    """
    Search for a word or phrase inside text and source-code files.

    project_path: Full path to the project directory.
    query: Text to search for (case-insensitive).
    relative_path: Optional folder inside the project.
    use_regex: Treat query as a regular expression (also case-insensitive).
    file_pattern: Optional glob pattern or extension filter (e.g. "*.py" or ".py").
    """

    try:
        root = validate_project_path(project_path)

        if not query or not query.strip():
            return "Error: Search query cannot be empty."

        if len(query) > 200:
            return "Error: Search query is too long (maximum 200 characters)."

        start = validate_path_components(root, relative_path)

        if not start.is_dir():
            return "Error: The requested path is not a directory."

        # Compile regex when requested; validate pattern up front.
        compiled_regex = None
        if use_regex:
            if not REGEX_HAS_TIMEOUT and NESTED_QUANTIFIER_RE.search(query):
                return (
                    "Error: This regex looks like it could run extremely "
                    "slowly (nested repetition such as (a+)+). "
                    "Please simplify it."
                )

            try:
                compiled_regex = regex_engine.compile(
                    query, regex_engine.IGNORECASE
                )
            except regex_engine.error as error:
                return f"Error: Invalid regular expression: {error}"

        # Normalize file pattern for matching.
        pattern = file_pattern.strip() if file_pattern else None

        def matches_file_pattern(filename: str, suffix: str) -> bool:
            if not pattern:
                return True

            lower_pattern = pattern.lower()
            lower_filename = filename.lower()
            lower_suffix = suffix.lower()

            # Direct extension match (e.g. ".py" or "py")
            if lower_pattern.startswith("."):
                if lower_suffix == lower_pattern:
                    return True
                if lower_suffix == lower_pattern.lstrip("."):
                    return True
                return False

            # Wildcard glob match (e.g. "*.py", "test_*")
            if "*" in lower_pattern or "?" in lower_pattern:
                return fnmatch.fnmatch(lower_filename, lower_pattern)

            # Substring match on filename or extension
            if lower_pattern in lower_filename or (
                lower_suffix and lower_pattern in lower_suffix
            ):
                return True

            return False

        matches = []
        total_matches = 0

        for current, dirs, files in os.walk(
            start,
            topdown=True,
            followlinks=False,
        ):
            current_path = Path(current)

            # Skip ignored and symbolic-link directories
            dirs[:] = sorted(
                directory
                for directory in dirs
                if not is_path_blocked(root, current_path / directory)
            )

            for filename in sorted(files):
                file_path = current_path / filename

                # Skip blocked files (sensitive, symlinks, ignored dirs, etc.)
                if is_path_blocked(root, file_path):
                    continue

                suffix = file_path.suffix.lower()

                # Apply file pattern filter
                if not matches_file_pattern(filename, suffix):
                    continue

                if (
                    suffix not in TEXT_EXTENSIONS
                    and filename.lower() not in TEXT_FILENAMES
                ):
                    continue

                try:
                    resolved_file = file_path.resolve(strict=True)

                    if not resolved_file.is_relative_to(root):
                        continue

                    if not resolved_file.is_file():
                        continue

                    if resolved_file.stat().st_size > MAX_FILE_SIZE:
                        continue

                    content = resolved_file.read_text(
                        encoding="utf-8"
                    )

                except (
                    OSError,
                    UnicodeDecodeError,
                ):
                    continue

                for line_number, line in enumerate(
                    content.splitlines(),
                    start=1,
                ):
                    if compiled_regex is not None:
                        text = line[:MAX_REGEX_LINE_LENGTH]

                        try:
                            if REGEX_HAS_TIMEOUT:
                                matched = compiled_regex.search(
                                    text, timeout=REGEX_TIMEOUT_SECONDS
                                ) is not None
                            else:
                                matched = compiled_regex.search(text) is not None
                        except TimeoutError:
                            return (
                                "Error: The regex took too long to run. "
                                "Please use a simpler pattern."
                            )
                    else:
                        matched = query.casefold() in line.casefold()

                    if not matched:
                        continue

                    total_matches += 1

                    if len(matches) < MAX_SEARCH_RESULTS:
                        displayed_line = line.strip()

                        if len(displayed_line) > MAX_SEARCH_LINE_LENGTH:
                            displayed_line = (
                                displayed_line[:MAX_SEARCH_LINE_LENGTH]
                                + "..."
                            )

                        relative_file = resolved_file.relative_to(root)

                        matches.append(
                            f"{relative_file}:{line_number}\n"
                            f"    {displayed_line}"
                        )

                    if total_matches >= MAX_SEARCH_RESULTS:
                        break

                if total_matches >= MAX_SEARCH_RESULTS:
                    break

            if total_matches >= MAX_SEARCH_RESULTS:
                break

        if not matches:
            return f"No matches found for: {query}"

        result = [
            f"Search query: {query}",
            f"Project: {root}",
            f"Matches found: {total_matches}",
            "-" * 40,
            *matches,
        ]

        if total_matches >= MAX_SEARCH_RESULTS:
            result.append(
                f"\nSearch stopped at {MAX_SEARCH_RESULTS} matches."
            )

        return "\n".join(result)

    except FileNotFoundError:
        return "Error: Project or requested folder does not exist."

    except PermissionError:
        return "Error: Permission denied."

    except ValueError as error:
        return f"Error: {error}"

    except OSError as error:
        return f"Error searching project: {error}"

# ==========================================
# Tool 4: Get Project Overview
# ==========================================

@mcp.tool(annotations=READ_ONLY)
def get_project_overview(project_path: str) -> str:
    """
    Generate a technical overview of a project.

    Includes programming languages, file statistics, dependency files,
    and documentation files. (For the folder structure use get_file_tree.)
    """

    try:
        root = validate_project_path(project_path)

        file_counts = {}
        language_counts = {}
        dependency_files = []
        documentation_files = []

        total_files = 0
        total_directories = 0
        skipped_files = 0
        max_files_to_scan = 10000
        scan_limit_reached = False

        LANGUAGE_MAP = {
            ".py": "Python",
            ".js": "JavaScript",
            ".jsx": "JavaScript React",
            ".ts": "TypeScript",
            ".tsx": "TypeScript React",
            ".html": "HTML",
            ".css": "CSS",
            ".scss": "SCSS",
            ".java": "Java",
            ".cpp": "C++",
            ".c": "C",
            ".cs": "C#",
            ".php": "PHP",
            ".go": "Go",
            ".rs": "Rust",
            ".rb": "Ruby",
            ".sql": "SQL",
            ".dart": "Dart",
        }

        DEPENDENCY_FILES = {
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "poetry.lock",
            "pipfile",
            "cargo.toml",
            "go.mod",
            "pom.xml",
            "build.gradle",
        }

        DOCUMENTATION_FILES = {
            "readme.md",
            "readme.txt",
            "readme",
            "contributing.md",
            "architecture.md",
            "changelog.md",
        }

        for current, dirs, files in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            current_path = Path(current)

            # Filter ignored directories and symbolic links
            safe_dirs = []

            for directory in sorted(dirs):
                folder_path = current_path / directory

                if is_path_blocked(root, folder_path):
                    continue

                try:
                    resolved_folder = folder_path.resolve(strict=True)

                    if not resolved_folder.is_relative_to(root):
                        continue

                    if not resolved_folder.is_dir():
                        continue

                except OSError:
                    continue

                safe_dirs.append(directory)

            dirs[:] = safe_dirs
            total_directories += len(dirs)

            for filename in sorted(files):
                if total_files >= max_files_to_scan:
                    scan_limit_reached = True
                    break

                file_path = current_path / filename

                # Skip blocked files (sensitive, symlinks, ignored dirs, etc.)
                if is_path_blocked(root, file_path):
                    skipped_files += 1
                    continue

                try:
                    resolved = file_path.resolve(strict=True)

                    if not resolved.is_relative_to(root):
                        skipped_files += 1
                        continue

                    if not resolved.is_file():
                        continue

                except OSError:
                    skipped_files += 1
                    continue

                total_files += 1

                extension = (
                    file_path.suffix.lower() or "[no extension]"
                )

                file_counts[extension] = (
                    file_counts.get(extension, 0) + 1
                )

                language = LANGUAGE_MAP.get(
                    file_path.suffix.lower()
                )

                if language:
                    language_counts[language] = (
                        language_counts.get(language, 0) + 1
                    )

                filename_lower = filename.lower()
                relative_file = str(file_path.relative_to(root))

                if filename_lower in DEPENDENCY_FILES:
                    dependency_files.append(relative_file)

                if filename_lower in DOCUMENTATION_FILES:
                    documentation_files.append(relative_file)

            if scan_limit_reached:
                break

        # Build overview report
        report = [
            f"PROJECT OVERVIEW: {root.name}",
            "=" * 40,
            f"Project path: {root}",
            f"Total files scanned: {total_files}",
            f"Total directories: {total_directories}",
            f"Skipped sensitive/blocked files: {skipped_files}",
        ]

        if scan_limit_reached:
            report.append(
                f"Warning: Scan stopped at {max_files_to_scan} files."
            )

        report.append("\nPROGRAMMING LANGUAGES:")

        if language_counts:
            for language, count in sorted(
                language_counts.items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                report.append(f"- {language}: {count} files")
        else:
            report.append(
                "- No recognized programming languages found."
            )

        report.append("\nFILE TYPES:")

        for extension, count in sorted(
            file_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:15]:
            report.append(f"- {extension}: {count}")

        report.append("\nDEPENDENCY FILES:")

        if dependency_files:
            report.extend(
                f"- {item}" for item in sorted(dependency_files)
            )
        else:
            report.append("- None found.")

        report.append("\nDOCUMENTATION FILES:")

        if documentation_files:
            report.extend(
                f"- {item}" for item in sorted(documentation_files)
            )
        else:
            report.append("- None found.")

        return "\n".join(report)

    except FileNotFoundError:
        return "Error: Project directory does not exist."

    except PermissionError:
        return "Error: Permission denied."

    except ValueError as error:
        return f"Error: {error}"

    except OSError as error:
        return f"Error generating project overview: {error}"


# ==========================================
# Tool 5: Get File Tree
# ==========================================

@mcp.tool(annotations=READ_ONLY)
def get_file_tree(
    project_path: str,
    relative_path: str = ".",
    max_depth: int | None = None,
) -> str:
    """
    Get a nested tree of files and folders inside a project.

    project_path: Full path to the project directory.
    relative_path: Optional folder inside the project to start from.
    max_depth: Optional depth to traverse (default and maximum: 5).
    """

    try:
        root = validate_project_path(project_path)

        start = validate_path_components(root, relative_path)

        if not start.is_dir():
            return "Error: The requested path is not a directory."

        depth_limit = (
            MAX_DEPTH if max_depth is None else max(1, min(max_depth, MAX_DEPTH))
        )
        truncated = {"value": False}

        lines = [
            f"Project: {root.name}",
            f"Root: {root}",
            f"Exploring: {start.relative_to(root)}",
            "-" * 40,
        ]

        def build_tree(current: Path, prefix: str, current_depth: int) -> None:
            if current_depth >= depth_limit:
                return

            try:
                entries = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            except OSError:
                return

            dirs = [e for e in entries if e.is_dir() and not e.is_symlink()]
            files = [e for e in entries if e.is_file() and not e.is_symlink()]

            # Filter directories
            visible_dirs = [
                d for d in dirs
                if not is_path_blocked(root, d)
            ]

            # Filter files
            visible_files = [
                f for f in files
                if not is_path_blocked(root, f)
            ]

            total = visible_dirs + visible_files

            for index, entry in enumerate(total):
                if len(lines) >= MAX_OUTPUT_LINES:
                    truncated["value"] = True
                    return

                is_last = index == len(total) - 1
                connector = "└── " if is_last else "├── "
                lines.append(f"{prefix}{connector}{entry.name}")

                if entry.is_dir() and not entry.is_symlink():
                    extension = "    " if is_last else "│   "
                    build_tree(entry, prefix + extension, current_depth + 1)

        build_tree(start, "", 0)

        if truncated["value"]:
            lines.append(
                f"\n... Output limited to {MAX_OUTPUT_LINES} lines. "
                "Use relative_path to explore a specific folder."
            )

        return "\n".join(lines)

    except FileNotFoundError:
        return "Error: Project or requested folder does not exist."

    except PermissionError:
        return "Error: Permission denied."

    except ValueError as error:
        return f"Error: {error}"

    except OSError as error:
        return f"Error building file tree: {error}"


# ==========================================
# Shared helpers for the Python-aware tools
# ==========================================

def iter_safe_files(root: Path, start: Path):
    """Yield every file under `start` that is safe to look at."""

    for current, dirs, files in os.walk(
        start,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)

        dirs[:] = sorted(
            directory
            for directory in dirs
            if not is_path_blocked(root, current_path / directory)
        )

        for filename in sorted(files):
            file_path = current_path / filename

            if is_path_blocked(root, file_path):
                continue

            yield file_path


def parse_python_file(root: Path, file_path: Path):
    """
    Safely parse a Python file.
    Returns (resolved_path, syntax_tree) or None if the file can't be used.
    """

    try:
        if is_path_blocked(root, file_path):
            return None

        resolved = file_path.resolve(strict=True)

        if not resolved.is_relative_to(root) or not resolved.is_file():
            return None

        if resolved.stat().st_size > MAX_FILE_SIZE:
            return None

        source = resolved.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(resolved))

        return resolved, tree

    except (
        OSError,
        UnicodeDecodeError,
        SyntaxError,
        ValueError,
        RecursionError,
        MemoryError,
    ):
        return None


# ==========================================
# Tool 6: Find Definitions
# ==========================================

def collect_definitions(node, prefix: str = "", in_class: bool = False):
    """
    Walk a syntax tree in source order and yield (kind, qualified_name, line).
    Methods are reported as ClassName.method_name.
    """

    for child in ast.iter_child_nodes(node):
        # Expressions can't contain definitions, so skip them.
        if isinstance(child, ast.expr):
            continue

        if isinstance(child, ast.ClassDef):
            qualified = prefix + child.name
            yield ("class", qualified, child.lineno)
            yield from collect_definitions(child, qualified + ".", True)

        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified = prefix + child.name
            kind = "method" if in_class else "function"
            yield (kind, qualified, child.lineno)
            yield from collect_definitions(child, qualified + ".", False)

        else:
            yield from collect_definitions(child, prefix, in_class)


@mcp.tool(annotations=READ_ONLY)
def find_definitions(
    project_path: str,
    relative_path: str = ".",
) -> str:
    """
    Find classes, functions and methods in Python files.
    Methods are shown as ClassName.method_name with their line number.

    project_path: Full path to the project directory.
    relative_path: Optional folder inside the project to scan.
    """

    try:
        root = validate_project_path(project_path)

        start = validate_path_components(root, relative_path)

        if not start.is_dir():
            return "Error: The requested path is not a directory."

        lines = []
        total = 0
        files_parsed = 0
        file_limit_reached = False

        for file_path in iter_safe_files(root, start):
            if file_path.suffix.lower() != ".py":
                continue

            if files_parsed >= MAX_PY_FILES_TO_PARSE:
                file_limit_reached = True
                break

            parsed = parse_python_file(root, file_path)

            if parsed is None:
                continue

            files_parsed += 1
            resolved, tree = parsed
            relative_file = resolved.relative_to(root)

            try:
                definitions = list(collect_definitions(tree))
            except RecursionError:
                continue

            for kind, name, line_number in definitions:
                total += 1

                if len(lines) < MAX_OUTPUT_LINES:
                    lines.append(
                        f"{kind}: {name} ({relative_file}:{line_number})"
                    )

        if total == 0:
            return "No definitions found."

        result = [
            f"Project: {root}",
            f"Python files scanned: {files_parsed}",
            f"Definitions found: {total}",
            "-" * 40,
            *lines,
        ]

        if total > len(lines):
            result.append(
                f"\nShowing the first {len(lines)} of {total} definitions. "
                "Use relative_path to scan a specific folder."
            )

        if file_limit_reached:
            result.append(
                f"\nScan stopped after {MAX_PY_FILES_TO_PARSE} Python files."
            )

        return "\n".join(result)

    except FileNotFoundError:
        return "Error: Project or requested folder does not exist."

    except PermissionError:
        return "Error: Permission denied."

    except ValueError as error:
        return f"Error: {error}"

    except OSError as error:
        return f"Error finding definitions: {error}"


# ==========================================
# Tool 7: Detect Frameworks
# ==========================================

# framework name -> exact package name to look for
FRAMEWORK_SIGNATURES = {
    "Python": {
        "Django": "django",
        "Flask": "flask",
        "FastAPI": "fastapi",
        "Pyramid": "pyramid",
        "Tornado": "tornado",
    },
    "JavaScript/TypeScript": {
        "React": "react",
        "Next.js": "next",
        "Vue": "vue",
        "Angular": "@angular/core",
        "Svelte": "svelte",
        "Express": "express",
        "NestJS": "@nestjs/core",
    },
}

# Only real "dependency list" files are checked.
# Lock files are skipped on purpose: they are huge and mention
# hundreds of unrelated packages.
MANIFEST_FILES = {
    "requirements.txt": "Python",
    "pyproject.toml": "Python",
    "pipfile": "Python",
    "package.json": "JavaScript/TypeScript",
}


def normalize_package_name(name: str) -> str:
    return name.lower().replace("_", "-")


def package_names_from_manifest(filename_lower: str, content: str) -> set:
    """Return the exact package names mentioned in a dependency file."""

    names = set()

    if filename_lower == "package.json":
        try:
            data = json.loads(content)
        except ValueError:
            return names

        if isinstance(data, dict):
            for section in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ):
                dependencies = data.get(section)

                if isinstance(dependencies, dict):
                    names.update(normalize_package_name(key) for key in dependencies)

        return names

    # Text-based files: split into whole words, so that
    # "next-themes" is one word and never matches "next".
    without_comments = "\n".join(
        line.split("#", 1)[0] for line in content.splitlines()
    )

    for word in re.findall(r"[A-Za-z0-9_.\-]+", without_comments):
        names.add(normalize_package_name(word))

    return names


@mcp.tool(annotations=READ_ONLY)
def detect_frameworks(project_path: str) -> str:
    """
    Detect frameworks and technologies used in a project by reading
    its dependency files (requirements.txt, pyproject.toml, package.json...).

    project_path: Full path to the project directory.
    """

    try:
        root = validate_project_path(project_path)

        detected = {}

        for file_path in iter_safe_files(root, root):
            filename_lower = file_path.name.lower()

            language = MANIFEST_FILES.get(filename_lower)

            if language is None:
                continue

            try:
                resolved = file_path.resolve(strict=True)

                if not resolved.is_relative_to(root) or not resolved.is_file():
                    continue

                if resolved.stat().st_size > MAX_FILE_SIZE:
                    continue

                content = resolved.read_text(encoding="utf-8")

            except (OSError, UnicodeDecodeError):
                continue

            names = package_names_from_manifest(filename_lower, content)

            for framework, package in FRAMEWORK_SIGNATURES[language].items():
                if normalize_package_name(package) in names:
                    detected.setdefault(framework, set()).add(
                        str(resolved.relative_to(root))
                    )

        if not detected:
            return f"No frameworks detected in: {root}"

        lines = [
            f"Project: {root.name}",
            f"Root: {root}",
            "-" * 40,
            "Detected frameworks and technologies:",
        ]

        for framework, files in sorted(detected.items()):
            lines.append(f"- {framework}:")

            for found_in in sorted(files):
                lines.append(f"    {found_in}")

        return "\n".join(lines)

    except FileNotFoundError:
        return "Error: Project directory does not exist."

    except PermissionError:
        return "Error: Permission denied."

    except ValueError as error:
        return f"Error: {error}"

    except OSError as error:
        return f"Error detecting frameworks: {error}"


# ==========================================
# Cache (used by the dependency graph)
# ==========================================

MAX_CACHE_ENTRIES = 32

# key -> (result_text, fingerprint)
_CACHE = {}


def project_fingerprint(root: Path) -> dict:
    """
    A cheap "snapshot" of every Python file in the project
    (modified time + size). If it changes, the cached result is stale.
    """

    fingerprint = {}

    for file_path in iter_safe_files(root, root):
        if file_path.suffix.lower() != ".py":
            continue

        try:
            info = file_path.stat()
        except OSError:
            continue

        fingerprint[str(file_path.relative_to(root))] = (
            info.st_mtime_ns,
            info.st_size,
        )

    return fingerprint


def cache_lookup(key: str, fingerprint: dict):
    entry = _CACHE.get(key)

    if entry is not None and entry[1] == fingerprint:
        return entry[0]

    return None


def cache_store(key: str, value: str, fingerprint: dict) -> None:
    if key not in _CACHE and len(_CACHE) >= MAX_CACHE_ENTRIES:
        # Drop the oldest entry so the cache can't grow forever.
        _CACHE.pop(next(iter(_CACHE)))

    _CACHE[key] = (value, fingerprint)


def clear_cache() -> int:
    """Empty the cache (handy for tests). Returns how many entries were removed."""

    count = len(_CACHE)
    _CACHE.clear()
    return count


# ==========================================
# Tool 8: Get Dependency Graph
# ==========================================

# Python 3.10+: the official list of standard-library module names.
STDLIB_MODULES = sys.stdlib_module_names


def resolve_module_to_project_file(
    root: Path,
    current_file: Path,
    module_name: str,
    level: int = 0,
):
    """
    Find the project file behind an import.
    Returns a path relative to the project, or None if it isn't in the project.
    """

    parts = module_name.split(".") if module_name else []

    if level > 0:
        # Relative import: from . import x   /   from ..utils import y
        base = current_file.parent

        for _ in range(level - 1):
            base = base.parent

        bases = [base]

    else:
        if not parts:
            return None

        # Normal layout (root/pkg) and "src" layout (root/src/pkg)
        bases = [root, root / "src"]

    for base in bases:
        target = base.joinpath(*parts) if parts else base

        candidates = [target / "__init__.py"]

        if parts:
            candidates.insert(0, target.parent / f"{target.name}.py")

        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)

                if (
                    resolved.is_relative_to(root)
                    and resolved.is_file()
                    and not is_path_blocked(root, resolved)
                ):
                    return str(resolved.relative_to(root))

            except (OSError, ValueError):
                continue

    return None


def classify_import(
    root: Path,
    current_file: Path,
    module_name: str,
    level: int,
) -> tuple:
    """Return (type, target) where type is internal / stdlib / external / unresolved."""

    target = resolve_module_to_project_file(root, current_file, module_name, level)

    if target:
        return "internal", target

    if level > 0 or not module_name:
        return "unresolved", "." * level + module_name

    if module_name.split(".")[0] in STDLIB_MODULES:
        return "stdlib", module_name

    return "external", module_name


def imports_of_file(root: Path, current_file: Path, tree) -> dict:
    """Return {(type, target): first_line} for every import in a file."""

    edges = {}

    def add(edge_type: str, target: str, line: int) -> None:
        edges.setdefault((edge_type, target), line)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(*classify_import(root, current_file, alias.name, 0), node.lineno)

        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            level = node.level or 0
            linked_submodule = False

            # "from pkg import module" -> link to the module file itself
            for alias in node.names:
                if alias.name == "*":
                    continue

                dotted = f"{module_name}.{alias.name}" if module_name else alias.name
                target = resolve_module_to_project_file(
                    root, current_file, dotted, level
                )

                if target:
                    add("internal", target, node.lineno)
                    linked_submodule = True

            if not linked_submodule:
                add(*classify_import(root, current_file, module_name, level), node.lineno)

    return edges


@mcp.tool(annotations=READ_ONLY)
def get_dependency_graph(
    project_path: str,
    relative_path: str = ".",
) -> str:
    """
    Show which Python files import what.

    Each import is labelled:
    - internal: another file inside this project
    - stdlib: Python's built-in standard library
    - external: an installed third-party package
    - unresolved: a relative import that could not be matched to a file

    project_path: Full path to the project directory.
    relative_path: Optional folder inside the project to scan.
    """

    try:
        root = validate_project_path(project_path)

        start = validate_path_components(root, relative_path)

        if not start.is_dir():
            return "Error: The requested path is not a directory."

        # The key includes the folder, so "src" and "." are cached separately.
        cache_key = (
            f"dependency_graph:{root}:{start.relative_to(root).as_posix()}"
        )
        fingerprint = project_fingerprint(root)

        cached = cache_lookup(cache_key, fingerprint)

        if cached is not None:
            return cached

        graph = {}
        files_parsed = 0
        file_limit_reached = False

        for file_path in iter_safe_files(root, start):
            if file_path.suffix.lower() != ".py":
                continue

            if files_parsed >= MAX_PY_FILES_TO_PARSE:
                file_limit_reached = True
                break

            parsed = parse_python_file(root, file_path)

            if parsed is None:
                continue

            files_parsed += 1
            resolved, tree = parsed

            try:
                edges = imports_of_file(root, resolved, tree)
            except RecursionError:
                continue

            if edges:
                graph[str(resolved.relative_to(root))] = edges

        header = [
            f"Project: {root.name}",
            f"Root: {root}",
            f"Python files scanned: {files_parsed}",
            "-" * 40,
        ]

        if not graph:
            result = "\n".join(header + ["No import dependencies found."])

        else:
            lines = ["Dependency graph:"]
            truncated = False

            for importer, edges in sorted(graph.items()):
                if len(lines) >= MAX_OUTPUT_LINES:
                    truncated = True
                    break

                lines.append(f"\n{importer}:")

                for (edge_type, target), line_number in sorted(
                    edges.items(), key=lambda item: item[1]
                ):
                    lines.append(f"  [{edge_type}] {target} (line {line_number})")

            if truncated:
                lines.append(
                    f"\n... Output limited to about {MAX_OUTPUT_LINES} lines. "
                    "Use relative_path to scan a specific folder."
                )

            if file_limit_reached:
                lines.append(
                    f"\nScan stopped after {MAX_PY_FILES_TO_PARSE} Python files."
                )

            result = "\n".join(header + lines)

        cache_store(cache_key, result, fingerprint)

        return result

    except FileNotFoundError:
        return "Error: Project or requested folder does not exist."

    except PermissionError:
        return "Error: Permission denied."

    except ValueError as error:
        return f"Error: {error}"

    except OSError as error:
        return f"Error building dependency graph: {error}"


# ==========================================
# Start MCP Server
# ==========================================

if __name__ == "__main__":
    mcp.run()
