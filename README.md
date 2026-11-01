# Codebase Explorer MCP Server

A read-only Model Context Protocol (MCP) server for exploring any project on your machine.

## Features

- **list_files** — List files and folders recursively inside a project.
- **read_file** — Read text or source-code files with optional line ranges.
- **search_code** — Search for a word or phrase inside text and source-code files (supports plain text and regex).
- **get_project_overview** — Generate a technical overview: languages, file statistics, dependency files, documentation.
- **get_file_tree** — Get a nested tree of files and folders with depth control.
- **find_definitions** — Find classes, functions, and methods in Python files via AST parsing.
- **detect_frameworks** — Detect frameworks and technologies by reading dependency files (`requirements.txt`, `pyproject.toml`, `package.json`, etc.).
- **get_dependency_graph** — Show which Python files import what (internal, stdlib, external, unresolved).

## Safety

- Read-only: no files are modified or deleted.
- Blocks sensitive files (`.env`, SSH keys, `.pem`, `.key`, passwords, etc.).
- Ignores `.git`, `node_modules`, `.venv`, `__pycache__`, `dist`, `build`, and other common directories.
- Limits depth, result counts, and file sizes to prevent runaway operations.
- Optional ReDoS protection via the `regex` package with per-line timeouts.

## Requirements

- Python 3.10+
- `mcp>=2`
- `regex` (optional, for ReDoS protection)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the server:

```bash
python server.py
```

Configure it in your MCP client (e.g. Cursor, Windsurf, Claude Desktop) to explore local projects.

## License

MIT