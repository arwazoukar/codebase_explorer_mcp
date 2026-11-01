import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import server  # noqa: E402


def _make_project(tmp_path, files):
    """Create a project directory with the given files.

    files: dict of relative_path -> content.
           Empty dict values create an empty directory.
    """
    for rel, content in files.items():
        target = tmp_path / rel
        if isinstance(content, dict):
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    return tmp_path


def _try_symlink(target, link_path):
    """Create a symlink; return False if not supported (e.g. Windows)."""
    try:
        os.symlink(target, link_path)
        return True
    except (OSError, NotImplementedError):
        return False


# ==========================================
# Path Traversal Tests
# ==========================================

def test_path_traversal_blocked(tmp_path):
    root = _make_project(tmp_path, {"safe.py": "x = 1\n"})
    with pytest.raises(ValueError):
        server.validate_path_components(root, "..\\..\\windows")
    with pytest.raises(ValueError):
        server.validate_path_components(root, "../safe.py")
    with pytest.raises(ValueError):
        server.validate_path_components(root, "sub/../../safe.py")


def test_absolute_path_blocked(tmp_path):
    root = _make_project(tmp_path, {"safe.py": "x = 1\n"})
    with pytest.raises(ValueError):
        server.validate_path_components(root, str(root / "safe.py"))


def test_read_file_traversal_blocked(tmp_path):
    root = _make_project(tmp_path, {"safe.py": "x = 1\n"})
    result = server.read_file(str(root), "..\\..\\windows\\win.ini")
    assert "Error" in result


# ==========================================
# Symlink Tests
# ==========================================

def test_symlink_file_blocked(tmp_path):
    root = _make_project(tmp_path, {"real.py": "x = 1\n"})
    link = root / "link.py"
    if not _try_symlink(str(root / "real.py"), str(link)):
        pytest.skip("Symlinks not supported on this system")
    result = server.read_file(str(root), "link.py")
    assert "not allowed" in result.lower() or "Error" in result


def test_symlink_dir_blocked(tmp_path):
    root = _make_project(tmp_path, {"sub": {}})
    sub_real = root / "sub"
    link = root / "linkdir"
    if not _try_symlink(str(sub_real), str(link)):
        pytest.skip("Symlinks not supported on this system")
    tree = server.get_file_tree(str(root), ".", max_depth=1)
    assert "linkdir" not in tree


# ==========================================
# Sensitive File Tests
# ==========================================

SENSITIVE_NAMES = [
    ".env",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "secrets",
    "secret.key",
    "cert.pem",
    "password.txt",
]


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_sensitive_file_read_blocked(tmp_path, name):
    root = _make_project(tmp_path, {name: "sensitive content\n"})
    result = server.read_file(str(root), name)
    assert "not allowed" in result.lower() or "Error" in result


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_sensitive_file_not_listed(tmp_path, name):
    root = _make_project(tmp_path, {name: "x\n", "safe.py": "x = 1\n"})
    listing = server.list_files(str(root), ".")
    assert name not in listing
    assert "safe.py" in listing


def test_git_directory_blocked(tmp_path):
    root = _make_project(tmp_path, {
        ".git/config": "[core]\n",
        "safe.py": "x = 1\n",
    })
    result = server.read_file(str(root), ".git/config")
    assert "not allowed" in result.lower() or "Error" in result
    listing = server.list_files(str(root), ".")
    assert ".git" not in listing


def test_blocked_extension(tmp_path):
    root = _make_project(tmp_path, {"data.db": "binary\n", "safe.py": "x = 1\n"})
    result = server.read_file(str(root), "data.db")
    assert "not allowed" in result.lower() or "Error" in result


# ==========================================
# ALLOWED_ROOTS Tests
# ==========================================

def test_allowed_roots_enforcement(tmp_path):
    root = _make_project(tmp_path, {"safe.py": "x = 1\n"})
    original = server.ALLOWED_ROOTS
    server.ALLOWED_ROOTS = {str(root)}
    try:
        validated = server.validate_project_path(str(root))
        assert validated == root.resolve()
    finally:
        server.ALLOWED_ROOTS = original


def test_allowed_roots_rejects_outside(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "safe.py").write_text("x = 1\n")
    original = server.ALLOWED_ROOTS
    server.ALLOWED_ROOTS = {str(allowed)}
    try:
        with pytest.raises(PermissionError):
            server.validate_project_path(str(outside))
    finally:
        server.ALLOWED_ROOTS = original


def test_allowed_roots_empty_allows_all(tmp_path):
    root = _make_project(tmp_path, {"safe.py": "x = 1\n"})
    original = server.ALLOWED_ROOTS
    server.ALLOWED_ROOTS = set()
    try:
        validated = server.validate_project_path(str(root))
        assert validated == root.resolve()
    finally:
        server.ALLOWED_ROOTS = original


# ==========================================
# read_file boundary tests
# ==========================================

def test_read_file_line_range(tmp_path):
    content = "\n".join(f"line {i}" for i in range(1, 11))
    root = _make_project(tmp_path, {"file.txt": content + "\n"})
    result = server.read_file(str(root), "file.txt", start_line=3, end_line=5)
    assert "line 3" in result
    assert "line 5" in result
    assert "line 2" not in result
    assert "line 6" not in result


def test_read_file_start_line_invalid(tmp_path):
    root = _make_project(tmp_path, {"file.txt": "a\nb\nc\n"})
    result = server.read_file(str(root), "file.txt", start_line=0)
    assert "Error" in result


def test_read_file_end_line_exceeds(tmp_path):
    root = _make_project(tmp_path, {"file.txt": "a\nb\nc\n"})
    result = server.read_file(str(root), "file.txt", end_line=10)
    assert "Error" in result


def test_read_file_start_greater_than_end(tmp_path):
    root = _make_project(tmp_path, {"file.txt": "a\nb\nc\n"})
    result = server.read_file(str(root), "file.txt", start_line=5, end_line=2)
    assert "Error" in result


# ==========================================
# search_code tests
# ==========================================

def test_search_code_plain(tmp_path):
    root = _make_project(tmp_path, {"main.py": "def hello():\n    pass\n"})
    result = server.search_code(str(root), "hello")
    assert "hello" in result
    assert "main.py" in result


def test_search_code_regex(tmp_path):
    root = _make_project(tmp_path, {"main.py": "import os\nimport sys\n"})
    result = server.search_code(str(root), r"import\s+\w+", use_regex=True)
    assert "import os" in result
    assert "import sys" in result


def test_search_code_invalid_regex(tmp_path):
    root = _make_project(tmp_path, {"main.py": "x = 1\n"})
    result = server.search_code(str(root), "[invalid", use_regex=True)
    assert "Error" in result


def test_search_code_file_pattern(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "def foo():\n    pass\n",
        "utils.js": "function bar() {}\n",
    })
    result = server.search_code(str(root), "def", file_pattern="*.py")
    assert "main.py" in result
    assert "utils.js" not in result


def test_search_code_empty_query(tmp_path):
    root = _make_project(tmp_path, {"main.py": "x = 1\n"})
    result = server.search_code(str(root), "")
    assert "Error" in result


# ==========================================
# get_file_tree tests
# ==========================================

def test_get_file_tree(tmp_path):
    root = _make_project(tmp_path, {
        "a.py": "x = 1\n",
        "sub/b.py": "y = 2\n",
        "sub/deep/c.py": "z = 3\n",
    })
    tree = server.get_file_tree(str(root), ".", max_depth=2)
    assert "a.py" in tree
    assert "b.py" in tree
    assert "c.py" not in tree  # depth 3, beyond limit 2


def test_get_file_tree_nonexistent(tmp_path):
    result = server.get_file_tree(str(tmp_path / "nope"), ".")
    assert "Error" in result


# ==========================================
# find_definitions tests
# ==========================================

def test_find_definitions(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "class MyClass:\n    def method(self):\n        pass\n\ndef standalone():\n    pass\n",
    })
    result = server.find_definitions(str(root), ".")
    assert "MyClass" in result
    assert "method" in result
    assert "standalone" in result
    assert "main.py" in result


def test_find_definitions_skips_non_py(tmp_path):
    root = _make_project(tmp_path, {
        "main.js": "function foo() {}\n",
    })
    result = server.find_definitions(str(root), ".")
    assert "No definitions found" in result


# ==========================================
# detect_frameworks tests
# ==========================================

def test_detect_frameworks_django(tmp_path):
    root = _make_project(tmp_path, {
        "requirements.txt": "Django==4.2\n",
    })
    result = server.detect_frameworks(str(root))
    assert "Django" in result


def test_detect_frameworks_react(tmp_path):
    root = _make_project(tmp_path, {
        "package.json": '{"dependencies": {"react": "^18.0"}}\n',
    })
    result = server.detect_frameworks(str(root))
    assert "React" in result


def test_detect_frameworks_none(tmp_path):
    root = _make_project(tmp_path, {
        "readme.md": "# Hello\n",
    })
    result = server.detect_frameworks(str(root))
    assert "No frameworks detected" in result


# ==========================================
# Dependency Graph Tests
# ==========================================

def test_dependency_graph_internal(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "from utils.helpers import format_date\n",
        "utils/__init__.py": "",
        "utils/helpers.py": "def format_date(d): return str(d)\n",
    })
    result = server.get_dependency_graph(str(root), ".")
    assert "main.py" in result
    assert "helpers.py" in result
    assert "[internal]" in result


def test_dependency_graph_external(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "import os\nimport json\n",
    })
    result = server.get_dependency_graph(str(root), ".")
    assert "main.py" in result
    assert "[external]" in result


def test_dependency_graph_unresolved(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "import nonexistent_module_xyz\n",
    })
    result = server.get_dependency_graph(str(root), ".")
    assert "main.py" in result
    assert "[unresolved]" in result


def test_dependency_graph_mixed(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "import os\nfrom utils.helpers import x\nimport nonexistent_module_xyz\n",
        "utils/__init__.py": "",
        "utils/helpers.py": "x = 1\n",
    })
    result = server.get_dependency_graph(str(root), ".")
    assert "main.py" in result
    assert "[internal]" in result
    assert "[external]" in result
    assert "[unresolved]" in result


def test_dependency_graph_no_imports(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "x = 1\ny = 2\n",
    })
    result = server.get_dependency_graph(str(root), ".")
    assert "No import dependencies found" in result


def test_dependency_graph_nonexistent(tmp_path):
    result = server.get_dependency_graph(str(tmp_path / "nope"), ".")
    assert "Error" in result


# ==========================================
# Cache Tests
# ==========================================

def test_cache_hit_and_miss(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "x = 1\n",
    })

    # First call populates cache
    result1 = server.find_definitions(str(root), ".")

    # Second call should hit cache (same result)
    result2 = server.find_definitions(str(root), ".")
    assert result1 == result2


def test_cache_invalidation_on_change(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "x = 1\n",
    })

    result1 = server.find_definitions(str(root), ".")

    # Modify a file to change fingerprint
    (root / "main.py").write_text("def foo():\n    pass\n", encoding="utf-8")

    result2 = server.find_definitions(str(root), ".")
    assert "foo" in result2
    assert result1 != result2


def test_clear_cache_all(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "x = 1\n",
    })

    # Populate cache
    server.find_definitions(str(root), ".")
    server.get_project_overview(str(root))

    result = server.clear_cache(None)
    assert "entries removed" in result


def test_clear_cache_project(tmp_path):
    root = _make_project(tmp_path, {
        "main.py": "x = 1\n",
    })

    server.find_definitions(str(root), ".")

    result = server.clear_cache(str(root))
    assert "entries removed" in result

