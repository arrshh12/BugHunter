"""
Comprehensive unit tests for Layer 2 Structural Codebase Memory Engine (src/code_graph.py).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from src.code_graph import (
    ClassNode,
    CodeGraphEngine,
    FunctionNode,
    LocalizedGraphContext,
    ModuleNode,
    NativeAstGraphEngine,
    TestNode,
)


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Create a temporary multi-module Python repository with sources and tests."""
    repo = tmp_path / "mock_repo"
    repo.mkdir()
    src = repo / "src"
    src.mkdir()
    tests = repo / "tests"
    tests.mkdir()

    # Module 1: Base service
    (src / "base.py").write_text(
        "class BaseService:\n"
        "    def run(self):\n"
        "        pass\n",
        encoding="utf-8",
    )

    # Module 2: Core engine inheriting base and calling helper
    (src / "engine.py").write_text(
        "from src.base import BaseService\n"
        "from src.helper import compute_hash\n\n"
        "class Engine(BaseService):\n"
        "    \"\"\"Core computation engine.\"\"\"\n"
        "    def execute(self, payload: str) -> str:\n"
        "        h = compute_hash(payload)\n"
        "        return h\n\n"
        "def standalone_func(val: int) -> int:\n"
        "    return val * 2\n",
        encoding="utf-8",
    )

    # Module 3: Helper
    (src / "helper.py").write_text(
        "import hashlib\n\n"
        "def compute_hash(data: str) -> str:\n"
        "    return hashlib.sha256(data.encode()).hexdigest()\n",
        encoding="utf-8",
    )

    # Module 4: Inbound caller
    (src / "caller.py").write_text(
        "from src.engine import Engine\n\n"
        "def main_process():\n"
        "    e = Engine()\n"
        "    return e.execute('test')\n",
        encoding="utf-8",
    )

    # Test file for engine: tests/test_engine.py
    (tests / "test_engine.py").write_text(
        "from src.engine import Engine, standalone_func\n\n"
        "def test_engine_execute():\n"
        "    e = Engine()\n"
        "    assert e.execute('data') is not None\n\n"
        "def test_standalone():\n"
        "    assert standalone_func(3) == 6\n",
        encoding="utf-8",
    )

    # Syntax error file to verify parser resilience
    (src / "broken.py").write_text("def broken_syntax(:\n", encoding="utf-8")

    return repo


def test_native_ast_graph_build(sample_repo: Path):
    """Verify nodes and edges are extracted from repository."""
    engine = NativeAstGraphEngine(sample_repo)
    engine.build_graph()

    # Modules
    assert "src/base.py" in engine.modules
    assert "src/engine.py" in engine.modules
    assert "src/helper.py" in engine.modules
    assert "tests/test_engine.py" in engine.modules
    assert engine.modules["tests/test_engine.py"].is_test is True
    assert engine.modules["src/engine.py"].is_test is False

    # Classes
    class_ids = set(engine.classes.keys())
    assert "src/base.py::BaseService" in class_ids
    assert "src/engine.py::Engine" in class_ids

    engine_class = engine.classes["src/engine.py::Engine"]
    assert engine_class.name == "Engine"
    assert "BaseService" in engine_class.bases
    assert "Core computation engine" in engine_class.docstring

    # Functions
    func_ids = set(engine.functions.keys())
    assert "src/engine.py::Engine.execute" in func_ids
    assert "src/engine.py::standalone_func" in func_ids
    assert "src/helper.py::compute_hash" in func_ids

    # Tests
    test_ids = set(engine.tests.keys())
    assert "tests/test_engine.py::test_engine_execute" in test_ids
    assert "tests/test_engine.py::test_standalone" in test_ids

    # Edges
    edge_types = {e.edge_type for e in engine.edges}
    assert "DEFINES" in edge_types
    assert "INHERITS" in edge_types
    assert "IMPORTS" in edge_types
    assert "CALLS" in edge_types
    assert "TESTS" in edge_types


def test_test_to_source_mapping(sample_repo: Path):
    """Verify test-to-source mapping identifies tests/test_engine.py for src/engine.py."""
    engine = NativeAstGraphEngine(sample_repo)
    engine.build_graph()

    ctx = engine.get_localized_context("src/engine.py")
    assert "tests/test_engine.py" in ctx.related_tests


def test_localized_context_and_enclosing_symbol(sample_repo: Path):
    """Verify localized context extracts enclosing symbol for a specific line number."""
    engine = NativeAstGraphEngine(sample_repo)
    engine.build_graph()

    # In src/engine.py:
    # line 7 is inside execute(self, payload: str)
    ctx = engine.get_localized_context("src/engine.py", line_number=7)
    assert ctx.target_file == "src/engine.py"
    assert "src/caller.py" in ctx.inbound_callers or any("caller" in c for c in ctx.inbound_callers)
    assert "src.base" in ctx.outbound_dependencies or any("base" in d for d in ctx.outbound_dependencies)
    assert "tests/test_engine.py" in ctx.related_tests

    # Verify formatted prompt block contents
    block = ctx.formatted_context_block
    assert "LAYER 2 STRUCTURAL CODEBASE MEMORY" in block
    assert "Target File: src/engine.py" in block
    assert "Enclosing Suspect Symbol" in block
    assert "execute" in block
    assert "Inbound Dependents" in block
    assert "Mapped Test Suites" in block
    assert "pytest tests/test_engine.py -v" in block


def test_code_graph_engine_facade_and_path_normalization(sample_repo: Path):
    """Verify CodeGraphEngine facade handles relative, absolute, and partial paths."""
    engine = CodeGraphEngine(sample_repo)
    engine.build_graph()

    # Test relative path
    ctx1 = engine.get_localized_context("src/engine.py")
    assert ctx1.target_file == "src/engine.py"

    # Test absolute path
    abs_path = str(sample_repo / "src" / "engine.py")
    ctx2 = engine.get_localized_context(abs_path)
    assert ctx2.target_file == "src/engine.py"

    # Test filename suffix match
    ctx3 = engine.get_localized_context("engine.py")
    assert ctx3.target_file == "src/engine.py"

    # Test generate_prompt_context
    prompt_str = engine.generate_prompt_context("src/engine.py", 7)
    assert "pytest tests/test_engine.py -v" in prompt_str


def test_broken_file_resilience(sample_repo: Path):
    """Verify syntax error in broken.py does not crash graph generation."""
    engine = CodeGraphEngine(sample_repo)
    engine.build_graph()

    assert "src/broken.py" in engine.modules
    ctx = engine.get_localized_context("src/broken.py")
    assert ctx.target_file == "src/broken.py"
    assert "No classes or functions detected" in ctx.formatted_context_block


def test_nonexistent_file_handling(sample_repo: Path):
    """Verify querying non-existent file produces a clean, non-crashing context block."""
    engine = CodeGraphEngine(sample_repo)
    engine.build_graph()

    ctx = engine.get_localized_context("src/nonexistent.py")
    assert ctx.target_file == "src/nonexistent.py"
    assert "LAYER 2 STRUCTURAL CODEBASE MEMORY" in ctx.formatted_context_block


def test_cognee_adapter_routing_and_fallback(sample_repo: Path):
    """Verify provider selection routes to Cognee adapter when available or falls back cleanly."""
    # Scenario 1: cognee not installed -> NativeAstGraphEngine
    engine_native = CodeGraphEngine(sample_repo, enable_cognee=True)
    assert isinstance(engine_native.provider, NativeAstGraphEngine)

    # Scenario 2: simulate cognee module present with sufficient RAM
    class DummyCognee:
        pass

    with patch.dict("sys.modules", {"cognee": DummyCognee()}):
        with patch("psutil.virtual_memory") as mock_mem:
            mock_mem.return_value.available = 1000 * 1024 * 1024  # 1000 MB > 750 MB
            engine_cognee = CodeGraphEngine(sample_repo, enable_cognee=True)
            from src.code_graph import CogneeGraphAdapter
            assert isinstance(engine_cognee.provider, CogneeGraphAdapter)

            # Check that building graph on adapter succeeds
            engine_cognee.build_graph()
            ctx = engine_cognee.get_localized_context("src/engine.py")
            assert "tests/test_engine.py" in ctx.related_tests


def test_relative_import_resolution_no_empty_target(tmp_path: Path):
    """Verify relative imports from . and .. resolve without empty target edges."""
    repo = tmp_path / "repo"
    pkg = repo / "pkg"
    sub = pkg / "sub"
    sub.mkdir(parents=True)

    (pkg / "sibling.py").write_text("def sibling_func(): pass\n", encoding="utf-8")
    (sub / "child.py").write_text(
        "from . import sub_sibling\n"
        "from .. import sibling\n"
        "from ..sibling import sibling_func\n",
        encoding="utf-8"
    )
    (sub / "sub_sibling.py").write_text("def sub_func(): pass\n", encoding="utf-8")
    (repo / "root_mod.py").write_text("from . import pkg\n", encoding="utf-8")

    engine = NativeAstGraphEngine(repo)
    engine.build_graph()

    import_edges = [e for e in engine.edges if e.edge_type == "IMPORTS" and e.source == "pkg/sub/child.py"]
    assert len(import_edges) >= 3

    # Verify no empty targets
    targets = [e.target for e in import_edges]
    assert "" not in targets
    assert "pkg.sub.sub_sibling" in targets
    assert "pkg.sibling" in targets

    root_edges = [e for e in engine.edges if e.edge_type == "IMPORTS" and e.source == "root_mod.py"]
    assert len(root_edges) >= 1
    assert all(e.target != "" for e in root_edges)
    assert any(e.target == "pkg" for e in root_edges)


def test_inbound_call_disambiguation_for_common_functions(tmp_path: Path):
    """Verify common function names like run/execute are not attributed as inbound callers without import."""
    repo = tmp_path / "disambiguate_repo"
    repo.mkdir()
    src = repo / "src"
    src.mkdir()

    # Module A: defines run
    (src / "service_a.py").write_text("def run():\n    return 42\n", encoding="utf-8")

    # Module B: imports service_a and calls run
    (src / "caller_b.py").write_text(
        "from src.service_a import run\n\n"
        "def start():\n"
        "    return run()\n",
        encoding="utf-8",
    )

    # Module C: unrelated, defines/calls its own run without importing service_a
    (src / "unrelated_c.py").write_text(
        "def execute():\n"
        "    run()\n\n"
        "def run():\n"
        "    pass\n",
        encoding="utf-8",
    )

    engine = CodeGraphEngine(repo)
    engine.build_graph()

    ctx_a = engine.get_localized_context("src/service_a.py")
    # caller_b should be recognized as inbound caller
    assert any("caller_b.py" in c for c in ctx_a.inbound_callers)
    # unrelated_c should NOT be recognized as inbound caller for service_a
    assert not any("unrelated_c.py" in c for c in ctx_a.inbound_callers)

