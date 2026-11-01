"""
Unified Dual-Layer Memory Manager for AutoBugHunter 24/7.
Provides Layer 1 Episodic Memory (sqlite-vec) and Layer 2 Structural Graph Memory (Cognee/AST).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from src.code_graph import CodeGraphEngine, LocalizedGraphContext
from src.database import Database, DeterministicCodeVectorizer


class MemoryManager:
    """
    Unified manager bridging Layer 1 (sqlite-vec episodic recall)
    and Layer 2 (structural codebase knowledge graph).
    """

    def __init__(self, database: Database, repo_path: Optional[Path | str] = None):
        self.db = database
        self.repo_path = Path(repo_path).resolve() if repo_path else None
        self._graph_engine: Optional[CodeGraphEngine] = None
        if self.repo_path:
            self._graph_engine = CodeGraphEngine(self.repo_path)

    @property
    def graph_engine(self) -> Optional[CodeGraphEngine]:
        return self._graph_engine

    def check_past_false_positive(
        self,
        snippet_text: str,
        rule_id: Optional[str] = None,
        threshold: float = 0.88,
    ) -> tuple[bool, Optional[str]]:
        """Check Layer 1 episodic memory for matching false positive or rejected patterns."""
        return self.db.should_skip_finding(
            code_snippet=snippet_text,
            rule_id=rule_id,
            threshold=threshold,
        )

    def record_bug_outcome(
        self,
        repo_slug: str,
        snippet: str,
        outcome: str,
        reason: Optional[str] = None,
        rule_id: str = "GENERIC",
        file_path: str = "unknown",
        commit_sha: str = "",
        stride_category: Optional[str] = None,
        owasp_category: Optional[str] = None,
    ) -> int:
        """Record finding embedding and patch outcome into Layer 1 episodic memory."""
        return self.db.record_bug_memory(
            repo_slug=repo_slug,
            commit_sha=commit_sha,
            rule_id=rule_id,
            file_path=file_path,
            code_snippet=snippet,
            patch_outcome=outcome,
            rejection_reason=reason,
            stride_category=stride_category,
            owasp_category=owasp_category,
        )

    def get_structural_context(
        self,
        file_path: str,
        line_number: Optional[int] = None,
    ) -> Optional[LocalizedGraphContext]:
        """Extract Layer 2 structural dependency subgraph and test mapping."""
        if not self._graph_engine:
            return None
        return self._graph_engine.get_localized_context(file_path, line_number)

    def generate_prompt_context(
        self,
        file_path: str,
        line_number: Optional[int] = None,
    ) -> str:
        """Generate Layer 2 formatted prompt block for agent injection."""
        if not self._graph_engine:
            return ""
        return self._graph_engine.generate_prompt_context(file_path, line_number)
