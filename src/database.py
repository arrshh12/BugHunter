"""
SQLite WAL Database Engine and state persistence for AutoBugHunter 24/7.
"""

from __future__ import annotations

import hashlib
import math
import re
import sqlite3
import struct
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional


class DeterministicCodeVectorizer:
    """
    Deterministic, zero-dependency 384-dimensional unit vectorizer for code snippets.
    Uses tokenization, character 3-grams, domain weighting, and sign-hash projections.
    Operates in < 1 MB RAM with zero external API calls.
    """
    DIMENSION: int = 384

    @classmethod
    def vectorize(
        cls,
        code_snippet: str,
        rule_id: Optional[str] = None,
        finding_message: Optional[str] = None,
    ) -> list[float]:
        dim = cls.DIMENSION
        vec = [0.0] * dim
        features: list[tuple[str, float]] = []

        if rule_id:
            features.append((f"RULE_{rule_id.strip()}", 6.0))

        if finding_message:
            for w in re.findall(r"\w+", finding_message.lower()):
                features.append((f"MSG_{w}", 2.0))

        clean_code = (code_snippet or "").strip()
        tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*|[^\s\w]", clean_code.lower())
        for t in tokens:
            features.append((f"CODE_{t}", 1.0))
            if len(t) >= 4 and t.isalnum():
                for i in range(len(t) - 2):
                    features.append((f"3GRAM_{t[i:i+3]}", 0.15))

        if not features:
            features.append(("EMPTY_SNIPPET", 1.0))

        for feat, weight in features:
            h = int(hashlib.md5(feat.encode("utf-8")).hexdigest()[:8], 16)
            idx = h % dim
            sign = 1.0 if ((h >> 16) & 1) else -1.0
            vec[idx] += sign * weight

        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0.0:
            vec = [x / norm for x in vec]
        return vec

    @classmethod
    def to_bytes(cls, vec: list[float]) -> bytes:
        """Serialize float list to 32-bit float bytes (bit-exact with sqlite-vec)."""
        return struct.pack(f"{len(vec)}f", *vec)

    @classmethod
    def from_bytes(cls, b: bytes) -> list[float]:
        """Deserialize 32-bit float bytes to float list."""
        count = len(b) // 4
        return list(struct.unpack(f"{count}f", b))

    @classmethod
    def cosine_similarity(cls, vec1: list[float], vec2: list[float]) -> float:
        """Compute cosine similarity between two unit vectors (dot product)."""
        return sum(a * b for a, b in zip(vec1, vec2))

    @classmethod
    def cosine_distance(cls, vec1: list[float], vec2: list[float]) -> float:
        """Compute cosine distance between two unit vectors: max(0.0, 1.0 - similarity)."""
        return max(0.0, 1.0 - cls.cosine_similarity(vec1, vec2))


class Database:
    """Thread-safe SQLite database manager operating in WAL mode."""

    SCHEMA_SQL = """
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 10000;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS repositories (
        repo_slug TEXT PRIMARY KEY,
        default_branch TEXT NOT NULL DEFAULT 'main',
        last_scanned_sha TEXT,
        fully_exhausted INTEGER NOT NULL DEFAULT 0,
        open_pr_count INTEGER NOT NULL DEFAULT 0,
        total_prs_created INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'IDLE',
        last_scan_at TIMESTAMP,
        last_error TEXT
    );

    CREATE TABLE IF NOT EXISTS pull_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_slug TEXT NOT NULL,
        pr_number INTEGER,
        pr_url TEXT NOT NULL,
        branch_name TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        file_modified TEXT NOT NULL,
        pr_title TEXT NOT NULL,
        bug_summary TEXT,
        llm_key_id TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS api_key_status (
        key_id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        base_url TEXT NOT NULL,
        masked_key TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'HEALTHY',
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        total_uses INTEGER NOT NULL DEFAULT 0,
        total_successes INTEGER NOT NULL DEFAULT 0,
        cooldown_until TIMESTAMP,
        last_error TEXT,
        last_used_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS scan_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_slug TEXT NOT NULL,
        commit_sha TEXT,
        key_id TEXT,
        outcome TEXT NOT NULL,
        duration_seconds REAL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_repo_status ON repositories(status);
    CREATE INDEX IF NOT EXISTS idx_repo_exhausted ON repositories(fully_exhausted);
    CREATE INDEX IF NOT EXISTS idx_pr_repo ON pull_requests(repo_slug);
    CREATE INDEX IF NOT EXISTS idx_key_state ON api_key_status(state);
    CREATE INDEX IF NOT EXISTS idx_scan_repo ON scan_logs(repo_slug);

    CREATE TABLE IF NOT EXISTS review_remediations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id TEXT UNIQUE NOT NULL,
        comment_id TEXT NOT NULL,
        repo_slug TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        commit_sha TEXT NOT NULL,
        reviewer TEXT,
        path TEXT,
        line INTEGER,
        feedback_summary TEXT,
        status TEXT NOT NULL DEFAULT 'RESOLVED',
        remediated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_rev_rem_thread ON review_remediations(thread_id);
    CREATE INDEX IF NOT EXISTS idx_rev_rem_repo_pr ON review_remediations(repo_slug, pr_number);
    CREATE INDEX IF NOT EXISTS idx_rev_rem_comment ON review_remediations(comment_id);
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @staticmethod
    def _load_extensions(conn: sqlite3.Connection) -> bool:
        """Safely load sqlite-vec extension if supported and available."""
        if hasattr(conn, "enable_load_extension"):
            conn.enable_load_extension(True)
            try:
                import sqlite_vec
                sqlite_vec.load(conn)
                return True
            except Exception:
                return False
            finally:
                conn.enable_load_extension(False)
        return False

    @staticmethod
    def _has_vec_table(conn: sqlite3.Connection) -> bool:
        """Check if bug_memory_vec table exists and is operational."""
        try:
            row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='bug_memory_vec'").fetchone()
            if not row:
                return False
            conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()
            return True
        except Exception:
            return False

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a thread-safe SQLite connection with WAL pragmas and automatic commit/rollback."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False
        )
        self._load_extensions(conn)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 10000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Internal context manager matching get_connection for test compatibility."""
        with self.get_connection() as conn:
            yield conn

    def init_db(self) -> None:
        """Initialize tables and indexes idempotently."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        try:
            conn.executescript(self.SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()
        self.init_bug_memory()

    def init_bug_memory(self) -> None:
        """Initialize episodic memory tables, vector index, and triggers."""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bug_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_slug TEXT NOT NULL,
                    commit_sha TEXT,
                    rule_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    code_snippet TEXT NOT NULL,
                    patch_outcome TEXT NOT NULL,
                    rejection_reason TEXT,
                    stride_category TEXT,
                    owasp_category TEXT,
                    embedding BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bug_mem_repo ON bug_memory(repo_slug);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bug_mem_rule ON bug_memory(rule_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bug_mem_outcome ON bug_memory(patch_outcome);")

            try:
                conn.execute("""
                    CREATE VIRTUAL TABLE IF NOT EXISTS bug_memory_vec USING vec0(
                        id INTEGER PRIMARY KEY,
                        embedding float[384] distance_metric=cosine
                    );
                """)
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS trg_bug_memory_insert
                    AFTER INSERT ON bug_memory
                    WHEN NEW.embedding IS NOT NULL
                    BEGIN
                        INSERT INTO bug_memory_vec (id, embedding) VALUES (NEW.id, NEW.embedding);
                    END;
                """)
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS trg_bug_memory_delete
                    AFTER DELETE ON bug_memory
                    BEGIN
                        DELETE FROM bug_memory_vec WHERE id = OLD.id;
                    END;
                """)
                # Migrate and ensure robust update trigger handling NULL embeddings safely
                conn.execute("DROP TRIGGER IF EXISTS trg_bug_memory_update;")
                conn.execute("DROP TRIGGER IF EXISTS trg_bug_memory_update_delete;")
                conn.execute("DROP TRIGGER IF EXISTS trg_bug_memory_update_insert;")
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS trg_bug_memory_update
                    AFTER UPDATE OF embedding ON bug_memory
                    BEGIN
                        DELETE FROM bug_memory_vec WHERE id = OLD.id;
                        INSERT INTO bug_memory_vec (id, embedding)
                        SELECT NEW.id, NEW.embedding
                        WHERE NEW.embedding IS NOT NULL;
                    END;
                """)

                # Idempotent reconciliation for existing databases
                conn.execute("""
                    DELETE FROM bug_memory_vec
                    WHERE id NOT IN (SELECT id FROM bug_memory WHERE embedding IS NOT NULL);
                """)
                conn.execute("""
                    INSERT INTO bug_memory_vec (id, embedding)
                    SELECT id, embedding FROM bug_memory
                    WHERE embedding IS NOT NULL
                      AND id NOT IN (SELECT id FROM bug_memory_vec);
                """)

            except Exception:
                # Fallback mode when sqlite-vec or vec0 virtual table cannot be loaded
                pass

    def upsert_repository(
        self,
        repo_slug: str,
        default_branch: str = "main",
        status: str = "IDLE",
        open_pr_count: int = 0
    ) -> None:
        """Insert or update repository basic configuration."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO repositories (repo_slug, default_branch, status, open_pr_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(repo_slug) DO UPDATE SET
                    default_branch = excluded.default_branch,
                    status = excluded.status,
                    open_pr_count = excluded.open_pr_count
            """, (repo_slug, default_branch, status, open_pr_count))

    def update_repository_status(
        self,
        repo_slug: str,
        status: str,
        last_error: Optional[str] = None
    ) -> None:
        """Update repository execution status and error state."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO repositories (repo_slug, status, last_error, last_scan_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(repo_slug) DO UPDATE SET
                    status = excluded.status,
                    last_error = excluded.last_error,
                    last_scan_at = CURRENT_TIMESTAMP
            """, (repo_slug, status, last_error))

    def record_scan_result(
        self,
        repo_slug: str,
        commit_sha: str,
        fully_exhausted: int,
        last_error: Optional[str] = None
    ) -> None:
        """Record scan result commit SHA and exhaustion state."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO repositories (repo_slug, last_scanned_sha, fully_exhausted, last_error, last_scan_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(repo_slug) DO UPDATE SET
                    last_scanned_sha = excluded.last_scanned_sha,
                    fully_exhausted = excluded.fully_exhausted,
                    last_error = excluded.last_error,
                    last_scan_at = CURRENT_TIMESTAMP
            """, (repo_slug, commit_sha, fully_exhausted, last_error))

    def update_open_pr_count(self, repo_slug: str, count: int) -> None:
        """Update open pull request counter for collision check."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO repositories (repo_slug, open_pr_count)
                VALUES (?, ?)
                ON CONFLICT(repo_slug) DO UPDATE SET
                    open_pr_count = excluded.open_pr_count
            """, (repo_slug, count))

    def record_pull_request(
        self,
        repo_slug: str,
        pr_number: int,
        pr_url: str,
        branch_name: str,
        commit_sha: str,
        file_modified: str,
        pr_title: str,
        bug_summary: Optional[str] = None,
        llm_key_id: Optional[str] = None
    ) -> int:
        """Record created PR and update repository metrics."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO pull_requests (
                    repo_slug, pr_number, pr_url, branch_name, commit_sha,
                    file_modified, pr_title, bug_summary, llm_key_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_slug, pr_number, pr_url, branch_name, commit_sha,
                file_modified, pr_title, bug_summary, llm_key_id
            ))
            pr_id = cursor.lastrowid
            conn.execute("""
                UPDATE repositories
                SET total_prs_created = total_prs_created + 1,
                    open_pr_count = open_pr_count + 1,
                    fully_exhausted = 0
                WHERE repo_slug = ?
            """, (repo_slug,))
            return pr_id or 0

    def upsert_api_key(
        self,
        key_id: str,
        provider: str,
        model: str,
        base_url: str,
        masked_key: str,
        state: str = "HEALTHY"
    ) -> None:
        """Upsert API key configuration and metadata."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO api_key_status (key_id, provider, model, base_url, masked_key, state)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_id) DO UPDATE SET
                    provider = excluded.provider,
                    model = excluded.model,
                    base_url = excluded.base_url,
                    masked_key = excluded.masked_key
            """, (key_id, provider, model, base_url, masked_key, state))

    def update_api_key_status(
        self,
        key_id: str,
        state: str,
        consecutive_failures: int,
        cooldown_until: Optional[str],
        last_error: Optional[str] = None
    ) -> None:
        """Update circuit breaker state and cooldown expiration."""
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE api_key_status
                SET state = ?, consecutive_failures = ?, cooldown_until = ?, last_error = ?, last_used_at = CURRENT_TIMESTAMP
                WHERE key_id = ?
            """, (state, consecutive_failures, cooldown_until, last_error, key_id))

    def record_api_key_usage(self, key_id: str, success: bool) -> None:
        """Increment usage metrics and reset failures on success."""
        with self.get_connection() as conn:
            if success:
                conn.execute("""
                    UPDATE api_key_status
                    SET total_uses = total_uses + 1,
                        total_successes = total_successes + 1,
                        consecutive_failures = 0,
                        state = 'HEALTHY',
                        cooldown_until = NULL,
                        last_used_at = CURRENT_TIMESTAMP
                    WHERE key_id = ?
                """, (key_id,))
            else:
                conn.execute("""
                    UPDATE api_key_status
                    SET total_uses = total_uses + 1,
                        consecutive_failures = consecutive_failures + 1,
                        last_used_at = CURRENT_TIMESTAMP
                    WHERE key_id = ?
                """, (key_id,))

    def add_scan_log(
        self,
        repo_slug: str,
        commit_sha: Optional[str],
        key_id: Optional[str],
        outcome: str,
        duration_seconds: float,
        details: Optional[str] = None
    ) -> int:
        """Record scan execution log."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scan_logs (repo_slug, commit_sha, key_id, outcome, duration_seconds, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (repo_slug, commit_sha, key_id, outcome, duration_seconds, details))
            return cursor.lastrowid or 0

    def get_stats(self) -> dict[str, Any]:
        """Compute aggregated KPIs, repositories, keys, and recent PRs for Mission Control UI."""
        with self.get_connection() as conn:
            total_repos = conn.execute("SELECT COUNT(*) FROM repositories").fetchone()[0]
            exhausted_repos = conn.execute("SELECT COUNT(*) FROM repositories WHERE fully_exhausted = 1").fetchone()[0]
            total_prs = conn.execute("SELECT COUNT(*) FROM pull_requests").fetchone()[0]
            healthy_keys = conn.execute("SELECT COUNT(*) FROM api_key_status WHERE state = 'HEALTHY'").fetchone()[0]
            total_keys = conn.execute("SELECT COUNT(*) FROM api_key_status").fetchone()[0]

            repos_list = [dict(r) for r in conn.execute("SELECT * FROM repositories ORDER BY repo_slug").fetchall()]
            keys_list = [dict(k) for k in conn.execute("SELECT * FROM api_key_status ORDER BY key_id").fetchall()]
            recent_prs = [dict(p) for p in conn.execute("SELECT * FROM pull_requests ORDER BY id DESC LIMIT 10").fetchall()]

            return {
                "kpis": {
                    "total_repos": total_repos,
                    "exhausted_repos": exhausted_repos,
                    "total_prs_created": total_prs,
                    "healthy_keys": healthy_keys,
                    "total_keys": total_keys,
                },
                "repositories": repos_list,
                "keys": keys_list,
                "recent_prs": recent_prs,
            }

    def reset_exhausted(self) -> int:
        """Reset fully_exhausted flag across all repositories."""
        with self.get_connection() as conn:
            cursor = conn.execute("UPDATE repositories SET fully_exhausted = 0 WHERE fully_exhausted = 1")
            return cursor.rowcount

    def record_bug_memory(
        self,
        repo_slug: str,
        commit_sha: str,
        rule_id: str,
        file_path: str,
        code_snippet: str,
        patch_outcome: str,
        rejection_reason: Optional[str] = None,
        stride_category: Optional[str] = None,
        owasp_category: Optional[str] = None,
        embedding: Optional[list[float] | bytes] = None,
    ) -> int:
        """
        Record bug finding and outcome into episodic memory.
        If embedding is not provided, computes deterministic 384-dimensional unit vector.
        Automatically synchronizes to bug_memory_vec via triggers.
        """
        if embedding is None:
            vec = DeterministicCodeVectorizer.vectorize(code_snippet, rule_id=rule_id)
            emb_bytes = DeterministicCodeVectorizer.to_bytes(vec)
        elif isinstance(embedding, list):
            emb_bytes = DeterministicCodeVectorizer.to_bytes(embedding)
        elif isinstance(embedding, (bytes, bytearray)):
            emb_bytes = bytes(embedding)
        else:
            emb_bytes = None

        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO bug_memory (
                    repo_slug, commit_sha, rule_id, file_path, code_snippet,
                    patch_outcome, rejection_reason, stride_category, owasp_category, embedding
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_slug, commit_sha, rule_id, file_path, code_snippet,
                patch_outcome, rejection_reason, stride_category, owasp_category, emb_bytes
            ))
            row_id = cursor.lastrowid or 0

            # Fallback sync if bug_memory_vec exists but trigger did not fire
            if emb_bytes and self._has_vec_table(conn):
                try:
                    vec_row = conn.execute("SELECT 1 FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()
                    if not vec_row:
                        conn.execute("INSERT INTO bug_memory_vec (id, embedding) VALUES (?, ?)", (row_id, emb_bytes))
                except Exception:
                    pass

            return row_id

    def query_similar_bugs(
        self,
        code_snippet: str,
        rule_id: Optional[str] = None,
        threshold: float = 0.88,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Query episodic memory for similar bugs by cosine similarity.
        Threshold 0.88 maps to cosine distance <= 0.12 (+1e-5 float32 epsilon).
        Uses sqlite-vec KNN search with two-stage hybrid rule lookup when rule_id is provided,
        and falls back to pure Python cosine distance when sqlite-vec is unavailable.
        """
        vec = DeterministicCodeVectorizer.vectorize(code_snippet, rule_id=rule_id)
        emb_bytes = DeterministicCodeVectorizer.to_bytes(vec)
        max_dist = max(0.0, 1.0 - threshold + 1e-5)
        results: list[dict[str, Any]] = []
        seen_ids: set[int] = set()

        with self.get_connection() as conn:
            if self._has_vec_table(conn):
                try:
                    # Stage 1: Vector KNN Search
                    # When rule_id is provided, expand k_val up to 4096 (sqlite-vec's hard limit)
                    # to prevent candidate saturation by foreign-rule vectors.
                    k_val = min(4096, max(1000, limit * 50)) if rule_id else min(4096, max(25, limit * 5))
                    query = """
                        SELECT m.id, m.repo_slug, m.commit_sha, m.rule_id, m.file_path, m.code_snippet,
                               m.patch_outcome, m.rejection_reason, m.stride_category, m.owasp_category,
                               (1.0 - v.distance) AS similarity, v.distance AS distance
                        FROM bug_memory_vec v
                        JOIN bug_memory m ON m.id = v.id
                        WHERE v.embedding MATCH ? AND k = ? AND v.distance <= ?
                    """
                    params: list[Any] = [emb_bytes, k_val, max_dist]
                    if rule_id:
                        query += " AND m.rule_id = ?"
                        params.append(rule_id)
                    query += " ORDER BY v.distance ASC LIMIT ?"
                    params.append(limit)

                    rows = conn.execute(query, tuple(params)).fetchall()
                    for r in rows:
                        results.append({
                            "id": r["id"],
                            "repo_slug": r["repo_slug"],
                            "commit_sha": r["commit_sha"],
                            "rule_id": r["rule_id"],
                            "file_path": r["file_path"],
                            "code_snippet": r["code_snippet"],
                            "patch_outcome": r["patch_outcome"],
                            "rejection_reason": r["rejection_reason"],
                            "stride_category": r["stride_category"],
                            "owasp_category": r["owasp_category"],
                            "similarity": float(r["similarity"]),
                            "distance": float(r["distance"]),
                        })
                        seen_ids.add(r["id"])

                    # Stage 2: Rule-Specific B-Tree Hybrid Fallback
                    # If rule_id was specified and sqlite-vec returned fewer than limit matches,
                    # scan rule-specific records directly via idx_bug_mem_rule.
                    # Guarantees 100% recall even if > 4096 foreign-rule vectors saturated KNN.
                    if rule_id and len(results) < limit:
                        rule_rows = conn.execute("""
                            SELECT id, repo_slug, commit_sha, rule_id, file_path, code_snippet,
                                   patch_outcome, rejection_reason, stride_category, owasp_category,
                                   embedding
                            FROM bug_memory
                            WHERE rule_id = ?
                        """, (rule_id,)).fetchall()

                        for r in rule_rows:
                            if r["id"] in seen_ids:
                                continue
                            blob = r["embedding"]
                            sim = 0.0
                            if blob:
                                target_vec = DeterministicCodeVectorizer.from_bytes(blob)
                                sim = DeterministicCodeVectorizer.cosine_similarity(vec, target_vec)
                            elif r["code_snippet"].strip() == (code_snippet or "").strip():
                                sim = 1.0

                            if sim >= (threshold - 1e-5):
                                dist = max(0.0, 1.0 - sim)
                                results.append({
                                    "id": r["id"],
                                    "repo_slug": r["repo_slug"],
                                    "commit_sha": r["commit_sha"],
                                    "rule_id": r["rule_id"],
                                    "file_path": r["file_path"],
                                    "code_snippet": r["code_snippet"],
                                    "patch_outcome": r["patch_outcome"],
                                    "rejection_reason": r["rejection_reason"],
                                    "stride_category": r["stride_category"],
                                    "owasp_category": r["owasp_category"],
                                    "similarity": float(sim),
                                    "distance": float(dist),
                                })
                                seen_ids.add(r["id"])

                        results.sort(key=lambda x: x["distance"])
                        return results[:limit]

                    return results
                except Exception:
                    # Fall through to pure Python fallback if runtime error in sqlite-vec
                    pass

            # Fallback mode: pure Python cosine distance calculation
            query = """
                SELECT id, repo_slug, commit_sha, rule_id, file_path, code_snippet,
                       patch_outcome, rejection_reason, stride_category, owasp_category,
                       embedding
                FROM bug_memory
            """
            params = []
            if rule_id:
                query += " WHERE rule_id = ?"
                params.append(rule_id)
            query += " ORDER BY id DESC LIMIT 500"

            rows = conn.execute(query, tuple(params)).fetchall()
            matches = []
            for r in rows:
                blob = r["embedding"]
                sim = 0.0
                if blob:
                    target_vec = DeterministicCodeVectorizer.from_bytes(blob)
                    sim = DeterministicCodeVectorizer.cosine_similarity(vec, target_vec)
                else:
                    if r["code_snippet"].strip() == (code_snippet or "").strip():
                        sim = 1.0

                if sim >= (threshold - 1e-5):
                    dist = max(0.0, 1.0 - sim)
                    matches.append({
                        "id": r["id"],
                        "repo_slug": r["repo_slug"],
                        "commit_sha": r["commit_sha"],
                        "rule_id": r["rule_id"],
                        "file_path": r["file_path"],
                        "code_snippet": r["code_snippet"],
                        "patch_outcome": r["patch_outcome"],
                        "rejection_reason": r["rejection_reason"],
                        "stride_category": r["stride_category"],
                        "owasp_category": r["owasp_category"],
                        "similarity": float(sim),
                        "distance": float(dist),
                    })

            matches.sort(key=lambda x: x["distance"])
            return matches[:limit]

    def should_skip_finding(
        self,
        code_snippet: str,
        rule_id: Optional[str] = None,
        threshold: float = 0.88,
    ) -> tuple[bool, Optional[str]]:
        """
        Check if a candidate finding matches a previously rejected patch or false positive.
        Cosine similarity > 0.88 corresponds to distance < 0.12.
        Returns (True, reason) if finding should be skipped, otherwise (False, None).
        """
        candidates = self.query_similar_bugs(
            code_snippet=code_snippet,
            rule_id=rule_id,
            threshold=threshold,
            limit=5,
        )
        for c in candidates:
            if c["patch_outcome"] in ("false_positive", "rejected"):
                reason = (
                    f"Matches previous {c['patch_outcome']} "
                    f"(rule={c['rule_id']}, sim={c['similarity']:.2f}): "
                    f"{c['rejection_reason'] or 'Prior rejection recorded'}"
                )
                return True, reason
        return False, None

    def record_review_remediation(
        self,
        thread_id: str,
        comment_id: str,
        repo_slug: str,
        pr_number: int,
        commit_sha: str,
        reviewer: str = "",
        path: str = "",
        line: int = 0,
        feedback_summary: str = "",
        status: str = "RESOLVED",
    ) -> int:
        """
        Record or update a pull request review remediation with strict idempotency.
        Uses ON CONFLICT(thread_id) DO UPDATE SET ...
        Returns the row id.
        """
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO review_remediations (
                    thread_id, comment_id, repo_slug, pr_number, commit_sha,
                    reviewer, path, line, feedback_summary, status, remediated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(thread_id) DO UPDATE SET
                    comment_id = excluded.comment_id,
                    repo_slug = excluded.repo_slug,
                    pr_number = excluded.pr_number,
                    commit_sha = excluded.commit_sha,
                    reviewer = excluded.reviewer,
                    path = excluded.path,
                    line = excluded.line,
                    feedback_summary = excluded.feedback_summary,
                    status = excluded.status,
                    remediated_at = CURRENT_TIMESTAMP
                """,
                (
                    thread_id,
                    comment_id,
                    repo_slug,
                    pr_number,
                    commit_sha,
                    reviewer,
                    path,
                    line,
                    feedback_summary,
                    status,
                ),
            )
            row = conn.execute(
                "SELECT id FROM review_remediations WHERE thread_id = ?",
                (thread_id,),
            ).fetchone()
            return int(row["id"]) if row else 0

    def is_thread_remediated(self, thread_id: str, require_resolved: bool = False) -> bool:
        """Check if a review thread has already been remediated."""
        query = "SELECT 1 FROM review_remediations WHERE thread_id = ?"
        params: list[Any] = [thread_id]
        if require_resolved:
            query += " AND status = 'RESOLVED'"
        query += " LIMIT 1"
        with self.get_connection() as conn:
            row = conn.execute(query, tuple(params)).fetchone()
            return row is not None

    def get_review_remediations(
        self,
        repo_slug: Optional[str] = None,
        pr_number: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Retrieve review remediations optionally filtered by repo_slug and pr_number."""
        query = "SELECT * FROM review_remediations WHERE 1=1"
        params: list[Any] = []
        if repo_slug:
            query += " AND repo_slug = ?"
            params.append(repo_slug)
        if pr_number is not None:
            query += " AND pr_number = ?"
            params.append(pr_number)
        query += " ORDER BY id DESC"
        with self.get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [dict(r) for r in rows]

