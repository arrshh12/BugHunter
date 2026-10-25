"""
Bugfinding Agent for AutoBugHunter 24/7 Two-Agent Architecture (R1).
Discovers, ingests multi-scanner findings (Flake8, ESLint, Bandit, Semgrep, Trivy),
clusters proximity findings (±2 lines), ranks by 5-axis severity, and generates
per-repo Bug-log.md maintaining state across re-scans.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.bughunter_agent import RawFinding, TriagedFinding, TriageSkill
from src.code_graph import CodeGraphEngine
from src.config import Config


@dataclass
class BugLogEntry:
    """Represents a single bug entry in Bug-log.md."""

    bug_id: str
    file_path: str
    line: int
    tool: str
    rule_id: str
    description: str
    is_done: bool = False
    raw_line: str = ""


class BugfindingAgent:
    """Autonomous bug discovery agent.

    Scans repositories, clusters findings via TriageSkill, and writes per-repo Bug-log.md.
    """

    DEFAULT_TARGET_REPOS = [
        "bitxwolf/Airllm-tui",
        "bitxwolf/orb",
        "bitxwolf/worldof3js",
        "bitxwolf/medical-for-non-medics",
        "bitxwolf/BugHunter",
    ]

    BUG_LOG_PATTERN = re.compile(
        r"^-\s*\[(?P<status>[ xX])\]\s*(?:DONE\s*:?\s*)?"
        r"(?:\*\*(?P<tag1>BUG-[^*]+)\*\*:?\s*)?"
        r"(?P<file>[^:\s]+):(?P<line>\d+)\s*-\s*\[(?P<tool>[^:]+):(?P<rule>[^\]]+)\]\s*(?P<desc>.*)$"
    )

    def __init__(
        self,
        config: Config | None = None,
        triage_skill: TriageSkill | None = None,
        bug_log_lock: threading.Lock | None = None,
    ):
        self.config = config
        self.triage_skill = triage_skill or TriageSkill()
        self._lock = bug_log_lock or threading.Lock()

    def get_target_repositories(self) -> list[str]:
        """Return the 5 target repository slugs."""
        if self.config and self.config.target_repos:
            return self.config.target_repos[:5]
        return list(self.DEFAULT_TARGET_REPOS)

    def parse_existing_bug_log(self, bug_log_path: Path) -> list[BugLogEntry]:
        """Parse existing Bug-log.md and return structured entries."""
        if not bug_log_path.exists():
            return []

        entries: list[BugLogEntry] = []
        for line in bug_log_path.read_text(encoding="utf-8").splitlines():
            line_str = line.strip()
            if not line_str.startswith("- ["):
                continue

            m = self.BUG_LOG_PATTERN.match(line_str)
            if m:
                status_char = m.group("status")
                tag1 = m.group("tag1") or ""
                is_done = (status_char.lower() == "x") or ("DONE" in line_str)

                bug_id = tag1 if tag1.startswith("BUG-") else ""
                if not bug_id:
                    m_id = re.search(r"\bBUG-[A-Za-z0-9_-]+\b", line_str)
                    bug_id = m_id.group(0) if m_id else f"BUG-{len(entries) + 1:03d}"

                clean_desc = (
                    m.group("desc")
                    .replace("(DONE)", "")
                    .replace("DONE", "")
                    .strip()
                )

                entries.append(
                    BugLogEntry(
                        bug_id=bug_id,
                        file_path=m.group("file").replace("\\", "/"),
                        line=int(m.group("line")),
                        tool=m.group("tool"),
                        rule_id=m.group("rule"),
                        description=clean_desc,
                        is_done=is_done,
                        raw_line=line_str,
                    )
                )
        return entries

    def ingest_scanner_outputs(
        self,
        raw_outputs: dict[str, Any],
    ) -> list[RawFinding]:
        """Ingest outputs from Flake8, ESLint, Bandit, Semgrep, and Trivy.

        raw_outputs maps tool name -> raw string/dict/list output.
        """
        findings: list[RawFinding] = []
        if "flake8" in raw_outputs:
            findings.extend(self.triage_skill.parse_flake8(raw_outputs["flake8"]))
        if "eslint" in raw_outputs:
            findings.extend(self.triage_skill.parse_eslint(raw_outputs["eslint"]))
        if "bandit" in raw_outputs:
            findings.extend(self.triage_skill.parse_bandit(raw_outputs["bandit"]))
        if "semgrep" in raw_outputs:
            findings.extend(self.triage_skill.parse_semgrep(raw_outputs["semgrep"]))
        if "trivy" in raw_outputs:
            findings.extend(self.triage_skill.parse_trivy(raw_outputs["trivy"]))
        return findings

    @staticmethod
    def _ensure_git_exclude(repo_path: Path) -> None:
        """Ensure Bug-log.md and logs.md are excluded in .git/info/exclude."""
        git_dir = repo_path / ".git"
        if git_dir.is_dir():
            info_dir = git_dir / "info"
            info_dir.mkdir(parents=True, exist_ok=True)
            exclude_file = info_dir / "exclude"
            existing_lines: list[str] = []
            if exclude_file.exists():
                existing_lines = exclude_file.read_text(encoding="utf-8").splitlines()
            patterns_to_add = ["Bug-log.md", "Bug-log*.md", "logs.md"]
            modified = False
            for p in patterns_to_add:
                if p not in existing_lines:
                    existing_lines.append(p)
                    modified = True
            if modified:
                exclude_file.write_text("\n".join(existing_lines) + "\n", encoding="utf-8")

    def generate_bug_log(
        self,
        repo_slug: str,
        findings: list[TriagedFinding],
        repo_path: Path | None = None,
        bug_log_path: Path | None = None,
    ) -> Path:
        """Generate or update Bug-log.md for the given repo.

        Retains existing DONE entries across re-scans.
        """
        target_path = bug_log_path
        if not target_path:
            if repo_path:
                target_path = repo_path / "Bug-log.md"
            else:
                safe_slug = re.sub(r"[/\\:]+", "_", repo_slug).strip("._")
                target_path = Path(f"Bug-log-{safe_slug}.md")

        if repo_path:
            self._ensure_git_exclude(repo_path)

        with self._lock:
            existing_entries = self.parse_existing_bug_log(target_path)

            done_signatures = {
                (e.file_path.lower(), e.line, e.rule_id.lower())
                for e in existing_entries
                if e.is_done
            }
            existing_ids = {e.bug_id for e in existing_entries}

            # 1. Retain all existing DONE entries
            output_entries: list[BugLogEntry] = [e for e in existing_entries if e.is_done]

            # 2. Retain existing pending entries that are still valid and not fixed
            pending_signatures = set()
            for e in existing_entries:
                if not e.is_done:
                    sig = (e.file_path.lower(), e.line, e.rule_id.lower())
                    if sig not in done_signatures:
                        output_entries.append(e)
                        pending_signatures.add(sig)

            # 3. Add new triaged findings that are not already present or DONE
            next_id_num = 1
            for f in findings:
                norm_file = f.file.replace("\\", "/")
                sig = (norm_file.lower(), f.line, f.rule_id.lower())
                if sig in done_signatures or sig in pending_signatures:
                    continue

                while f"BUG-{next_id_num:03d}" in existing_ids:
                    next_id_num += 1

                bug_id = f"BUG-{next_id_num:03d}"
                existing_ids.add(bug_id)
                next_id_num += 1

                tools_str = f.tools_reporting[0] if f.tools_reporting else "static"
                output_entries.append(
                    BugLogEntry(
                        bug_id=bug_id,
                        file_path=norm_file,
                        line=f.line,
                        tool=tools_str,
                        rule_id=f.rule_id,
                        description=f.message.replace("\n", " ").strip(),
                        is_done=False,
                    )
                )
                pending_signatures.add(sig)

            # Render markdown
            lines = [
                f"# Bug Log — {repo_slug}",
                "",
                "## Pending Bugs",
            ]
            pending = [e for e in output_entries if not e.is_done]
            done = [e for e in output_entries if e.is_done]

            if pending:
                for e in pending:
                    lines.append(
                        f"- [ ] **{e.bug_id}**: {e.file_path}:{e.line} - [{e.tool}:{e.rule_id}] {e.description}"
                    )
            else:
                lines.append("*(No pending bugs)*")

            lines.extend(["", "## Fixed Bugs"])
            if done:
                for e in done:
                    lines.append(
                        f"- [x] **{e.bug_id}**: {e.file_path}:{e.line} - [{e.tool}:{e.rule_id}] {e.description} (DONE)"
                    )
            else:
                lines.append("*(No fixed bugs)*")
            lines.append("")

            # Atomic write via temporary file
            parent_dir = target_path.parent
            parent_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_file = tempfile.mkstemp(
                dir=str(parent_dir), prefix="buglog_", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_file, str(target_path))
            except Exception:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
                raise

            return target_path

    def scan_repositories(
        self,
        repo_slugs: list[str],
        repos_dir: Path | None = None,
        graph_engine: CodeGraphEngine | None = None,
        simulated_tool_outputs: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Path]:
        """Scan multiple repositories, rank findings, and generate Bug-log.md per repo.

        Returns a dict of repo_slug -> bug_log_path.
        """
        results: dict[str, Path] = {}
        for slug in repo_slugs:
            repo_path: Path | None = None
            if repos_dir:
                safe_slug = slug.replace("\\", "/").replace("/", "__").strip("._")
                cand = (repos_dir / safe_slug).resolve()
                try:
                    if not cand.is_relative_to(repos_dir.resolve()):
                        cand = (repos_dir / safe_slug.replace(".", "")).resolve()
                except (ValueError, AttributeError):
                    cand = (repos_dir / safe_slug.replace(".", "")).resolve()
                if not cand.exists():
                    clean_name = slug.replace("\\", "/").split("/")[-1]
                    cand_alt = (repos_dir / clean_name).resolve()
                    if cand_alt.exists() and cand_alt.is_relative_to(repos_dir.resolve()):
                        cand = cand_alt
                repo_path = cand

            raw_findings: list[RawFinding] = []
            if simulated_tool_outputs is not None:
                tool_outputs = simulated_tool_outputs.get(slug, {})
                raw_findings = self.ingest_scanner_outputs(tool_outputs)
            else:
                def _parse_raw_findings(items: list[Any]) -> list[RawFinding]:
                    parsed: list[RawFinding] = []
                    for item in items:
                        if isinstance(item, dict):
                            line_val = item.get("line")
                            col_val = item.get("column")
                            try:
                                line_num = int(line_val) if line_val is not None else 1
                            except (ValueError, TypeError):
                                line_num = 1
                            try:
                                col_num = int(col_val) if col_val is not None else 1
                            except (ValueError, TypeError):
                                col_num = 1
                            parsed.append(
                                RawFinding(
                                    tool=str(item.get("tool", "static")),
                                    rule_id=str(item.get("rule_id") or item.get("code") or "static-rule"),
                                    file=str(item.get("file", "")),
                                    line=line_num,
                                    column=col_num,
                                    message=str(item.get("message", "")),
                                    severity=str(item.get("severity", "WARNING")),
                                    code_snippet=str(item.get("code_snippet") or item.get("snippet") or ""),
                                    raw_data=item,
                                )
                            )
                    return parsed

                findings_file = repo_path / ".static_findings.json" if repo_path else None
                if findings_file and findings_file.exists():
                    try:
                        data = json.loads(findings_file.read_text(encoding="utf-8"))
                        if isinstance(data, list):
                            raw_findings = _parse_raw_findings(data)
                    except Exception:
                        pass
                if not raw_findings and repo_path:
                    try:
                        from src.static_scanner import StaticScanner
                        scanner = StaticScanner(config=self.config)
                        static_file = scanner.run_static_prefilter(repo_path, skip_files=[])
                        if static_file and static_file.exists():
                            data = json.loads(static_file.read_text(encoding="utf-8"))
                            if isinstance(data, list):
                                raw_findings = _parse_raw_findings(data)
                    except Exception:
                        pass

            triaged = self.triage_skill.triage_and_rank(
                raw_findings=raw_findings,
                repo_path=repo_path or Path.cwd(),
                graph_engine=graph_engine,
            )
            log_path = self.generate_bug_log(slug, triaged, repo_path=repo_path)
            results[slug] = log_path
        return results
