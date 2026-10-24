"""
Modular BugHunter Agent with Skills (R1) for AutoBugHunter 24/7.
Decouples bug discovery, multi-tool triage, AST context extraction,
and surgical patch planning from code editing.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.code_graph import CodeGraphEngine
from src.static_scanner import FiveAxisTriageEngine

# =========================================================================
# Data Models
# =========================================================================

@dataclass
class RawFinding:
    """Represents an un-triaged finding from an external scanner or linter."""
    tool: str  # "flake8", "eslint", "bandit", "semgrep", "trivy"
    rule_id: str
    file: str  # relative posix path
    line: int = 1
    column: int = 1
    end_line: int | None = None
    end_column: int | None = None
    message: str = ""
    severity: str = "WARNING"  # CRITICAL, HIGH, ERROR, MEDIUM, WARNING, LOW, INFO
    code_snippet: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class TriagedFinding:
    """Represents a deduplicated, scored, and blast-radius-ranked bug."""
    id: str  # Unique deduplication fingerprint
    primary_axis: str  # correctness, security, performance, architecture, readability
    severity: str  # Normalized: CRITICAL, ERROR, WARNING, INFO
    composite_score: float
    blast_radius_score: float
    is_trust_boundary: bool
    inbound_dependents_count: int
    tools_reporting: list[str]  # e.g. ["flake8", "bandit"]
    file: str
    line: int
    column: int
    rule_id: str
    message: str
    code_snippet: str
    stride_category: str | None = None
    owasp_category: str | None = None


@dataclass
class ExtractedContext:
    """Surgical context slice extracting only relevant code structures."""
    file_path: str
    target_line: int
    enclosing_symbol: str  # e.g. "class AuthManager -> def verify_token"
    imports_slice: str  # Top-level or referenced imports
    code_slice: str  # Only the target function, class, or window
    context_type: str  # "ast_python" | "text_window" | "empty"
    total_lines: int
    formatted_prompt_block: str


@dataclass
class PatchPlan:
    """Step-by-step atomic patch specification for Aider."""
    bug_id: str
    target_file: str
    target_line: int
    rule_id: str
    severity: str
    scope: str
    pr_title: str  # fix(<scope>): resolve <rule_id> in <filename>
    pr_body: str
    patch_instructions: list[str]
    aider_prompt: str  # Formatted for aider --message
    diff_ceiling_lines: int = 150
    diff_ceiling_files: int = 3


# =========================================================================
# Skill 1: Static Analysis & Triage Skill
# =========================================================================

class TriageSkill:
    """
    Parses findings from Flake8, ESLint, Bandit, Semgrep, and Trivy;
    deduplicates identical issues across tools;
    ranks by 5-axis severity and codebase blast radius.
    """

    SEVERITY_SCORES: dict[str, float] = {
        "CRITICAL": 2.0,
        "HIGH": 1.5,
        "ERROR": 1.5,
        "MEDIUM": 1.0,
        "WARNING": 1.0,
        "LOW": 0.5,
        "INFO": 0.5,
    }

    def __init__(self, triage_engine: FiveAxisTriageEngine | None = None):
        self.triage_engine = triage_engine or FiveAxisTriageEngine()

    def parse_flake8(self, text: str) -> list[RawFinding]:
        """
        Parse standard Flake8 text output: path:line:col: CODE message
        or path:line: CODE message.
        """
        findings: list[RawFinding] = []
        if not text or not isinstance(text, str):
            return findings

        # Support both Windows (e.g. C:\...) and POSIX relative paths
        pattern = re.compile(
            r"^(?P<path>(?:[a-zA-Z]:[\\/])?[^:\n\r]+):(?P<line>\d+)(?::(?P<col>\d+))?:\s*(?P<code>[A-Za-z0-9_-]+)\s*(?P<msg>.*)$"
        )
        for raw_line in text.splitlines():
            line_str = raw_line.strip()
            if not line_str:
                continue
            m = pattern.match(line_str)
            if m:
                code = m.group("code").upper()
                file_norm = m.group("path").replace("\\", "/").strip()
                line_no = int(m.group("line"))
                col_no = int(m.group("col")) if m.group("col") else 1
                msg = m.group("msg").strip()

                # Severity classification:
                # F... (pyflakes error) or E9... (syntax/IO) or S... (flake8-bandit security) -> ERROR
                # B... (bugbear) or E... (style error) -> WARNING
                # W... (style warning) -> INFO
                if code.startswith(("F", "E9", "S")):
                    sev = "ERROR"
                elif code.startswith(("E", "B")):
                    sev = "WARNING"
                elif code.startswith("W"):
                    sev = "INFO"
                else:
                    sev = "WARNING"

                findings.append(RawFinding(
                    tool="flake8",
                    rule_id=code,
                    file=file_norm,
                    line=line_no,
                    column=col_no,
                    message=msg,
                    severity=sev,
                ))
        return findings

    def parse_eslint(self, data: str | list[Any] | dict[str, Any]) -> list[RawFinding]:
        """Parse ESLint JSON array format output."""
        findings: list[RawFinding] = []
        items = data
        if isinstance(data, str):
            try:
                items = json.loads(data)
            except json.JSONDecodeError:
                return findings

        if isinstance(items, dict) and "results" in items:
            items = items["results"]
        if not isinstance(items, list):
            return findings

        for file_entry in items:
            if not isinstance(file_entry, dict):
                continue
            file_p = str(file_entry.get("filePath") or "").replace("\\", "/").strip()
            messages = file_entry.get("messages") or []
            if not isinstance(messages, list):
                continue
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                sev_num = msg.get("severity", 1)
                sev = "ERROR" if sev_num == 2 else "WARNING"
                rule_id = str(msg.get("ruleId") or "eslint-error")
                line_val = msg.get("line")
                col_val = msg.get("column")
                line_no = int(line_val) if (line_val is not None and str(line_val).isdigit()) else 1
                col_no = int(col_val) if (col_val is not None and str(col_val).isdigit()) else 1
                end_line = msg.get("endLine")
                end_col = msg.get("endColumn")
                end_line_no = int(end_line) if (end_line is not None and str(end_line).isdigit()) else None
                end_col_no = int(end_col) if (end_col is not None and str(end_col).isdigit()) else None
                message = str(msg.get("message") or "")

                findings.append(RawFinding(
                    tool="eslint",
                    rule_id=rule_id,
                    file=file_p,
                    line=line_no,
                    column=col_no,
                    end_line=end_line_no,
                    end_column=end_col_no,
                    message=message,
                    severity=sev,
                    raw_data=msg,
                ))
        return findings

    def parse_bandit(self, data: str | dict[str, Any]) -> list[RawFinding]:
        """Parse Bandit JSON format output."""
        findings: list[RawFinding] = []
        payload = data
        if isinstance(data, str):
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                return findings

        if not isinstance(payload, dict):
            return findings

        results = payload.get("results") or []
        if not isinstance(results, list):
            return findings

        for res in results:
            if not isinstance(res, dict):
                continue
            sev_raw = str(res.get("issue_severity") or "MEDIUM").upper()
            if sev_raw == "HIGH":
                sev = "ERROR"
            elif sev_raw == "MEDIUM":
                sev = "WARNING"
            else:
                sev = "INFO"

            rule_id = str(res.get("test_id") or res.get("test_name") or "bandit-rule")
            file_p = str(res.get("filename") or "").replace("\\", "/").strip()
            line_val = res.get("line_number")
            line_no = int(line_val) if (line_val is not None and str(line_val).isdigit()) else 1
            col_val = res.get("col_offset")
            col_offset = int(col_val) if (col_val is not None and str(col_val).isdigit()) else 1
            issue_text = str(res.get("issue_text") or "")
            code = str(res.get("code") or "").strip()

            findings.append(RawFinding(
                tool="bandit",
                rule_id=rule_id,
                file=file_p,
                line=line_no,
                column=col_offset,
                message=issue_text,
                severity=sev,
                code_snippet=code,
                raw_data=res,
            ))
        return findings

    def parse_semgrep(self, data: str | dict[str, Any]) -> list[RawFinding]:
        """Parse Semgrep JSON format output."""
        findings: list[RawFinding] = []
        payload = data
        if isinstance(data, str):
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                return findings

        if not isinstance(payload, dict):
            return findings

        results = payload.get("results") or []
        if not isinstance(results, list):
            return findings

        for item in results:
            if not isinstance(item, dict):
                continue
            extra = item.get("extra") or {}
            start = item.get("start") or {}
            end = item.get("end") or {}
            if not isinstance(extra, dict):
                extra = {}
            if not isinstance(start, dict):
                start = {}
            if not isinstance(end, dict):
                end = {}
            sev_raw = str(extra.get("severity") or "WARNING").upper()
            if sev_raw in ("ERROR", "CRITICAL"):
                sev = "ERROR"
            elif sev_raw == "WARNING":
                sev = "WARNING"
            else:
                sev = "INFO"

            rule_id = str(item.get("check_id") or "semgrep-rule")
            file_p = str(item.get("path") or "").replace("\\", "/").strip()
            start_line_val = start.get("line")
            start_col_val = start.get("col")
            line_no = int(start_line_val) if (start_line_val is not None and str(start_line_val).isdigit()) else 1
            col_no = int(start_col_val) if (start_col_val is not None and str(start_col_val).isdigit()) else 1
            end_line_val = end.get("line")
            end_col_val = end.get("col")
            end_line = int(end_line_val) if (end_line_val is not None and str(end_line_val).isdigit()) else None
            end_col = int(end_col_val) if (end_col_val is not None and str(end_col_val).isdigit()) else None
            message = str(extra.get("message") or "")
            snippet = str(extra.get("lines") or "").strip()

            findings.append(RawFinding(
                tool="semgrep",
                rule_id=rule_id,
                file=file_p,
                line=line_no,
                column=col_no,
                end_line=end_line,
                end_column=end_col,
                message=message,
                severity=sev,
                code_snippet=snippet,
                raw_data=item,
            ))
        return findings

    def parse_trivy(self, data: str | dict[str, Any]) -> list[RawFinding]:
        """Parse Trivy JSON format output with Vulnerabilities and Misconfigurations."""
        findings: list[RawFinding] = []
        payload = data
        if isinstance(data, str):
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                return findings

        if not isinstance(payload, dict):
            return findings

        results = payload.get("Results") or []
        if not isinstance(results, list):
            return findings

        for res in results:
            if not isinstance(res, dict):
                continue
            target = str(res.get("Target") or "").replace("\\", "/").strip()

            def _norm_trivy_sev(raw: str) -> str:
                s = raw.upper()
                if s == "CRITICAL":
                    return "CRITICAL"
                if s == "HIGH":
                    return "ERROR"
                if s == "MEDIUM":
                    return "WARNING"
                if s == "LOW":
                    return "INFO"
                return "WARNING"

            # 1. Vulnerabilities
            vulns = res.get("Vulnerabilities") or []
            if isinstance(vulns, list):
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    sev_raw = str(vuln.get("Severity") or "MEDIUM")
                    vuln_id = str(vuln.get("VulnerabilityID") or "trivy-vuln")
                    pkg = str(vuln.get("PkgName") or "")
                    title = str(vuln.get("Title") or vuln.get("Description") or "")
                    msg = f"{pkg}: {title}".strip(": ") if pkg else title

                    findings.append(RawFinding(
                        tool="trivy",
                        rule_id=vuln_id,
                        file=target,
                        line=1,
                        column=1,
                        message=msg,
                        severity=_norm_trivy_sev(sev_raw),
                        raw_data=vuln,
                    ))

            # 2. Misconfigurations
            misconfigs = res.get("Misconfigurations") or []
            if isinstance(misconfigs, list):
                for misc in misconfigs:
                    if not isinstance(misc, dict):
                        continue
                    misc_id = str(misc.get("ID") or "trivy-misconfig")
                    cause = misc.get("CauseMetadata") or {}
                    start_line_val = cause.get("StartLine") if isinstance(cause, dict) else None
                    line_no = int(start_line_val) if (start_line_val is not None and str(start_line_val).isdigit()) else 1
                    msg = str(misc.get("Message") or misc.get("Title") or "")
                    sev_raw = str(misc.get("Severity") or "MEDIUM")

                    findings.append(RawFinding(
                        tool="trivy",
                        rule_id=misc_id,
                        file=target,
                        line=line_no,
                        column=1,
                        message=msg,
                        severity=_norm_trivy_sev(sev_raw),
                        raw_data=misc,
                    ))

        return findings

    def deduplicate(self, findings: list[RawFinding]) -> list[list[RawFinding]]:
        """
        Cluster duplicate findings from multiple tools targeting the same line
        or semantic bug using proximity clustering (same file within ±2 lines).
        """
        if not findings:
            return []

        # Group by normalized posix file path
        file_groups: dict[str, list[RawFinding]] = {}
        for f in findings:
            norm_file = Path(f.file).as_posix().lower()
            file_groups.setdefault(norm_file, []).append(f)

        clusters: list[list[RawFinding]] = []
        for _, group in file_groups.items():
            # Sort findings in this file by line number then column
            sorted_group = sorted(group, key=lambda x: (x.line, x.column))
            current_cluster: list[RawFinding] = []
            cluster_base_line: int | None = None

            for f in sorted_group:
                if not current_cluster:
                    current_cluster.append(f)
                    cluster_base_line = f.line
                else:
                    # Bound cluster strictly within 2 lines of the cluster base line
                    if cluster_base_line is not None and abs(f.line - cluster_base_line) <= 2:
                        current_cluster.append(f)
                    else:
                        clusters.append(current_cluster)
                        current_cluster = [f]
                        cluster_base_line = f.line

            if current_cluster:
                clusters.append(current_cluster)

        return clusters

    def calculate_blast_radius(
        self,
        finding: RawFinding,
        graph_engine: Any | None = None,
    ) -> tuple[float, int, bool]:
        """
        Calculate blast radius based on trust boundary exposure (+30)
        and incoming non-test dependency callers (+10 per unique inbound caller).
        """
        norm_file = Path(finding.file).as_posix().lstrip("./")
        is_boundary = self.triage_engine.is_trust_boundary(norm_file)
        inbound_count = 0

        if graph_engine and hasattr(graph_engine, "edges"):
            stem = Path(norm_file).stem
            mod_dot = norm_file.replace("/", ".").replace(".py", "")
            matching_targets = {
                norm_file.lower(),
                stem.lower(),
                mod_dot.lower(),
            }

            inbound_sources: set[str] = set()
            for edge in graph_engine.edges:
                if getattr(edge, "edge_type", "") == "IMPORTS":
                    target = str(getattr(edge, "target", "")).replace("\\", "/").lstrip("./")
                    target_lower = target.lower()
                    source = str(getattr(edge, "source", "")).replace("\\", "/").lstrip("./")
                    source_lower = source.lower()

                    # Exclude self-references and test modules
                    if source_lower in matching_targets or "test" in Path(source_lower).name:
                        continue

                    if (
                        target_lower in matching_targets
                        or target_lower == norm_file.lower()
                        or norm_file.lower().endswith("/" + target_lower + ".py")
                        or norm_file.lower() == target_lower + ".py"
                    ):
                        inbound_sources.add(source)

            inbound_count = len(inbound_sources)

        blast_radius = (inbound_count * 10.0) + (30.0 if is_boundary else 0.0)
        return blast_radius, inbound_count, is_boundary

    def triage_and_rank(
        self,
        raw_findings: list[RawFinding],
        repo_path: Path,
        graph_engine: CodeGraphEngine | None = None,
        skip_files: list[str] | None = None,
    ) -> list[TriagedFinding]:
        """
        Deduplicate, filter skip files, drop cosmetic readability findings,
        calculate composite score, and rank descending.
        """
        skip_set = {Path(s).as_posix().lower() for s in (skip_files or [])}
        skip_names = {Path(s).name.lower() for s in (skip_files or [])}

        clusters = self.deduplicate(raw_findings)
        triaged: list[TriagedFinding] = []

        for cluster in clusters:
            # Evaluate all findings in cluster and filter out skip files and cosmetic readability noise
            valid_candidates: list[tuple[RawFinding, dict[str, Any], str]] = []
            for f in cluster:
                norm_file = Path(f.file).as_posix()
                if norm_file.lower() in skip_set or Path(norm_file).name.lower() in skip_names:
                    continue

                eval_res = self.triage_engine.evaluate_finding({
                    "rule_id": f.rule_id,
                    "message": f.message,
                    "severity": f.severity,
                    "file": norm_file,
                    "tool": f.tool,
                }, repo_path=repo_path)

                primary_axis = eval_res.get("primary_axis", FiveAxisTriageEngine.AXIS_CORRECTNESS)
                base_weight = eval_res.get("base_weight", 0)

                # Dedicated security scanners (Bandit, Trivy) and Flake8-Bandit (S-codes) map to Security axis
                if f.tool.lower() in ("bandit", "trivy") or f.rule_id.upper().startswith("S"):
                    primary_axis = FiveAxisTriageEngine.AXIS_SECURITY
                    base_weight = self.triage_engine.AXIS_WEIGHTS.get(FiveAxisTriageEngine.AXIS_SECURITY, 100)
                    eval_res["primary_axis"] = primary_axis
                    eval_res["base_weight"] = base_weight

                # Drop cosmetic readability noise completely
                if primary_axis == FiveAxisTriageEngine.AXIS_READABILITY or base_weight == 0:
                    continue

                valid_candidates.append((f, eval_res, norm_file))

            if not valid_candidates:
                continue

            # Select representative finding from valid candidates with highest severity score / weight
            best, eval_res, norm_file = max(
                valid_candidates,
                key=lambda item: (
                    item[1].get("base_weight", 0) * self.SEVERITY_SCORES.get(item[0].severity.upper(), 1.0),
                    1 if item[0].code_snippet else 0,
                ),
            )

            primary_axis = eval_res.get("primary_axis", FiveAxisTriageEngine.AXIS_CORRECTNESS)
            base_weight = eval_res.get("base_weight", 0)

            blast_radius, inbound_count, is_boundary = self.calculate_blast_radius(best, graph_engine)
            sev_multiplier = self.SEVERITY_SCORES.get(best.severity.upper(), eval_res.get("severity_multiplier", 1.0))
            composite_score = (base_weight * sev_multiplier) + blast_radius

            tools_reporting = sorted({f.tool for f in cluster if f.tool})
            finding_id = f"{norm_file}:{best.line}:{best.rule_id}"

            snippet = best.code_snippet
            if not snippet and repo_path:
                snippet = self.triage_engine.extract_snippet_context(repo_path, norm_file, best.line)

            triaged.append(TriagedFinding(
                id=finding_id,
                primary_axis=primary_axis,
                severity=best.severity.upper(),
                composite_score=composite_score,
                blast_radius_score=blast_radius,
                is_trust_boundary=is_boundary,
                inbound_dependents_count=inbound_count,
                tools_reporting=tools_reporting,
                file=norm_file,
                line=best.line,
                column=best.column,
                rule_id=best.rule_id,
                message=best.message,
                code_snippet=snippet,
                stride_category=eval_res.get("stride_category"),
                owasp_category=eval_res.get("owasp_category"),
            ))

        triaged.sort(key=lambda x: x.composite_score, reverse=True)
        return triaged


# =========================================================================
# Skill 2: Context Extraction Skill
# =========================================================================

class _EnclosingAstFinder(ast.NodeVisitor):
    """Locate the innermost function or class enclosing target_line."""

    def __init__(self, target_line: int):
        self.target_line = target_line
        self.enclosing_class: ast.ClassDef | None = None
        self.enclosing_fn: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        self._class_stack: list[ast.ClassDef] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        start = node.lineno
        if node.decorator_list:
            start = min(d.lineno for d in node.decorator_list)
        end = getattr(node, "end_lineno", start)
        if start <= self.target_line <= end:
            self._class_stack.append(node)
            self.enclosing_class = node
            self.generic_visit(node)
            self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_fn(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_fn(node)

    def _visit_fn(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        start = node.lineno
        if node.decorator_list:
            start = min(d.lineno for d in node.decorator_list)
        end = getattr(node, "end_lineno", start)
        if start <= self.target_line <= end:
            self.enclosing_fn = node
            if self._class_stack:
                self.enclosing_class = self._class_stack[-1]
            self.generic_visit(node)


class ContextExtractionSkill:
    """
    Extracts surgical code context (enclosing function, class skeleton, immediate imports)
    without passing entire large files. Supports Python AST and generic fallback slicing.
    """

    def extract_context(
        self,
        repo_path: Path,
        file_path: str,
        line_number: int,
        context_window_lines: int = 25,
    ) -> ExtractedContext:
        """Extract surgical context for the target line."""
        norm_rel = file_path.replace("\\", "/").strip().lstrip("/")
        repo_res = repo_path.resolve()
        target = (repo_path / norm_rel).resolve()

        try:
            if not target.is_relative_to(repo_res):
                return ExtractedContext(
                    file_path=norm_rel,
                    target_line=line_number,
                    enclosing_symbol="(File Outside Repository)",
                    imports_slice="",
                    code_slice="",
                    context_type="empty",
                    total_lines=0,
                    formatted_prompt_block="",
                )
        except (ValueError, AttributeError):
            return ExtractedContext(
                file_path=norm_rel,
                target_line=line_number,
                enclosing_symbol="(File Outside Repository)",
                imports_slice="",
                code_slice="",
                context_type="empty",
                total_lines=0,
                formatted_prompt_block="",
            )

        if not target.is_file():
            # Check relative directly within repo
            direct_target = Path(norm_rel)
            if direct_target.is_file() and direct_target.resolve().is_relative_to(repo_res):
                target = direct_target.resolve()
            elif Path(file_path).is_file() and Path(file_path).resolve().is_relative_to(repo_res):
                target = Path(file_path).resolve()
            else:
                return ExtractedContext(
                    file_path=norm_rel,
                    target_line=line_number,
                    enclosing_symbol="(File Not Found)",
                    imports_slice="",
                    code_slice="",
                    context_type="empty",
                    total_lines=0,
                    formatted_prompt_block="",
                )

        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ExtractedContext(
                file_path=norm_rel,
                target_line=line_number,
                enclosing_symbol="(Read Error)",
                imports_slice="",
                code_slice="",
                context_type="empty",
                total_lines=0,
                formatted_prompt_block="",
            )

        lines = content.splitlines()

        if target.suffix.lower() == ".py":
            try:
                return self._extract_python_ast_context(norm_rel, lines, line_number)
            except SyntaxError:
                pass  # Fall back to sliding text window on syntax error

        return self._extract_text_window_context(norm_rel, lines, line_number, context_window_lines)

    def _extract_python_ast_context(
        self,
        file_path: str,
        lines: list[str],
        line_number: int,
    ) -> ExtractedContext:
        """Extract Python enclosing AST function/class and top-level imports."""
        source_code = "\n".join(lines)
        tree = ast.parse(source_code)

        # 1. Extract top-level imports
        import_lines: list[str] = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                start = node.lineno - 1
                end = getattr(node, "end_lineno", node.lineno)
                import_lines.extend(lines[start:end])
        imports_slice = "\n".join(import_lines)

        # 2. Locate enclosing function or class using visitor
        finder = _EnclosingAstFinder(line_number)
        finder.visit(tree)

        target_fn = finder.enclosing_fn
        target_class = finder.enclosing_class

        code_slice_lines: list[str] = []
        annotated_code_lines: list[str] = []
        enclosing_symbol = "module scope"

        if target_fn and target_class:
            fn_kw = "async def" if isinstance(target_fn, ast.AsyncFunctionDef) else "def"
            enclosing_symbol = f"class {target_class.name} -> {fn_kw} {target_fn.name}"

            # Class header
            cls_start = target_class.lineno - 1
            cls_header = lines[cls_start]
            code_slice_lines.append(f"{cls_header}  # (line {target_class.lineno})")
            code_slice_lines.append("    ...")
            annotated_code_lines.append(f"{target_class.lineno:4d} | {cls_header}")
            annotated_code_lines.append("     ... |     # ... (class body omitted)")

            # Function body
            fn_start = target_fn.lineno - 1
            if target_fn.decorator_list:
                fn_start = min(d.lineno for d in target_fn.decorator_list) - 1
            fn_start = max(0, fn_start)
            fn_end = getattr(target_fn, "end_lineno", target_fn.lineno)
            for idx in range(fn_start, min(len(lines), fn_end)):
                code_slice_lines.append(lines[idx])
                annotated_code_lines.append(f"{idx + 1:4d} | {lines[idx]}")

        elif target_fn:
            fn_kw = "async def" if isinstance(target_fn, ast.AsyncFunctionDef) else "def"
            enclosing_symbol = f"{fn_kw} {target_fn.name}"

            fn_start = target_fn.lineno - 1
            if target_fn.decorator_list:
                fn_start = min(d.lineno for d in target_fn.decorator_list) - 1
            fn_start = max(0, fn_start)
            fn_end = getattr(target_fn, "end_lineno", target_fn.lineno)
            for idx in range(fn_start, min(len(lines), fn_end)):
                code_slice_lines.append(lines[idx])
                annotated_code_lines.append(f"{idx + 1:4d} | {lines[idx]}")

        elif target_class:
            enclosing_symbol = f"class {target_class.name}"
            c_start = target_class.lineno - 1
            if target_class.decorator_list:
                c_start = min(d.lineno for d in target_class.decorator_list) - 1
            c_start = max(0, c_start)
            c_end = min(len(lines), getattr(target_class, "end_lineno", target_class.lineno))
            for idx in range(c_start, c_end):
                code_slice_lines.append(lines[idx])
                annotated_code_lines.append(f"{idx + 1:4d} | {lines[idx]}")

        else:
            # Module-level statements: extract window around target line
            start = max(0, line_number - 15)
            end = min(len(lines), line_number + 15)
            for idx in range(start, end):
                code_slice_lines.append(lines[idx])
                annotated_code_lines.append(f"{idx + 1:4d} | {lines[idx]}")

        code_slice = "\n".join(code_slice_lines)
        annotated_slice = "\n".join(annotated_code_lines)

        formatted_block = (
            f"=== SURGICAL CONTEXT: {file_path} (Line {line_number}) ===\n"
            f"Enclosing Symbol: {enclosing_symbol}\n\n"
            f"--- RELEVANT IMPORTS ---\n"
            f"{imports_slice or '(None)'}\n\n"
            f"--- TARGET DEFINITION (Line-Annotated) ---\n"
            f"{annotated_slice}\n"
            f"==========================================================="
        )

        return ExtractedContext(
            file_path=file_path,
            target_line=line_number,
            enclosing_symbol=enclosing_symbol,
            imports_slice=imports_slice,
            code_slice=code_slice,
            context_type="ast_python",
            total_lines=len(lines),
            formatted_prompt_block=formatted_block,
        )

    def _extract_text_window_context(
        self,
        file_path: str,
        lines: list[str],
        line_number: int,
        window: int,
    ) -> ExtractedContext:
        """Language-agnostic sliding window context extraction with top-level imports."""
        import_lines: list[str] = []
        for line in lines[:40]:
            trimmed = line.strip()
            if trimmed.startswith(("import ", "from ", "const ", "var ", "let ", "require(", "#include", "package ", "use ")):
                import_lines.append(line)
        imports_slice = "\n".join(import_lines)

        start = max(0, line_number - 1 - window)
        end = min(len(lines), line_number + window)

        code_slice_lines = lines[start:end]
        code_slice = "\n".join(code_slice_lines)

        annotated_code_lines = [
            f"{idx + 1:4d} | {lines[idx]}" for idx in range(start, end)
        ]
        annotated_slice = "\n".join(annotated_code_lines)
        enclosing_symbol = f"lines {start + 1}-{end}"

        formatted_block = (
            f"=== SURGICAL CONTEXT: {file_path} (Lines {start + 1}-{end} around Line {line_number}) ===\n"
            f"--- TOP DECLARATIONS/IMPORTS ---\n"
            f"{imports_slice or '(None)'}\n\n"
            f"--- LOCAL WINDOW (Line-Annotated) ---\n"
            f"{annotated_slice}\n"
            f"=========================================================================="
        )

        return ExtractedContext(
            file_path=file_path,
            target_line=line_number,
            enclosing_symbol=enclosing_symbol,
            imports_slice=imports_slice,
            code_slice=code_slice,
            context_type="text_window",
            total_lines=len(lines),
            formatted_prompt_block=formatted_block,
        )


# =========================================================================
# Skill 3: Patch Planning Skill
# =========================================================================

class PatchPlanningSkill:
    """
    Formulates surgical step-by-step patch instructions for Aider
    strictly enforcing One Bug = One PR and a <=150 lines diff ceiling.
    """

    def synthesize_scope(self, file_path: str) -> str:
        """Synthesize scope slug from file path."""
        p = Path(file_path.strip().strip('"\''))
        stem = p.stem.lower()
        clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "", stem)
        return clean or "core"

    def formulate_plan(
        self,
        finding: TriagedFinding,
        context: ExtractedContext,
    ) -> PatchPlan:
        """Create surgical patch plan with Aider instructions."""
        scope = self.synthesize_scope(finding.file)
        clean_desc = re.sub(r"[\n\r\t]+", " ", finding.message).strip()
        filename = Path(finding.file).name
        pr_title = f"fix({scope}): resolve {finding.rule_id} in {filename}"

        # Actionable step-by-step instructions
        instructions = [
            f"Open file `{finding.file}` and locate `{context.enclosing_symbol}` around line {finding.line}.",
            f"Address root cause for rule `{finding.rule_id}` ({finding.severity}): {clean_desc}.",
            "Strict Invariant: One Bug = One PR. Fix ONLY this functional issue. Do NOT modify any other functions or files.",
            "Diff Ceiling Budget: Total changes must be <= 150 lines of diff and at most 3 files.",
            "Do NOT make cosmetic changes, formatting rewrites, docstring updates, or unrelated refactorings.",
        ]

        # Markdown PR body
        threat_line = f"**STRIDE Threat**: {finding.stride_category}\n" if finding.stride_category else ""
        owasp_line = f"**OWASP Category**: {finding.owasp_category}\n" if finding.owasp_category else ""
        tools_str = ", ".join(finding.tools_reporting) if finding.tools_reporting else "static_scanner"

        pr_body = (
            f"## Description\n"
            f"Automated surgical remediation of static finding `{finding.rule_id}` ({finding.severity}) "
            f"in `{finding.file}:{finding.line}`.\n\n"
            f"**Primary Axis**: {finding.primary_axis.capitalize()}\n"
            f"**Blast Radius Score**: {finding.blast_radius_score:.1f}\n"
            f"**Reporting Tools**: {tools_str}\n"
            f"{threat_line}{owasp_line}\n"
            f"## Root Cause\n"
            f"{clean_desc}\n\n"
            f"## Remediation Instructions\n"
            + "\n".join(f"- {inst}" for inst in instructions)
            + "\n\n## Verification\n"
            "Ensure tests pass with zero regressions and diff <= 150 lines."
        )

        # Formatted Aider prompt for CLI message
        aider_prompt = (
            f"Fix bug `{finding.rule_id}` in `{finding.file}` at line {finding.line}.\n\n"
            f"MESSAGE: {clean_desc}\n"
            f"ENCLOSING SYMBOL: {context.enclosing_symbol}\n\n"
            f"{context.formatted_prompt_block}\n\n"
            f"INSTRUCTIONS:\n"
            + "\n".join(f"{idx + 1}. {inst}" for idx, inst in enumerate(instructions))
        )

        return PatchPlan(
            bug_id=finding.id,
            target_file=finding.file,
            target_line=finding.line,
            rule_id=finding.rule_id,
            severity=finding.severity,
            scope=scope,
            pr_title=pr_title,
            pr_body=pr_body,
            patch_instructions=instructions,
            aider_prompt=aider_prompt,
            diff_ceiling_lines=150,
            diff_ceiling_files=3,
        )


# =========================================================================
# BugHunterAgent Coordinator
# =========================================================================

class BugHunterAgent:
    """
    Decoupled BugHunter Agent coordinating Triage, Context Extraction,
    and Patch Planning skills. Produces immutable PatchPlans for Aider.
    """

    def __init__(
        self,
        triage_skill: TriageSkill | None = None,
        context_skill: ContextExtractionSkill | None = None,
        planning_skill: PatchPlanningSkill | None = None,
    ):
        self.triage_skill = triage_skill or TriageSkill()
        self.context_skill = context_skill or ContextExtractionSkill()
        self.planning_skill = planning_skill or PatchPlanningSkill()

    def triage_findings(
        self,
        raw_findings: list[RawFinding],
        repo_path: Path,
        graph_engine: CodeGraphEngine | None = None,
        skip_files: list[str] | None = None,
    ) -> list[TriagedFinding]:
        """Run Triage Skill on raw findings."""
        return self.triage_skill.triage_and_rank(
            raw_findings=raw_findings,
            repo_path=repo_path,
            graph_engine=graph_engine,
            skip_files=skip_files,
        )

    def extract_context(
        self,
        repo_path: Path,
        finding: TriagedFinding,
    ) -> ExtractedContext:
        """Run Context Extraction Skill for the given finding."""
        return self.context_skill.extract_context(
            repo_path=repo_path,
            file_path=finding.file,
            line_number=finding.line,
        )

    def create_patch_plan(
        self,
        finding: TriagedFinding,
        context: ExtractedContext,
    ) -> PatchPlan:
        """Run Patch Planning Skill."""
        return self.planning_skill.formulate_plan(finding, context)

    def analyze_and_plan(
        self,
        repo_path: Path,
        raw_findings: list[RawFinding],
        skip_files: list[str] | None = None,
        graph_engine: CodeGraphEngine | None = None,
    ) -> PatchPlan | None:
        """End-to-end pipeline: triage -> extract surgical context -> formulate patch plan."""
        triaged = self.triage_findings(raw_findings, repo_path, graph_engine, skip_files)
        if not triaged:
            return None

        # Select first bug that resolves to an existing file on disk
        for bug in triaged:
            context = self.extract_context(repo_path, bug)
            if context.context_type != "empty":
                return self.create_patch_plan(bug, context)

        # Fallback if no findings match existing files on disk
        top_bug = triaged[0]
        context = self.extract_context(repo_path, top_bug)
        return self.create_patch_plan(top_bug, context)
