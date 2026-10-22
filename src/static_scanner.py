"""
Static Analysis Pre-Filter for AutoBugHunter 24/7: Ruff AST and Semgrep OSS integration,
with FiveAxisTriageEngine (code-review-and-quality & security-and-hardening).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional


class FiveAxisTriageEngine:
    """
    5-Axis Static Finding Triage Engine integrating code-review-and-quality & security-and-hardening.
    Axes:
      - Correctness: 100
      - Security: 100
      - Performance: 60
      - Architecture: 40
      - Readability: 0 (filtered out as cosmetic noise)
    """

    AXIS_CORRECTNESS = "correctness"
    AXIS_SECURITY = "security"
    AXIS_PERFORMANCE = "performance"
    AXIS_ARCHITECTURE = "architecture"
    AXIS_READABILITY = "readability"

    AXIS_WEIGHTS: dict[str, int] = {
        AXIS_CORRECTNESS: 100,
        AXIS_SECURITY: 100,
        AXIS_PERFORMANCE: 60,
        AXIS_ARCHITECTURE: 40,
        AXIS_READABILITY: 0,
    }

    SEVERITY_MULTIPLIERS: dict[str, float] = {
        "ERROR": 1.5,
        "WARNING": 1.0,
        "INFO": 0.5,
    }

    # Trust boundary patterns: web_server.py, api/, routes/, cli.py, main.py
    TRUST_BOUNDARY_PATTERNS = [
        re.compile(r"(^|/)(web_server|cli|main)\.py$", re.IGNORECASE),
        re.compile(r"(^|/)(api|routes)/", re.IGNORECASE),
    ]

    def is_trust_boundary(self, file_path: Optional[str]) -> bool:
        """Detect boundary paths: web_server.py, api/, routes/, cli.py, main.py."""
        if not file_path or not isinstance(file_path, str):
            return False
        norm_path = file_path.replace("\\", "/")
        return any(p.search(norm_path) for p in self.TRUST_BOUNDARY_PATTERNS)

    def classify_stride_and_owasp(self, rule_id: str, message: str) -> tuple[str, str]:
        """
        Map security rules to STRIDE categories and OWASP Top 10 categories.
        STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
        OWASP: A01:2021 through A10:2021.
        """
        text = f"{rule_id} {message}".lower()

        # 1. Spoofing / Authentication Failures
        if any(k in text for k in ("auth", "login", "jwt", "session", "csrf", "impersonat", "spoof", "cookie")):
            return "Spoofing", "A07:2021-Identification and Authentication Failures"

        # 2. Information Disclosure / Cryptographic Failures & Secrets
        if any(k in text for k in ("secret", "token", "password", "private key", "leak", "cred", "api_key", "crypt", "hash", "md5", "sha1")):
            return "Information Disclosure", "A02:2021-Cryptographic Failures"

        # 3. Elevation of Privilege / Broken Access Control / Path Traversal
        if any(k in text for k in ("traversal", "path", "directory", "permission", "privilege", "escalat")):
            return "Elevation of Privilege", "A01:2021-Broken Access Control"

        # 4. Tampering / Untrusted Deserialization
        if any(k in text for k in ("pickle", "yaml.load", "deserializ")):
            return "Tampering", "A08:2021-Software and Data Integrity Failures"

        # 5. Tampering / Injection
        if any(k in text for k in ("sql", "injection", "command", "shell", "exec", "eval", "subprocess", "os.system")):
            return "Tampering", "A03:2021-Injection"

        # 6. Denial of Service / Security Misconfiguration
        if any(k in text for k in ("dos", "redos", "unbounded", "timeout", "resource", "flood")):
            return "Denial of Service", "A05:2021-Security Misconfiguration"

        # 7. Repudiation / Security Logging and Monitoring Failures
        if any(k in text for k in ("log", "audit", "repudiat", "trace")):
            return "Repudiation", "A09:2021-Security Logging and Monitoring Failures"

        # 8. Server-Side Request Forgery (SSRF)
        if any(k in text for k in ("ssrf", "request forgery", "open redirect")):
            return "Tampering", "A10:2021-Server-Side Request Forgery (SSRF)"

        return "Tampering", "A04:2021-Insecure Design"

    def map_stride_and_owasp(self, rule_id: str, message: str) -> tuple[str, str]:
        """Alias for classify_stride_and_owasp."""
        return self.classify_stride_and_owasp(rule_id, message)

    def classify_axis(self, rule_id: str, message: str, severity: str = "WARNING", tool: str = "") -> str:
        """Classify a static finding into one of the 5 axes."""
        rule_upper = str(rule_id or "").upper()
        msg_lower = str(message or "").lower()
        sev_upper = str(severity or "WARNING").upper()
        tool_lower = str(tool or "").lower()

        # 1. Security (highest priority, weight 100)
        if rule_upper.startswith("S") or (
            tool_lower == "semgrep" and any(k in rule_upper for k in ("SEC", "CWE", "OWASP"))
        ):
            return self.AXIS_SECURITY
        if any(
            k in msg_lower or k in rule_upper.lower()
            for k in (
                "vulnerability", "injection", "traversal", "xss", "csrf", "secret",
                "token", "password", "leak", "cred", "hash", "deserializ", "pickle",
                "permission", "insecure", "cipher", "cookie", "crypto",
            )
        ):
            return self.AXIS_SECURITY
        if "auth" in rule_upper.lower() or (
            "auth" in msg_lower and (
                "author" not in msg_lower
                or "authoriz" in msg_lower
                or "authoris" in msg_lower
                or "auth" in re.sub(r"\bauthor(s)?\b", "", msg_lower)
            )
        ):
            return self.AXIS_SECURITY

        # 2. Correctness (weight 100)
        if (
            ((rule_upper.startswith("F") and not rule_upper.startswith("FIX")))
            or rule_upper.startswith("E9")
            or rule_upper.startswith("B")
            or rule_upper.startswith("PLE")
            or (rule_upper.startswith("PLR") and not rule_upper.startswith("PLR09"))
            or rule_upper.startswith("ASYNC")
            or rule_upper.startswith("YTT")
        ):
            return self.AXIS_CORRECTNESS
        if any(
            k in msg_lower or k in rule_upper.lower()
            for k in (
                "undefined", "syntax", "null", "none", "exception", "unhandled", "error", "mutable default", "pointer"
            )
        ):
            return self.AXIS_CORRECTNESS

        # 3. Readability: Filter out cosmetic noise (E501, docstring, whitespace, formatting, import ordering, comments)
        if rule_upper == "E501" or "line too long" in msg_lower:
            return self.AXIS_READABILITY
        if bool(re.match(r"^D\d{3}$", rule_upper)) or "docstring" in msg_lower:
            return self.AXIS_READABILITY
        if (
            bool(re.match(r"^I\d{3}$", rule_upper))
            or "import order" in msg_lower
            or "unsorted import" in msg_lower
            or "import block" in msg_lower
        ):
            return self.AXIS_READABILITY
        if bool(re.match(r"^Q\d{3}$", rule_upper)) or "quote" in msg_lower:
            return self.AXIS_READABILITY
        if bool(re.match(r"^COM\d{3}$", rule_upper)) or "trailing comma" in msg_lower:
            return self.AXIS_READABILITY
        if bool(re.match(r"^N\d{3}$", rule_upper)) or "naming" in msg_lower:
            return self.AXIS_READABILITY
        if (
            rule_upper.startswith(("ERA", "PGH", "TD", "FIX"))
            or "commented out" in msg_lower
            or any(k in msg_lower for k in ("todo", "fixme", "xxx"))
        ):
            return self.AXIS_READABILITY
        if (
            rule_upper in ("W291", "W292", "W293", "W391", "W503", "W504")
            or "whitespace" in msg_lower
            or "blank line" in msg_lower
        ):
            return self.AXIS_READABILITY
        if "formatting" in msg_lower:
            return self.AXIS_READABILITY

        # 4. Performance
        if rule_upper.startswith("PERF") or rule_upper.startswith("UP") or "performance" in msg_lower or "n+1" in msg_lower:
            return self.AXIS_PERFORMANCE

        # 5. Architecture
        if rule_upper.startswith("C90") or rule_upper.startswith("PLR09") or rule_upper.startswith("ICN"):
            return self.AXIS_ARCHITECTURE

        # Fallback based on severity
        if sev_upper == "ERROR":
            return self.AXIS_CORRECTNESS
        return self.AXIS_ARCHITECTURE

    def evaluate_finding(
        self,
        finding: dict[str, Any],
        repo_path: Optional[Path] = None
    ) -> dict[str, Any]:
        """Evaluate a finding and return its 5-axis triage metadata."""
        raw_rule = finding.get("rule_id")
        rule_id = str(raw_rule) if raw_rule is not None else ""

        raw_msg = finding.get("message")
        message = str(raw_msg) if raw_msg is not None else ""

        raw_sev = finding.get("severity")
        if isinstance(raw_sev, str) and raw_sev.strip():
            severity = raw_sev.strip().upper()
        else:
            severity = "WARNING"

        raw_file = finding.get("file")
        if raw_file is not None and not isinstance(raw_file, (dict, list, set)):
            file_path = str(raw_file)
        else:
            file_path = ""

        raw_tool = finding.get("tool")
        if raw_tool is not None and not isinstance(raw_tool, (dict, list, set)):
            tool = str(raw_tool)
        else:
            tool = ""

        primary_axis = self.classify_axis(rule_id, message, severity, tool)
        base_weight = self.AXIS_WEIGHTS.get(primary_axis, 40)

        is_boundary = self.is_trust_boundary(file_path)
        boundary_bonus = 30.0 if (is_boundary and base_weight > 0) else 0.0

        if base_weight == 0:
            composite_score = 0.0
        else:
            sev_multiplier = self.SEVERITY_MULTIPLIERS.get(severity, 1.0)
            composite_score = (base_weight * sev_multiplier) + boundary_bonus

        stride_cat, owasp_cat = self.classify_stride_and_owasp(rule_id, message)

        return {
            "primary_axis": primary_axis,
            "base_weight": base_weight,
            "severity_multiplier": self.SEVERITY_MULTIPLIERS.get(severity, 1.0),
            "boundary_bonus": int(boundary_bonus),
            "composite_score": composite_score,
            "stride_category": stride_cat,
            "stride_threat": stride_cat,
            "owasp_category": owasp_cat,
            "is_boundary_exposed": is_boundary,
            "is_trust_boundary": is_boundary,
        }

    def extract_snippet_context(
        self,
        repo_path: Path,
        rel_file: str,
        line_no: int,
        context_lines: int = 2
    ) -> str:
        """Read 2 lines before and 2 lines after target line from target source file."""
        if not rel_file or not isinstance(rel_file, str):
            return ""
        try:
            line_idx = int(line_no)
        except (ValueError, TypeError):
            return ""
        if line_idx < 1:
            return ""
        target_file = repo_path / rel_file
        if not target_file.is_file():
            return ""
        try:
            content = target_file.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            if not lines:
                return ""
            if line_idx > len(lines):
                return ""
            start = max(0, line_idx - 1 - context_lines)
            end = min(len(lines), line_idx + context_lines)
            return "\n".join(lines[start:end])
        except Exception:
            return ""


class StaticScanner:
    """Pre-scanner executing local Ruff and Semgrep tools to isolate high-confidence bugs."""

    def __init__(self, timeout_seconds: int = 90, max_findings: int = 10):
        self.timeout_seconds = timeout_seconds
        self.max_findings = max_findings
        self.triage_engine = FiveAxisTriageEngine()

    def run_static_prefilter(
        self,
        repo_path: Path,
        skip_files: list[str],
        simulated_findings: Optional[list[dict[str, Any]]] = None
    ) -> Path:
        """Run static analysis tools, filter skip_files, rank via FiveAxisTriageEngine, and write .static_findings.json."""
        output_file = repo_path / ".static_findings.json"

        if simulated_findings is not None:
            raw_findings = simulated_findings
        else:
            raw_findings = []

            # 1. Run Ruff AST linter
            if shutil.which("ruff"):
                try:
                    res = subprocess.run(
                        ["ruff", "check", "--output-format=json", "."],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout_seconds
                    )
                    if res.stdout.strip():
                        ruff_items = json.loads(res.stdout)
                        for item in ruff_items:
                            if not isinstance(item, dict):
                                continue
                            try:
                                raw_fn = item.get("filename")
                                file_p = str(raw_fn) if raw_fn is not None else ""
                                try:
                                    rel_file = Path(file_p).relative_to(repo_path).as_posix() if file_p else ""
                                except (ValueError, TypeError):
                                    rel_file = file_p
                                raw_code = item.get("code")
                                code = str(raw_code or "")
                                severity = "ERROR" if (((code.startswith("F") and not code.startswith("FIX"))) or code.startswith("E9")) else "WARNING"
                                loc = item.get("location")
                                if not isinstance(loc, dict):
                                    loc = {}
                                row_val = loc.get("row", 1)
                                try:
                                    row = int(row_val) if row_val is not None else 1
                                except (ValueError, TypeError):
                                    row = 1
                                col_val = loc.get("column", 1)
                                try:
                                    col = int(col_val) if col_val is not None else 1
                                except (ValueError, TypeError):
                                    col = 1
                                snip = self.triage_engine.extract_snippet_context(repo_path, rel_file, row, context_lines=2)
                                raw_findings.append({
                                    "tool": "ruff",
                                    "rule_id": code,
                                    "severity": severity,
                                    "file": rel_file,
                                    "line": row,
                                    "column": col,
                                    "message": str(item.get("message") or ""),
                                    "code_snippet": snip
                                })
                            except Exception:
                                continue
                except Exception:
                    pass

            # 2. Run Semgrep OSS
            if shutil.which("semgrep"):
                try:
                    res = subprocess.run(
                        ["semgrep", "--config=auto", "--json", "--quiet", "."],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout_seconds
                    )
                    if res.stdout.strip():
                        semgrep_data = json.loads(res.stdout)
                        for item in semgrep_data.get("results", []):
                            if not isinstance(item, dict):
                                continue
                            try:
                                file_p = item.get("path", "")
                                try:
                                    rel_file = Path(file_p).relative_to(repo_path).as_posix() if file_p else ""
                                except (ValueError, TypeError):
                                    rel_file = file_p
                                extra = item.get("extra", {})
                                if not isinstance(extra, dict):
                                    extra = {}
                                sev = str(extra.get("severity", "WARNING")).upper()
                                if sev not in ("ERROR", "WARNING", "INFO"):
                                    sev = "WARNING"
                                start_dict = item.get("start", {})
                                if not isinstance(start_dict, dict):
                                    start_dict = {}
                                raw_findings.append({
                                    "tool": "semgrep",
                                    "rule_id": str(item.get("check_id") or ""),
                                    "severity": sev,
                                    "file": rel_file,
                                    "line": start_dict.get("line", 1),
                                    "column": start_dict.get("col", 1),
                                    "message": str(extra.get("message") or ""),
                                    "code_snippet": str(extra.get("lines") or "")
                                })
                            except Exception:
                                continue
                except Exception:
                    pass

        # 3. Filter out skip files
        skip_set = {Path(s).as_posix() for s in skip_files}
        skip_names = {Path(s).name for s in skip_files}

        filtered = []
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            raw_file = f.get("file")
            if not raw_file or isinstance(raw_file, (dict, list, set)):
                f_path = ""
            else:
                try:
                    f_path = Path(str(raw_file)).as_posix()
                except Exception:
                    f_path = str(raw_file)
            f_name = Path(f_path).name if f_path else ""
            if f_path and (f_path in skip_set or f_name in skip_names):
                continue

            # Populate snippet if missing and target file exists
            if not f.get("code_snippet"):
                line_val = f.get("line")
                try:
                    target_line = int(line_val) if line_val is not None else 1
                except (ValueError, TypeError):
                    target_line = 1
                snip = self.triage_engine.extract_snippet_context(
                    repo_path, f_path, target_line, context_lines=2
                )
                if snip:
                    f["code_snippet"] = snip

            # 5-Axis Triage evaluation
            triage_info = self.triage_engine.evaluate_finding(f, repo_path=repo_path)
            if (
                triage_info["primary_axis"] == FiveAxisTriageEngine.AXIS_READABILITY
                or triage_info["composite_score"] <= 0
            ):
                continue  # Filter out all cosmetic Readability noise

            f["triage"] = triage_info
            f["primary_axis"] = triage_info["primary_axis"]
            f["composite_score"] = triage_info["composite_score"]
            f["stride_category"] = triage_info["stride_category"]
            f["owasp_category"] = triage_info["owasp_category"]
            f["is_boundary_exposed"] = triage_info["is_boundary_exposed"]

            filtered.append(f)

        # 4. Rank by composite score descending
        filtered.sort(
            key=lambda x: x.get("triage", {}).get("composite_score", 0),
            reverse=True
        )

        # 5. Cap output to top N
        final_findings = filtered[:self.max_findings]
        output_file.write_text(json.dumps(final_findings, indent=2), encoding="utf-8")
        return output_file
