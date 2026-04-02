#!/usr/bin/env python3
"""
JavaScript/TypeScript Vulnerability Reachability Analyzer

Analyzes whether vulnerable npm packages are imported or declared in package.json.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import unquote

from .common import (
    CriticalityLevel,
    UsageContext,
    VulnAnalysis,
    normalize_severity,
    build_report_dict,
)

try:
    from .javascript_call_graph import JavaScriptCallGraphBuilder
    HAS_CALL_GRAPH = True
except ImportError:
    HAS_CALL_GRAPH = False


class JavaScriptReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self._declared_dependencies = self._collect_declared_dependencies()
        self.import_patterns = [
            re.compile(r'^\s*import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]'),
            re.compile(r'^\s*import\s+[\'"]([^\'"]+)[\'"]'),
            re.compile(r'require\(\s*[\'"]([^\'"]+)[\'"]\s*\)'),
            re.compile(r'import\(\s*[\'"]([^\'"]+)[\'"]\s*\)'),
        ]
        self.func_def_pattern = re.compile(
            r'^\s*(?:async\s+)?(?:function\s+([a-zA-Z0-9_$]+)\s*\(|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=.*=>)'
        )

        self.call_graph_builder = None
        if HAS_CALL_GRAPH:
            try:
                self.call_graph_builder = JavaScriptCallGraphBuilder(str(self.project_root))
                self.call_graph_builder.build_graph()
            except Exception:
                self.call_graph_builder = None

    def _normalize_package_name(self, package_name: str) -> str:
        raw = (package_name or "").strip()
        if not raw:
            return ""

        # purl: pkg:npm/%40scope/name@1.2.3
        if raw.startswith("pkg:npm/"):
            raw = unquote(raw[len("pkg:npm/"):])

        # scoped names like @scope/pkg@1.2.3 should keep the first @
        if raw.startswith("@") and "@" in raw[1:]:
            raw = raw.rsplit("@", 1)[0]
        elif "@" in raw:
            raw = raw.split("@", 1)[0]

        return raw.strip()

    def _collect_declared_dependencies(self) -> Dict[str, List[UsageContext]]:
        deps: Dict[str, List[UsageContext]] = {}
        for root, dirs, files in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "dist", "build", "coverage", ".next", "out"
            }]
            if "package.json" not in files:
                continue

            pkg_file = Path(root) / "package.json"
            try:
                with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
            except Exception:
                continue

            rel_path = str(pkg_file.relative_to(self.project_root))
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                section_data = data.get(section, {})
                if not isinstance(section_data, dict):
                    continue
                for name, version in section_data.items():
                    normalized = self._normalize_package_name(str(name))
                    if not normalized:
                        continue
                    deps.setdefault(normalized, []).append(
                        UsageContext(
                            file_path=rel_path,
                            line_number=1,
                            context_line=f'{normalized}: {version} ({section})',
                            usage_type="declared_dependency",
                        )
                    )
        return deps

    def find_js_files(self) -> List[Path]:
        files: List[Path] = []
        exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
        for root, dirs, names in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "dist", "build", "coverage", ".next", "out"
            }]
            for name in names:
                if Path(name).suffix in exts:
                    files.append(Path(root) / name)
        return files

    def _module_matches_package(self, module_name: str, package_name: str) -> bool:
        mod = module_name.strip()
        pkg = self._normalize_package_name(package_name)
        if not mod or not pkg:
            return False
        if mod.startswith("."):
            return False
        return mod == pkg or mod.startswith(pkg + "/")

    def find_package_usage(self, package_name: str) -> List[UsageContext]:
        usage_contexts: List[UsageContext] = []
        target = self._normalize_package_name(package_name)
        if not target:
            return usage_contexts

        for js_file in self.find_js_files():
            try:
                with open(js_file, "r", encoding="utf-8", errors="ignore") as f:
                    current_scope: Optional[str] = None
                    for line_num, line in enumerate(f, 1):
                        m = self.func_def_pattern.search(line)
                        if m:
                            current_scope = m.group(1) or m.group(2)
                        for pattern in self.import_patterns:
                            match = pattern.search(line)
                            if not match:
                                continue
                            module_name = match.group(1)
                            if self._module_matches_package(module_name, target):
                                usage_contexts.append(
                                    UsageContext(
                                        file_path=str(js_file.relative_to(self.project_root)),
                                        line_number=line_num,
                                        context_line=line.strip(),
                                        usage_type="import",
                                        enclosing_scope=current_scope,
                                    )
                                )
                                break
            except Exception:
                pass

        return usage_contexts

    def find_declared_dependency_usage(self, package_name: str) -> List[UsageContext]:
        pkg = self._normalize_package_name(package_name)
        return list(self._declared_dependencies.get(pkg, []))

    def analyze_vulnerability(self, vuln_data: Dict) -> VulnAnalysis:
        package_name = self._normalize_package_name(
            vuln_data.get("package_name", vuln_data.get("package", ""))
        )
        installed_version = vuln_data.get("installed_version", vuln_data.get("version", ""))
        recommended_version = vuln_data.get(
            "recommended_version", vuln_data.get("recommended_fixed_version", vuln_data.get("fixed_version", ""))
        )

        import_usages = self.find_package_usage(package_name)
        declared_usages = self.find_declared_dependency_usage(package_name)
        usage_contexts = import_usages + declared_usages

        is_imported = bool(import_usages)
        is_declared = bool(declared_usages)
        is_used = bool(usage_contexts)

        if not is_used:
            criticality = CriticalityLevel.NOT_REACHABLE
            risk_reason = "Package not imported and not declared in package.json"
        else:
            criticality = normalize_severity(vuln_data.get("severity", "MEDIUM"))
            if is_imported and is_declared:
                risk_reason = (
                    f"Package imported in {len(import_usages)} location(s) and "
                    f"declared in package.json"
                )
            elif is_imported:
                risk_reason = f"Package imported in {len(import_usages)} location(s)"
            else:
                risk_reason = "Package declared in package.json"

        call_graph_mermaid = None
        if self.call_graph_builder and is_imported:
            target_methods = {ctx.enclosing_scope for ctx in import_usages if ctx.enclosing_scope}
            if target_methods:
                traces = self.call_graph_builder.find_trace_to_usage(list(target_methods))
                if traces:
                    call_graph_mermaid = self.call_graph_builder.get_mermaid_graph(traces)
                    risk_reason += f" [VERIFIED: {len(traces)} paths from entry points]"
                    if criticality in (CriticalityLevel.HIGH, CriticalityLevel.MEDIUM):
                        criticality = CriticalityLevel.CRITICAL

        return VulnAnalysis(
            package_name=package_name,
            installed_version=installed_version,
            recommended_version=recommended_version,
            is_used=is_used,
            usage_contexts=usage_contexts,
            criticality=criticality,
            risk_reason=risk_reason,
            call_chain_graph=call_graph_mermaid,
        )


def run_javascript_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    print(f"\n{'=' * 60}")
    print("JS/TS Vulnerability Reachability Analysis")
    print(f"{'=' * 60}\n")

    try:
        with open(consolidated_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Error loading consolidated data: {e}")
        return

    analyzer = JavaScriptReachabilityAnalyzer(project_root)
    analyses: List[VulnAnalysis] = []

    for vuln in vulns:
        analysis = analyzer.analyze_vulnerability(vuln)
        analyses.append(analysis)
        status = "✓ USED" if analysis.is_used else "✗ NOT USED"
        print(f"{status} | {analysis.package_name:40} | {analysis.criticality.value:15} | {analysis.risk_reason}")

    report = build_report_dict(analyses, project_root, "javascript")
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved report to {output_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python javascript_reachability_analyzer.py <project_root> <consolidated_json> [output_path]")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "javascript_vulnerability_reachability_report.json"
    run_javascript_reachability_analysis(project_root, consolidated_path, output_path)
