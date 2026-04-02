#!/usr/bin/env python3
"""
PHP Vulnerability Reachability Analyzer

Analyzes whether vulnerable Composer packages are used in PHP code.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List

from .common import (
    CriticalityLevel,
    UsageContext,
    VulnAnalysis,
    normalize_severity,
    build_report_dict,
)


class PHPReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self._declared_dependencies = self._parse_composer_json()
        self.use_pattern = re.compile(r'^\s*use\s+([A-Za-z0-9_\\]+)\s*;')

    def _normalize_package_name(self, package_name: str) -> str:
        raw = (package_name or "").strip()
        if raw.startswith("pkg:composer/"):
            raw = raw[len("pkg:composer/"):]
        return raw.split("@", 1)[0].strip().lower()

    def _package_tokens(self, package_name: str) -> List[str]:
        pkg = self._normalize_package_name(package_name)
        return [p for p in re.split(r'[/\-_\.]', pkg) if p]

    def _parse_composer_json(self) -> Dict[str, str]:
        deps: Dict[str, str] = {}
        composer = self.project_root / "composer.json"
        if not composer.exists():
            return deps
        try:
            with open(composer, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            return deps

        for section in ("require", "require-dev"):
            section_deps = data.get(section, {})
            if isinstance(section_deps, dict):
                for name, version in section_deps.items():
                    deps[self._normalize_package_name(str(name))] = str(version)
        return deps

    def find_php_files(self) -> List[Path]:
        files: List[Path] = []
        for root, dirs, names in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in {".git", "vendor", "node_modules", ".idea", ".vscode"}]
            for name in names:
                if name.endswith(".php"):
                    files.append(Path(root) / name)
        return files

    def find_package_usage(self, package_name: str) -> List[UsageContext]:
        usage_contexts: List[UsageContext] = []
        tokens = [t.lower() for t in self._package_tokens(package_name)]
        if not tokens:
            return usage_contexts

        for php_file in self.find_php_files():
            try:
                with open(php_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        m = self.use_pattern.search(line)
                        if not m:
                            continue
                        namespace = m.group(1)
                        ns_tokens = [t.lower() for t in re.split(r'[\\_]', namespace) if t]
                        if any(t in ns_tokens for t in tokens if len(t) > 2):
                            usage_contexts.append(
                                UsageContext(
                                    file_path=str(php_file.relative_to(self.project_root)),
                                    line_number=line_num,
                                    context_line=line.strip(),
                                    usage_type="import",
                                )
                            )
            except Exception:
                pass

        return usage_contexts

    def find_declared_dependency_usage(self, package_name: str) -> List[UsageContext]:
        pkg = self._normalize_package_name(package_name)
        if pkg in self._declared_dependencies:
            return [
                UsageContext(
                    file_path="composer.json",
                    line_number=1,
                    context_line=f'{pkg}: {self._declared_dependencies[pkg]}',
                    usage_type="declared_dependency",
                )
            ]
        short = pkg.split("/")[-1]
        matches: List[UsageContext] = []
        for dep in self._declared_dependencies:
            if dep == pkg or dep.endswith("/" + short):
                matches.append(
                    UsageContext(
                        file_path="composer.json",
                        line_number=1,
                        context_line=f'{dep}: {self._declared_dependencies[dep]}',
                        usage_type="declared_dependency",
                    )
                )
        return matches

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
            risk_reason = "Package not imported and not declared in composer.json"
        else:
            criticality = normalize_severity(vuln_data.get("severity", "MEDIUM"))
            if is_imported and is_declared:
                risk_reason = (
                    f"Package imported in {len(import_usages)} location(s) and "
                    f"declared in composer.json"
                )
            elif is_imported:
                risk_reason = f"Package imported in {len(import_usages)} location(s)"
            else:
                risk_reason = "Package declared in composer.json"

        return VulnAnalysis(
            package_name=package_name,
            installed_version=installed_version,
            recommended_version=recommended_version,
            is_used=is_used,
            usage_contexts=usage_contexts,
            criticality=criticality,
            risk_reason=risk_reason,
            call_chain_graph=None,
        )


def run_php_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    print(f"\n{'=' * 60}")
    print("PHP Vulnerability Reachability Analysis")
    print(f"{'=' * 60}\n")

    try:
        with open(consolidated_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Error loading consolidated data: {e}")
        return

    analyzer = PHPReachabilityAnalyzer(project_root)
    analyses: List[VulnAnalysis] = []

    for vuln in vulns:
        analysis = analyzer.analyze_vulnerability(vuln)
        analyses.append(analysis)
        status = "✓ USED" if analysis.is_used else "✗ NOT USED"
        print(f"{status} | {analysis.package_name:40} | {analysis.criticality.value:15} | {analysis.risk_reason}")

    report = build_report_dict(analyses, project_root, "php")
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved report to {output_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python php_reachability_analyzer.py <project_root> <consolidated_json> [output_path]")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "php_vulnerability_reachability_report.json"
    run_php_reachability_analysis(project_root, consolidated_path, output_path)
