#!/usr/bin/env python3
"""
Multi-Language Vulnerability Reachability Analyzer

Automatically detects project language and runs appropriate reachability analysis.
"""

import os
from pathlib import Path
import importlib
from typing import Callable, Dict, List, Optional, Sequence, Set

from .python_reachability_analyzer import run_python_reachability_analysis
from .java_reachability_analyzer import run_java_reachability_analysis

# Optional debug flag
_DEBUG_IMPORTS = os.getenv("VULNREACH_DEBUG_IMPORTS") == "1"
if _DEBUG_IMPORTS:
    print(f"[DEBUG] multi_language_analyzer loaded from: {__file__}")

# Track import errors for analyzers (debug only)
_import_errors: dict[str, Exception] = {}

# Dynamically load optional analyzers to avoid static import errors during analysis
run_javascript_reachability_analysis: Optional[Callable[[str, str, str], None]] = None
run_go_reachability_analysis: Optional[Callable[[str, str, str], None]] = None
run_csharp_reachability_analysis: Optional[Callable[[str, str, str], None]] = None
run_php_reachability_analysis: Optional[Callable[[str, str, str], None]] = None

try:
    _mod = importlib.import_module('.javascript_reachability_analyzer', package=__package__)
    run_javascript_reachability_analysis = getattr(_mod, 'run_javascript_reachability_analysis', None)
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Loaded JavaScript analyzer: {_mod.__file__ if hasattr(_mod,'__file__') else 'no file'} => {run_javascript_reachability_analysis}")
except Exception as e:
    _import_errors["javascript"] = e
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Failed to load JavaScript analyzer: {e.__class__.__name__}: {e}")

try:
    _mod = importlib.import_module('.go_reachability_analyzer', package=__package__)
    run_go_reachability_analysis = getattr(_mod, 'run_go_reachability_analysis', None)
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Loaded Go analyzer: {_mod.__file__ if hasattr(_mod,'__file__') else 'no file'} => {run_go_reachability_analysis}")
except Exception as e:
    _import_errors["go"] = e
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Failed to load Go analyzer: {e.__class__.__name__}: {e}")

try:
    _mod = importlib.import_module('.csharp_reachability_analyzer', package=__package__)
    run_csharp_reachability_analysis = getattr(_mod, 'run_csharp_reachability_analysis', None)
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Loaded C# analyzer: {_mod.__file__ if hasattr(_mod,'__file__') else 'no file'} => {run_csharp_reachability_analysis}")
except Exception as e:
    _import_errors["csharp"] = e
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Failed to load C# analyzer: {e.__class__.__name__}: {e}")

try:
    _mod = importlib.import_module('.php_reachability_analyzer', package=__package__)
    run_php_reachability_analysis = getattr(_mod, 'run_php_reachability_analysis', None)
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Loaded PHP analyzer: {_mod.__file__ if hasattr(_mod,'__file__') else 'no file'} => {run_php_reachability_analysis}")
except Exception as e:
    _import_errors["php"] = e
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Failed to load PHP analyzer: {e.__class__.__name__}: {e}")


# Provide safe no-op stubs if dynamic import failed so unconditional calls won't crash
if run_javascript_reachability_analysis is None:
    def run_javascript_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):  # type: ignore
        print("⚠️ JavaScript analyzer unavailable; skipping reachability analysis.")
if run_go_reachability_analysis is None:
    def run_go_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):  # type: ignore
        print("⚠️ Go analyzer unavailable; skipping reachability analysis.")
if run_csharp_reachability_analysis is None:
    def run_csharp_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):  # type: ignore
        print("⚠️ C# analyzer unavailable; skipping reachability analysis.")
if run_php_reachability_analysis is None:
    def run_php_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):  # type: ignore
        print("⚠️ PHP analyzer unavailable; skipping reachability analysis.")


def get_import_errors() -> dict:
    """Return a copy of analyzer import errors keyed by language name."""
    return dict(_import_errors)


class ProjectLanguageDetector:
    """Detect one or more project languages."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
    
    def _scan_project_signals(self) -> tuple[Dict[str, int], Set[str]]:
        file_counts: Dict[str, int] = {}
        build_files: Set[str] = set()
        
        # Scan for files and build configurations
        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', '__pycache__', '.venv', 'venv', '.env', 'env', 'node_modules',
                'target', 'build', '.gradle', '.idea', '.vscode', 'bin', 'out'
            }]
            
            for file in files:
                # Count source files
                if file.endswith('.py'):
                    file_counts['python'] = file_counts.get('python', 0) + 1
                elif file.endswith('.java'):
                    file_counts['java'] = file_counts.get('java', 0) + 1
                elif file.endswith('.js') or file.endswith('.ts'):
                    file_counts['javascript'] = file_counts.get('javascript', 0) + 1
                elif file.endswith('.go'):
                    file_counts['go'] = file_counts.get('go', 0) + 1
                elif file.endswith('.cs'):
                    file_counts['csharp'] = file_counts.get('csharp', 0) + 1
                elif file.endswith('.php'):
                    file_counts['php'] = file_counts.get('php', 0) + 1

                # Check for build files
                if file in {'pom.xml', 'build.gradle', 'build.gradle.kts'}:
                    build_files.add('java')
                elif file in {'requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'}:
                    build_files.add('python')
                elif file in {'package.json', 'yarn.lock', 'package-lock.json'}:
                    build_files.add('javascript')
                elif file in {'go.mod', 'go.sum'}:
                    build_files.add('go')
                # csproj or solution files may be named per-project, so check suffixes
                elif file.endswith('.csproj') or file.endswith('.sln'):
                    build_files.add('csharp')
                elif file == 'composer.json':
                    build_files.add('php')

        return file_counts, build_files

    def detect_languages(self) -> List[str]:
        """Detect all supported languages present in the repository."""
        file_counts, build_files = self._scan_project_signals()
        detected: List[str] = []

        # Build-file backed languages first.
        for language in _LANGUAGE_ORDER:
            if language in build_files and file_counts.get(language, 0) > 0:
                detected.append(language)

        # Add languages that have source files but no explicit build marker.
        for language in _LANGUAGE_ORDER:
            if file_counts.get(language, 0) > 0 and language not in detected:
                detected.append(language)

        if detected:
            return detected

        if file_counts:
            # Fallback for unusual repos: pick the dominant language.
            return [max(file_counts, key=file_counts.get)]

        return []

    def detect_language(self) -> str:
        """Backward-compatible primary-language detector."""
        languages = self.detect_languages()
        return languages[0] if languages else "unknown"


_LANGUAGE_ORDER = ["python", "java", "javascript", "go", "csharp", "php"]


_ANALYZERS: Dict[str, Callable[[str, str, str], None]] = {
    "python": run_python_reachability_analysis,
    "java": run_java_reachability_analysis,
    "javascript": run_javascript_reachability_analysis,
    "go": run_go_reachability_analysis,
    "csharp": run_csharp_reachability_analysis,
    "php": run_php_reachability_analysis,
}


def run_multi_language_analysis(
    project_root: str,
    consolidated_path: str,
    output_dir: str = None,
    languages: Optional[Sequence[str]] = None,
) -> List[str]:
    """Run reachability analysis for all detected (or requested) languages."""

    if not output_dir:
        output_dir = "security_findings"

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    detector = ProjectLanguageDetector(project_root)
    selected_languages = (
        [str(lang).strip().lower() for lang in languages if str(lang).strip()]
        if languages
        else detector.detect_languages()
    )

    if not selected_languages:
        print("⚠️  No supported languages detected for reachability analysis")
        return []

    print(f"🔍 Detected project languages: {', '.join(lang.upper() for lang in selected_languages)}")

    executed: List[str] = []
    for language in selected_languages:
        analyzer = _ANALYZERS.get(language)
        if analyzer is None:
            print(f"⚠️  Language '{language}' not supported for reachability analysis")
            continue
        output_path = os.path.join(output_dir, f"{language}_vulnerability_reachability_report.json")
        try:
            analyzer(project_root, consolidated_path, output_path)
            executed.append(language)
        except Exception as exc:
            print(f"⚠️  {language.upper()} analyzer failed: {exc}")

    if not executed:
        print("⚠️  No language analyzer produced a report")
    return list(selected_languages)


__all__ = [
    "ProjectLanguageDetector",
    "run_multi_language_analysis",
    "get_import_errors",
]


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python multi_language_analyzer.py <project_root> <consolidated_json>")
        sys.exit(1)
    
    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else None
    
    run_multi_language_analysis(project_root, consolidated_path, output_dir)
