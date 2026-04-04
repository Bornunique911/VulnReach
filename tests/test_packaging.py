from setuptools import find_packages
import tomllib
from pathlib import Path


def test_build_includes_local_scan_runtime_packages():
    packages = set(
        find_packages(
            include=[
                "agents*",
                "api*",
                "config*",
                "core*",
                "correlation*",
                "intelligent_dast*",
                "storage*",
                "vulnreach*",
            ]
        )
    )

    assert {
        "agents",
        "config",
        "core",
        "correlation",
        "storage",
        "vulnreach",
    }.issubset(packages)


def test_base_dependencies_include_packaging_for_trivy_agent():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject["project"]["dependencies"]

    assert any(dep.startswith("packaging>=") for dep in dependencies)
