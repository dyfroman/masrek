"""Result parsers — one per scanner tool.

Common interface: parse(file_path: Path, run_id: str) -> list[ParsedFinding]
A missing or empty file yields [] without crashing.
"""

from .headers import parse as parse_headers
from .zap import parse as parse_zap
from .nuclei import parse as parse_nuclei
from .nikto import parse as parse_nikto
from .testssl import parse as parse_testssl
from .gitleaks import parse as parse_gitleaks
from .osv import parse as parse_osv
from .trivy import parse as parse_trivy

__all__ = [
    "parse_headers", "parse_zap", "parse_nuclei",
    "parse_nikto", "parse_testssl", "parse_gitleaks",
    "parse_osv", "parse_trivy",
]
