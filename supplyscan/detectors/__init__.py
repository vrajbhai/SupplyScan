"""Detector implementations for SupplyScan."""

from supplyscan.detectors.ast_detector import AstDetector
from supplyscan.detectors.cve_detector import CveDetector
from supplyscan.detectors.entropy_detector import EntropyDetector
from supplyscan.detectors.local_feed import LocalFeedDetector
from supplyscan.detectors.maintainer import MaintainerDetector
from supplyscan.detectors.network_detector import NetworkDetector
from supplyscan.detectors.semgrep_detector import SemgrepDetector
from supplyscan.detectors.typosquat import TyposquatDetector
from supplyscan.detectors.yara_detector import YaraDetector

__all__ = [
    "AstDetector",
    "CveDetector",
    "EntropyDetector",
    "LocalFeedDetector",
    "MaintainerDetector",
    "NetworkDetector",
    "SemgrepDetector",
    "TyposquatDetector",
    "YaraDetector",
]

