"""
ArchSec Reviewer.

Security architecture analysis for cloud-native,
AI, and distributed systems.
"""

from .analyzer import Review, analyze_architecture

__title__ = "archsec-reviewer"
__version__ = "0.1.0"
__author__ = "Khirawdhi Ray"
__license__ = "MIT"

__all__ = [
    "Review",
    "analyze_architecture",
    "__title__",
    "__version__",
    "__author__",
    "__license__",
]
