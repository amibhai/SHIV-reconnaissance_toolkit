"""
recon.core — Core infrastructure for the reconnaissance toolkit.

LEGAL NOTICE: This toolkit is for authorized security testing and
educational purposes only. Unauthorized use against systems you do not
own or have explicit written permission to test is illegal.
"""

from recon.core.config import ReconConfig
from recon.core.logger import get_logger, console
from recon.core.output import OutputManager, ScanReport
from recon.core.privilege import PrivilegeChecker

__all__ = [
    "ReconConfig",
    "get_logger",
    "console",
    "OutputManager",
    "ScanReport",
    "PrivilegeChecker",
]
