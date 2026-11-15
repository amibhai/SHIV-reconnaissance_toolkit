"""Single source of truth for the recon-toolkit version.

Every other component (package metadata, CLI help, banner, HTML report footer,
SARIF tool version) reads the version from here. Do not hardcode the version
anywhere else.
"""

__version__ = "2.1.0"
