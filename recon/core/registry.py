"""
recon.core.registry — a lightweight scanner registry.

Both front-ends (the Typer CLI and the interactive menu) enumerate capabilities
from one place instead of hard-coding their own lists, and each capability
declares the privilege it needs so availability can be shown honestly. This is a
plain frozen dataclass, not a heavy ABC: the modules have heterogeneous
constructors and return types, so a forced base class would be over-engineering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

__all__ = ["ScannerSpec", "REGISTRY", "register", "get", "all_specs", "available"]


@dataclass(frozen=True)
class ScannerSpec:
    name: str                                   # canonical capability name, e.g. "tlsprobe"
    summary: str                                # one-line description
    required_feature: Optional[str] = None      # privilege key (see privilege.py) or None
    runner: Optional[Callable[..., object]] = None   # engine.run_*(target, config, **opts) -> ScanReport
    menu_order: int = 100
    needs_target: bool = True


REGISTRY: dict[str, ScannerSpec] = {}


def register(spec: ScannerSpec) -> ScannerSpec:
    """Register (or replace) a scanner spec by name."""
    REGISTRY[spec.name] = spec
    return spec


def get(name: str) -> Optional[ScannerSpec]:
    return REGISTRY.get(name)


def all_specs() -> list[ScannerSpec]:
    """All registered specs, ordered for menu display."""
    return sorted(REGISTRY.values(), key=lambda s: (s.menu_order, s.name))


def available(priv) -> list[ScannerSpec]:
    """Specs whose required privilege is satisfied by ``priv`` (a PrivilegeChecker)."""
    out = []
    for spec in all_specs():
        if spec.required_feature is None or priv.can(spec.required_feature):
            out.append(spec)
    return out
