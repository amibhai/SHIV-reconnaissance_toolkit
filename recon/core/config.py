"""
recon.core.config — Global configuration via Pydantic v2 BaseSettings.

Reads from environment variables (RECON_ prefix) and optional
~/.recon/config.toml, with typed defaults for all runtime options.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["ReconConfig"]

_TOML_PATH = Path.home() / ".recon" / "config.toml"


def _load_toml_defaults() -> dict[str, Any]:
    """Load config from ~/.recon/config.toml if present."""
    if not _TOML_PATH.exists():
        return {}
    try:
        if sys.version_info >= (3, 11):
            import tomllib
            with open(_TOML_PATH, "rb") as f:
                return tomllib.load(f)
        else:
            try:
                import tomli
                with open(_TOML_PATH, "rb") as f:
                    return tomli.load(f)
            except ImportError:
                return {}
    except Exception:
        return {}


class ReconConfig(BaseSettings):
    """
    Global runtime configuration for the recon toolkit.

    Fields can be set via:
    - Environment variables (RECON_THREADS=100)
    - ~/.recon/config.toml
    - Direct instantiation (ReconConfig(threads=100))
    """

    model_config = SettingsConfigDict(
        env_prefix="RECON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Concurrency
    threads: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Worker thread count for scanning operations",
    )

    # Timing
    timeout: float = Field(
        default=3.0,
        gt=0,
        description="Socket/connection timeout in seconds",
    )
    rate_limit: float = Field(
        default=0.0,
        ge=0,
        description="Minimum delay between packets/requests in seconds",
    )
    connect_timeout: float = Field(
        default=2.0,
        gt=0,
        description="TCP connect timeout in seconds",
    )

    # Output
    verbosity: int = Field(
        default=1,
        ge=0,
        le=3,
        description="Output verbosity: 0=quiet, 1=normal, 2=verbose, 3=debug",
    )
    output_dir: Path = Field(
        default=Path("./output"),
        description="Directory for scan output files",
    )
    report_formats: list[str] = Field(
        default=["json", "html"],
        description="Output formats: json, csv, html",
    )

    # PCAP
    pcap_enabled: bool = Field(
        default=False,
        description="Enable packet capture for all scans",
    )
    pcap_ring_size: int = Field(
        default=10000,
        ge=100,
        description="Maximum packets to buffer in PCAP ring before flush",
    )

    # Evasion
    evasion_level: int = Field(
        default=0,
        ge=0,
        le=3,
        description=(
            "Evasion aggressiveness: "
            "0=none, 1=random order, 2=rate limiting, 3=full stealth"
        ),
    )
    randomize_ports: bool = Field(
        default=False,
        description="Randomize port scan order",
    )
    ttl_randomize: bool = Field(
        default=False,
        description="Randomize IP TTL in crafted packets",
    )
    decoy_ips: list[str] = Field(
        default=[],
        description="Decoy IP addresses to use in SYN scans",
    )

    # DNS
    dns_resolvers_file: Path = Field(
        default=Path(__file__).parent.parent / "data" / "wordlists" / "dns_resolvers.txt",
        description="Path to custom DNS resolver list",
    )
    dns_use_doh: bool = Field(
        default=False,
        description="Use DNS-over-HTTPS as fallback",
    )

    # Ports
    top_ports: int = Field(
        default=1000,
        ge=1,
        description="Number of top ports to scan when using --top",
    )

    @field_validator("output_dir", mode="before")
    @classmethod
    def expand_output_dir(cls, v: Any) -> Path:
        return Path(v).expanduser().resolve()

    @field_validator("evasion_level", mode="after")
    @classmethod
    def sync_evasion_flags(cls, v: int) -> int:
        return v

    def effective_delay(self) -> float:
        """Return effective inter-packet delay based on evasion level."""
        if self.evasion_level >= 3:
            import random
            return random.uniform(0.5, 2.0)
        if self.evasion_level >= 2:
            import random
            return random.uniform(0.05, 0.3)
        if self.evasion_level >= 1:
            return 0.01
        return self.rate_limit

    def ensure_output_dir(self) -> Path:
        """Create output directory if it does not exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir

    @classmethod
    def from_toml(cls, path: Path | None = None) -> "ReconConfig":
        """Instantiate config, merging TOML file values as defaults."""
        toml_data = _load_toml_defaults() if path is None else {}
        if path and path.exists():
            try:
                if sys.version_info >= (3, 11):
                    import tomllib
                    with open(path, "rb") as f:
                        toml_data = tomllib.load(f)
                else:
                    try:
                        import tomli
                        with open(path, "rb") as f:
                            toml_data = tomli.load(f)
                    except ImportError:
                        pass
            except Exception:
                pass
        return cls(**toml_data)
