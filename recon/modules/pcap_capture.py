"""
recon.modules.pcap_capture — Thread-safe PCAP capture engine.

Uses Scapy AsyncSniffer with a ring buffer; multiple modules
can request simultaneous captures routed to separate files.
"""

from __future__ import annotations

import collections
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from recon.core.config import ReconConfig
from recon.core.logger import get_logger

__all__ = ["PCAPCapture", "CaptureSession"]

_log = get_logger("pcap_capture")

# BPF filters per scan module
_DEFAULT_FILTERS: dict[str, str] = {
    "dns_enum":       "udp port 53 or tcp port 53",
    "host_discovery": "icmp or arp",
    "port_scan":      "tcp",
    "vuln_scan":      "tcp or udp",
    "wireless":       "type mgt",
    "full":           "",  # Capture everything
}


@dataclass
class CaptureSession:
    """A single PCAP capture session."""
    session_id: str
    output_path: Path
    bpf_filter: str
    ring_size: int = 10000
    _ring: collections.deque = field(default_factory=lambda: collections.deque(maxlen=10000))
    _sniffer: Any = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _packet_count: int = 0
    _start_time: float = field(default_factory=time.time)
    _active: bool = False

    def packet_count(self) -> int:
        return self._packet_count

    def is_active(self) -> bool:
        return self._active


class PCAPCapture:
    """
    Manages multiple simultaneous PCAP capture sessions.

    Each call to start_capture() creates an independent sniffer
    writing to its own .pcap file.

    Args:
        config: ReconConfig instance.
        output_dir: Directory for PCAP files.
    """

    def __init__(
        self,
        config: ReconConfig | None = None,
        output_dir: Path | None = None,
    ) -> None:
        self.config = config or ReconConfig()
        self.output_dir = (output_dir or self.config.output_dir / "pcap")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, CaptureSession] = {}
        self._sessions_lock = threading.Lock()
        self._flush_thread: threading.Thread | None = None
        self._flush_stop = threading.Event()
        self._start_flush_thread()

    # ------------------------------------------------------------------ #
    # Session management                                                   #
    # ------------------------------------------------------------------ #

    def start_capture(
        self,
        session_id: str,
        scan_module: str = "full",
        iface: str | None = None,
        bpf_filter: str | None = None,
    ) -> CaptureSession | None:
        """
        Start a new PCAP capture session.

        Args:
            session_id: Unique identifier for this capture session.
            scan_module: Module name for default BPF filter selection.
            iface: Network interface (None = Scapy default).
            bpf_filter: BPF filter string (overrides default).

        Returns:
            CaptureSession instance, or None if Scapy unavailable.
        """
        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError:
            _log.warning("Scapy not available; PCAP capture disabled")
            return None

        if session_id in self._sessions:
            _log.warning("Session %s already active", session_id)
            return self._sessions[session_id]

        filt = bpf_filter if bpf_filter is not None else _DEFAULT_FILTERS.get(scan_module, "")
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"{session_id}_{ts}.pcap"
        out_path = self.output_dir / fname

        session = CaptureSession(
            session_id=session_id,
            output_path=out_path,
            bpf_filter=filt,
            ring_size=self.config.pcap_ring_size,
        )
        session._ring = collections.deque(maxlen=self.config.pcap_ring_size)

        def _pkt_handler(pkt):
            with session._lock:
                session._ring.append(pkt)
                session._packet_count += 1

        kwargs: dict[str, Any] = {
            "prn": _pkt_handler,
            "store": False,
        }
        if filt:
            kwargs["filter"] = filt
        if iface:
            kwargs["iface"] = iface

        try:
            sniffer = AsyncSniffer(**kwargs)
            session._sniffer = sniffer
            session._active = True
            sniffer.start()

            with self._sessions_lock:
                self._sessions[session_id] = session

            _log.info(
                "PCAP capture started: session=%s filter='%s' output=%s",
                session_id, filt, out_path,
            )
            return session
        except Exception as exc:
            _log.error("PCAP capture start failed (%s): %s", session_id, exc)
            return None

    def stop_capture(self, session_id: str, flush: bool = True) -> Path | None:
        """
        Stop a capture session and flush remaining packets to disk.

        Args:
            session_id: Session identifier to stop.
            flush: Write remaining ring buffer to disk.

        Returns:
            Path to the written PCAP file, or None.
        """
        with self._sessions_lock:
            session = self._sessions.pop(session_id, None)
        if not session:
            _log.warning("No active session: %s", session_id)
            return None

        try:
            if session._sniffer:
                session._sniffer.stop()
        except Exception:
            pass

        session._active = False

        if flush:
            path = self._flush_session(session)
            _log.info(
                "PCAP session stopped: %s (%d packets → %s)",
                session_id, session._packet_count, path,
            )
            return path
        return session.output_path

    def stop_all(self) -> list[Path]:
        """Stop all active capture sessions."""
        ids = list(self._sessions.keys())
        return [p for sid in ids if (p := self.stop_capture(sid)) is not None]

    # ------------------------------------------------------------------ #
    # PCAP writing                                                         #
    # ------------------------------------------------------------------ #

    def _flush_session(self, session: CaptureSession) -> Path:
        """Write the session ring buffer to a .pcap file."""
        with session._lock:
            packets = list(session._ring)
            session._ring.clear()

        if not packets:
            # Write empty PCAP with header only
            self._write_pcap_file(session.output_path, [], session)
            return session.output_path

        try:
            from scapy.utils import PcapWriter
            with PcapWriter(str(session.output_path), append=True, sync=True) as writer:
                # Write custom comment in the global header comment area
                for pkt in packets:
                    writer.write(pkt)
        except ImportError:
            self._write_pcap_file(session.output_path, packets, session)
        except Exception as exc:
            _log.error("PCAP write error for %s: %s", session.output_path, exc)

        return session.output_path

    def _write_pcap_file(
        self,
        path: Path,
        packets: list[Any],
        session: CaptureSession,
    ) -> None:
        """Write raw PCAP file without Scapy PcapWriter (pure Python fallback)."""
        PCAP_MAGIC = 0xa1b2c3d4
        PCAP_MAJOR = 2
        PCAP_MINOR = 4
        SNAPLEN = 65535
        LINKTYPE_ETHERNET = 1

        try:
            with open(path, "wb") as f:
                # Global header
                f.write(struct.pack(
                    "<IHHiIII",
                    PCAP_MAGIC, PCAP_MAJOR, PCAP_MINOR,
                    0,         # thiszone (GMT)
                    0,         # sigfigs
                    SNAPLEN,
                    LINKTYPE_ETHERNET,
                ))
                # Write packet records
                for pkt in packets:
                    try:
                        raw = bytes(pkt)
                        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
                        ts_sec = int(ts)
                        ts_usec = int((ts - ts_sec) * 1_000_000)
                        f.write(struct.pack(
                            "<IIII",
                            ts_sec, ts_usec, len(raw), len(raw),
                        ))
                        f.write(raw)
                    except Exception:
                        continue
        except OSError as exc:
            _log.error("PCAP file write error %s: %s", path, exc)

    # ------------------------------------------------------------------ #
    # Background flush thread                                              #
    # ------------------------------------------------------------------ #

    def _start_flush_thread(self) -> None:
        """Periodically flush ring buffers to disk."""
        def _flusher():
            while not self._flush_stop.wait(timeout=30):
                with self._sessions_lock:
                    sessions = list(self._sessions.values())
                for session in sessions:
                    if session._active:
                        try:
                            self._flush_session(session)
                        except Exception as exc:
                            _log.debug("Periodic flush error %s: %s", session.session_id, exc)

        self._flush_thread = threading.Thread(
            target=_flusher, daemon=True, name="pcap-flusher"
        )
        self._flush_thread.start()

    def shutdown(self) -> None:
        """Stop all captures and the flush thread."""
        self._flush_stop.set()
        self.stop_all()
        if self._flush_thread:
            self._flush_thread.join(timeout=5)

    def active_sessions(self) -> list[str]:
        """Return IDs of currently active capture sessions."""
        with self._sessions_lock:
            return [sid for sid, s in self._sessions.items() if s.is_active()]
