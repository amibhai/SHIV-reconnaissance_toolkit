"""
recon.modules.wireless — Wireless reconnaissance module.

Features:
- Interface detection via /sys/class/net, /proc/net/dev, iw
- Monitor mode: airmon-ng preferred, manual iw fallback
- Channel hopping: 2.4 GHz, 5 GHz, 6 GHz
- 802.11 management frame parsing (Beacon, Probe Response)
- PMKID/EAPOL frame detection
- Clean atexit/signal restoration of managed mode
"""

from __future__ import annotations

import atexit
import os
import platform
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from recon.core.config import ReconConfig
from recon.core.logger import console, get_logger

__all__ = ["WirelessManager", "WirelessNetwork"]

_log = get_logger("wireless")

# Channel lists
_CHANNELS_24GHZ = list(range(1, 14))
_CHANNELS_5GHZ = [
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
]
_CHANNELS_6GHZ = list(range(1, 234, 4))  # 1, 5, 9, ..., 233


@dataclass
class WirelessNetwork:
    """A discovered wireless network from Beacon/Probe frame."""
    bssid: str
    ssid: str = "<hidden>"
    channel: int = 0
    signal_dbm: int = -100
    encryption: str = "Open"
    cipher: str = ""
    auth: str = ""
    vendor: str = ""
    pmkid_seen: bool = False
    eapol_seen: bool = False
    beacons: int = 0
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "signal_dbm": self.signal_dbm,
            "encryption": self.encryption,
            "cipher": self.cipher,
            "auth": self.auth,
            "pmkid_seen": self.pmkid_seen,
            "eapol_seen": self.eapol_seen,
            "beacons": self.beacons,
        }


class WirelessManager:
    """
    Wireless interface and monitoring manager.

    Args:
        config: ReconConfig instance.
    """

    def __init__(self, config: ReconConfig | None = None) -> None:
        self.config = config or ReconConfig()
        self._interfaces: list[dict[str, str]] = []
        self._monitor_ifaces: list[str] = []
        self._hop_thread: threading.Thread | None = None
        self._sniffer = None
        self._hop_stop = threading.Event()
        self._networks: dict[str, WirelessNetwork] = {}
        self._networks_lock = threading.Lock()
        self._current_channel = 1

        # Register cleanup handlers
        atexit.register(self._cleanup)
        if platform.system() != "Windows":
            try:
                signal.signal(signal.SIGINT,  self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)
            except ValueError:
                # signal.signal() only works from the main thread of the
                # main interpreter; if WirelessManager is constructed
                # from a worker thread, just skip and rely on atexit.
                _log.debug(
                    "Skipping SIGINT/SIGTERM handlers — not in main thread"
                )

    # ------------------------------------------------------------------ #
    # Interface discovery                                                  #
    # ------------------------------------------------------------------ #

    def discover_interfaces(self) -> list[dict[str, str]]:
        """
        Detect all wireless interfaces on the system.

        Returns:
            List of dicts: {name, mac, mode, driver, phy}.
        """
        interfaces: list[dict[str, str]] = []

        if platform.system() == "Windows":
            _log.warning("Wireless monitor mode is not supported on Windows")
            return interfaces

        # Method 1: /sys/class/net
        sys_net = "/sys/class/net"
        if os.path.isdir(sys_net):
            for iface in os.listdir(sys_net):
                wireless_path = f"{sys_net}/{iface}/wireless"
                phy80211_path = f"{sys_net}/{iface}/phy80211"
                if os.path.exists(wireless_path) or os.path.exists(phy80211_path):
                    info = {"name": iface, "mac": "", "mode": "managed", "driver": "", "phy": ""}
                    mac_path = f"{sys_net}/{iface}/address"
                    if os.path.exists(mac_path):
                        try:
                            info["mac"] = open(mac_path).read().strip()
                        except Exception:
                            pass
                    interfaces.append(info)

        # Method 2: iw dev (more details)
        iw_info = self._run_iw_dev()
        if iw_info:
            for iface_info in iw_info:
                name = iface_info.get("name", "")
                existing = next((i for i in interfaces if i["name"] == name), None)
                if existing:
                    existing.update(iface_info)
                else:
                    interfaces.append(iface_info)

        # Method 3: /proc/net/dev fallback
        if not interfaces:
            try:
                with open("/proc/net/dev") as f:
                    for line in f:
                        if "wlan" in line or "wifi" in line or "ath" in line or "wl" in line:
                            name = line.split(":")[0].strip()
                            interfaces.append({"name": name, "mac": "", "mode": "unknown"})
            except Exception:
                pass

        self._interfaces = interfaces
        _log.info("Discovered %d wireless interface(s): %s",
                  len(interfaces), [i["name"] for i in interfaces])
        return interfaces

    def _run_iw_dev(self) -> list[dict[str, str]]:
        """Parse `iw dev` output for interface details."""
        results: list[dict[str, str]] = []
        try:
            out = subprocess.check_output(
                ["iw", "dev"], stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            current: dict[str, str] = {}
            for line in out.splitlines():
                line = line.strip()
                m = re.match(r"Interface\s+(\S+)", line)
                if m:
                    if current.get("name"):
                        results.append(current)
                    current = {"name": m.group(1), "mac": "", "mode": "managed", "phy": ""}
                m = re.match(r"addr\s+([\da-f:]+)", line)
                if m:
                    current["mac"] = m.group(1)
                m = re.match(r"type\s+(\S+)", line)
                if m:
                    current["mode"] = m.group(1)
                m = re.match(r"wiphy\s+(\d+)", line)
                if m:
                    current["phy"] = f"phy{m.group(1)}"
            if current.get("name"):
                results.append(current)
        except (FileNotFoundError, subprocess.SubprocessError):
            pass
        return results

    def get_interface_mode(self, iface: str) -> str:
        """
        Return current mode of a wireless interface.

        Args:
            iface: Interface name.

        Returns:
            Mode string: 'managed', 'monitor', 'AP', etc.
        """
        try:
            out = subprocess.check_output(
                ["iw", "dev", iface, "info"],
                stderr=subprocess.DEVNULL, text=True, timeout=5,
            )
            m = re.search(r"type\s+(\S+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "unknown"

    # ------------------------------------------------------------------ #
    # Monitor mode management                                              #
    # ------------------------------------------------------------------ #

    def enable_monitor_mode(self, iface: str, ask_kill: bool = True) -> str | None:
        """
        Enable monitor mode on a wireless interface.

        Tries airmon-ng first, falls back to manual iw method.

        Args:
            iface: Interface name.
            ask_kill: Prompt before killing interfering processes.

        Returns:
            Monitor mode interface name, or None on failure.
        """
        if platform.system() == "Windows":
            _log.error("Monitor mode not supported on Windows")
            return None

        if os.geteuid() != 0:
            _log.error("Monitor mode requires root privileges")
            return None

        if ask_kill:
            _log.warning(
                "Enabling monitor mode may require killing NetworkManager and wpa_supplicant. "
                "Confirm before proceeding."
            )

        # Try airmon-ng
        monitor_iface = self._airmon_enable(iface)
        if monitor_iface:
            _log.info("[bold green]Monitor mode enabled[/] via airmon-ng: %s", monitor_iface)
            self._monitor_ifaces.append(monitor_iface)
            return monitor_iface

        # Manual iw fallback
        monitor_iface = self._iw_enable_monitor(iface)
        if monitor_iface:
            _log.info("[bold green]Monitor mode enabled[/] via iw: %s", monitor_iface)
            self._monitor_ifaces.append(monitor_iface)
            return monitor_iface

        _log.error("Failed to enable monitor mode on %s", iface)
        return None

    def _kill_interfering_processes(self) -> None:
        """Kill processes that interfere with monitor mode (wifi_down approach)."""
        # Method 1: airmon-ng check kill — handles all interfering processes at once
        try:
            subprocess.run(["airmon-ng", "check", "kill"],
                           capture_output=True, timeout=10)
            _log.debug("airmon-ng check kill completed")
        except Exception:
            pass
        # Method 2: systemctl stop
        for svc in ("NetworkManager", "wpa_supplicant"):
            try:
                subprocess.run(["systemctl", "stop", svc],
                               capture_output=True, timeout=5)
            except Exception:
                pass
        # Method 3: pkill -9 for any remaining processes
        for proc in ("NetworkManager", "wpa_supplicant", "dhclient"):
            try:
                subprocess.run(["pkill", "-9", proc],
                               capture_output=True, timeout=5)
            except Exception:
                pass

    def _airmon_enable(self, iface: str) -> str | None:
        try:
            subprocess.check_output(["airmon-ng", "--help"],
                                    stderr=subprocess.DEVNULL, timeout=3)
        except (FileNotFoundError, subprocess.SubprocessError):
            _log.debug("airmon-ng not found")
            return None
        try:
            self._kill_interfering_processes()
            out = subprocess.check_output(
                ["airmon-ng", "start", iface],
                stderr=subprocess.STDOUT, text=True, timeout=15,
            )
            # Multi-pattern parse (wifi_down approach)
            monitor_iface = self._parse_airmon_output(out)
            if monitor_iface and self._verify_monitor_mode(monitor_iface):
                return monitor_iface
            # Fallback: inspect iw dev for any new monitor-mode interfaces
            candidates = self._get_monitor_ifaces_from_iw()
            if candidates:
                return candidates[0]
            # Last resort: iface + "mon"
            fallback = f"{iface}mon"
            if self._verify_monitor_mode(fallback):
                return fallback
            return None
        except Exception as exc:
            _log.debug("airmon-ng enable failed: %s", exc)
            return None

    @staticmethod
    def _parse_airmon_output(out: str) -> str | None:
        """Try multiple regex patterns to extract monitor interface from airmon-ng output."""
        patterns = [
            r"\(mac80211 monitor mode vif enabled for .+? on \[?(\w+mon\d*)\]?\)",
            r"monitor mode (?:vif )?enabled(?: for|on) \[?(\w+)\]?",
            r"monitor mode enabled on (\w+)",
            r"(\w+mon\d*)\s+on\s+\[phy",
            r"(\w+mon\d*)",
            r"(mon\d+)",
        ]
        _skip = {"for", "on", "enabled", "mode", "monitor", "vif"}
        for pattern in patterns:
            m = re.search(pattern, out, re.IGNORECASE)
            if m:
                candidate = m.group(1)
                if candidate.lower() not in _skip:
                    return candidate
        return None

    def _get_monitor_ifaces_from_iw(self) -> list[str]:
        """Return names of all interfaces currently in monitor mode per `iw dev`."""
        try:
            out = subprocess.check_output(
                ["iw", "dev"], stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            ifaces: list[str] = []
            current = ""
            for line in out.splitlines():
                line = line.strip()
                m = re.match(r"Interface\s+(\S+)", line)
                if m:
                    current = m.group(1)
                if re.search(r"type\s+monitor", line, re.IGNORECASE) and current:
                    ifaces.append(current)
            return ifaces
        except Exception:
            return []

    def _verify_monitor_mode(self, iface: str) -> bool:
        """Return True if the interface is confirmed to be in monitor mode."""
        return self.get_interface_mode(iface) == "monitor"

    def get_monitor_interface(self) -> str | None:
        """
        Return the active monitor-mode interface name.

        Checks the internal tracker first, then falls back to live `iw dev` output.
        """
        if self._monitor_ifaces:
            return self._monitor_ifaces[0]
        live = self._get_monitor_ifaces_from_iw()
        return live[0] if live else None

    def _iw_enable_monitor(self, iface: str) -> str | None:
        try:
            subprocess.run(["ip", "link", "set", iface, "down"],
                           check=True, capture_output=True, timeout=5)
            # Correct iw command: set type monitor (not "set monitor control")
            subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                           check=True, capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", iface, "up"],
                           check=True, capture_output=True, timeout=5)
            if self._verify_monitor_mode(iface):
                return iface
            return None
        except Exception as exc:
            _log.debug("Manual iw monitor failed: %s", exc)
        return None

    def disable_monitor_mode(self, iface: str) -> bool:
        """
        Restore interface to managed mode.

        Args:
            iface: Monitor-mode interface name.

        Returns:
            True if successfully restored.
        """
        if platform.system() == "Windows":
            return False
        # Try airmon-ng stop
        try:
            subprocess.run(["airmon-ng", "stop", iface],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        # Manual restore
        try:
            subprocess.run(["ip", "link", "set", iface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)
            if iface in self._monitor_ifaces:
                self._monitor_ifaces.remove(iface)
            _log.info("[bold green]Restored[/] %s to managed mode", iface)
            return True
        except Exception as exc:
            _log.error("Failed to restore %s: %s", iface, exc)
            return False

    # ------------------------------------------------------------------ #
    # Channel hopping                                                      #
    # ------------------------------------------------------------------ #

    def set_channel(self, iface: str, channel: int) -> bool:
        """
        Set wireless interface to a specific channel.

        Args:
            iface: Interface name (must be in monitor mode).
            channel: Channel number.

        Returns:
            True on success.
        """
        try:
            subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channel)],
                capture_output=True, timeout=3,
            )
            self._current_channel = channel
            return True
        except Exception as exc:
            _log.debug("Channel set failed (%d): %s", channel, exc)
            return False

    def hop_channels(
        self,
        iface: str,
        bands: list[str] | None = None,
        interval: float = 0.5,
    ) -> None:
        """
        Start channel hopping in a daemon thread.

        Args:
            iface: Monitor-mode interface name.
            bands: List of band names: '2.4ghz', '5ghz', '6ghz'.
            interval: Seconds per channel.
        """
        bands = bands or ["2.4ghz", "5ghz"]
        channels: list[int] = []
        if "2.4ghz" in bands:
            channels.extend(_CHANNELS_24GHZ)
        if "5ghz" in bands:
            channels.extend(_CHANNELS_5GHZ)
        if "6ghz" in bands:
            channels.extend(_CHANNELS_6GHZ)

        if not channels:
            channels = _CHANNELS_24GHZ

        self._hop_stop.clear()

        def _hopper():
            idx = 0
            while not self._hop_stop.is_set():
                ch = channels[idx % len(channels)]
                self.set_channel(iface, ch)
                idx += 1
                time.sleep(interval)

        self._hop_thread = threading.Thread(target=_hopper, daemon=True, name="chan-hopper")
        self._hop_thread.start()
        _log.info("Channel hopping started on %s (%d channels)", iface, len(channels))

    def stop_hopping(self) -> None:
        """Stop the channel hopping thread."""
        self._hop_stop.set()
        if self._hop_thread:
            self._hop_thread.join(timeout=3)

    # ------------------------------------------------------------------ #
    # Packet capture & parsing                                             #
    # ------------------------------------------------------------------ #

    def start_capture(self, iface: str, duration: int = 60) -> list[WirelessNetwork]:
        """
        Capture 802.11 management frames and parse networks.

        Args:
            iface: Monitor-mode interface name.
            duration: Capture duration in seconds.

        Returns:
            List of WirelessNetwork objects discovered.
        """
        try:
            from scapy.layers.dot11 import (
                Dot11,
                Dot11Beacon,
                Dot11Elt,
                Dot11ProbeResp,
                EAPOL,
            )
            from scapy.sendrecv import AsyncSniffer
        except ImportError:
            _log.error("Scapy not available; wireless capture disabled")
            return []

        _log.info("Capturing 802.11 frames on %s for %ds", iface, duration)

        def _process_pkt(pkt):
            try:
                self._parse_80211_frame(pkt)
            except Exception:
                pass

        sniffer = AsyncSniffer(
            iface=iface,
            prn=_process_pkt,
            store=False,
            filter="type mgt",
        )
        sniffer.start()
        time.sleep(duration)
        sniffer.stop()

        with self._networks_lock:
            result = sorted(
                self._networks.values(),
                key=lambda n: -n.beacons,
            )
        _log.info("[bold green]Capture complete[/]: %d networks found", len(result))
        return result

    def _parse_80211_frame(self, pkt: Any) -> None:
        """Parse a raw 802.11 frame and update network database."""
        try:
            from scapy.layers.dot11 import (
                Dot11,
                Dot11Beacon,
                Dot11Elt,
                Dot11ProbeResp,
                EAPOL,
            )
        except ImportError:
            return

        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        bssid = dot11.addr3 or dot11.addr2 or ""
        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            return

        is_beacon = pkt.haslayer(Dot11Beacon)
        is_probe_resp = pkt.haslayer(Dot11ProbeResp)
        is_eapol = pkt.haslayer(EAPOL)

        if is_eapol:
            with self._networks_lock:
                if bssid in self._networks:
                    self._networks[bssid].eapol_seen = True
            return

        if not (is_beacon or is_probe_resp):
            return

        # Extract SSID
        ssid = "<hidden>"
        channel = self._current_channel
        enc = "Open"
        cipher = ""
        auth = ""
        signal_dbm = -100

        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0:  # SSID
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace") or "<hidden>"
                    except Exception:
                        ssid = "<hidden>"
                elif elt.ID == 3:  # DS Parameter Set (channel)
                    if elt.info:
                        channel = elt.info[0]
                elif elt.ID == 48:  # RSN (WPA2)
                    enc = "WPA2"
                    rsn_info = self._parse_rsn(bytes(elt.info))
                    cipher = rsn_info.get("cipher", "CCMP")
                    auth = rsn_info.get("auth", "PSK")
                    if "SAE" in auth:
                        enc = "WPA3"
                elif elt.ID == 221:  # Vendor specific (WPA1)
                    info = bytes(elt.info)
                    if info[:4] == b"\x00\x50\xf2\x01" and enc == "Open":
                        enc = "WPA"
                try:
                    elt = elt.payload[Dot11Elt]
                except Exception:
                    break

        # Signal strength from RadioTap
        try:
            from scapy.layers.radiotap import RadioTap
            if pkt.haslayer(RadioTap):
                rt = pkt[RadioTap]
                if hasattr(rt, "dBm_AntSignal"):
                    signal_dbm = rt.dBm_AntSignal
        except Exception:
            pass

        with self._networks_lock:
            if bssid not in self._networks:
                self._networks[bssid] = WirelessNetwork(
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    signal_dbm=signal_dbm,
                    encryption=enc,
                    cipher=cipher,
                    auth=auth,
                )
            net = self._networks[bssid]
            if ssid != "<hidden>":
                net.ssid = ssid
            net.beacons += 1
            if signal_dbm > -100:
                net.signal_dbm = signal_dbm
            net.channel = channel
            net.last_seen = time.time()

    @staticmethod
    def _parse_rsn(data: bytes) -> dict[str, str]:
        """Parse RSN IE to extract cipher suite and AKM."""
        result = {"cipher": "CCMP", "auth": "PSK"}
        try:
            if len(data) < 6:
                return result
            # Version (2) + Group cipher (4)
            offset = 6
            # Pairwise cipher count
            if len(data) < offset + 2:
                return result
            count = int.from_bytes(data[offset:offset+2], "little")
            offset += 2 + count * 4  # Skip pairwise ciphers
            # AKM count
            if len(data) < offset + 2:
                return result
            akm_count = int.from_bytes(data[offset:offset+2], "little")
            offset += 2
            if len(data) >= offset + 4:
                akm_suite = data[offset:offset+4]
                akm_map = {
                    b"\x00\x0f\xac\x02": "PSK",
                    b"\x00\x0f\xac\x04": "PSK-SHA256",
                    b"\x00\x0f\xac\x06": "PSK-SHA256",
                    b"\x00\x0f\xac\x08": "SAE",     # WPA3
                    b"\x00\x0f\xac\x01": "802.1X",
                }
                result["auth"] = akm_map.get(akm_suite, "PSK")
        except Exception:
            pass
        return result

    # ------------------------------------------------------------------ #
    # Auto setup                                                           #
    # ------------------------------------------------------------------ #

    def auto_setup(self, iface: str | None = None) -> str | None:
        """
        Automatic setup: detect interface, enable monitor mode.

        Args:
            iface: Optional interface name. If None, picks first detected.

        Returns:
            Monitor interface name, or None on failure.
        """
        if not self._interfaces:
            self.discover_interfaces()

        if not self._interfaces:
            _log.error("No wireless interfaces found")
            return None

        if iface is None:
            iface = self._interfaces[0]["name"]

        return self.enable_monitor_mode(iface)

    # ------------------------------------------------------------------ #
    # Cleanup                                                              #
    # ------------------------------------------------------------------ #

    def _cleanup(self) -> None:
        """Restore all monitor-mode interfaces to managed mode."""
        self.stop_hopping()
        for iface in list(self._monitor_ifaces):
            try:
                self.disable_monitor_mode(iface)
            except Exception:
                pass

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle SIGINT/SIGTERM for graceful shutdown.

        After restoring interfaces we re-raise the signal with the default
        disposition so the process actually terminates. Returning normally
        would let the interrupted call (e.g. a capture's sleep) resume on an
        interface we just switched back to managed mode.
        """
        _log.info("Signal %d received; restoring interfaces...", signum)
        self._cleanup()
        try:
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)
        except Exception:
            raise KeyboardInterrupt

    def networks(self) -> list[WirelessNetwork]:
        """Return all discovered wireless networks."""
        with self._networks_lock:
            return sorted(self._networks.values(), key=lambda n: -n.beacons)
