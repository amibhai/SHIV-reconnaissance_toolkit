#!/usr/bin/env python3
"""
Wireless Adapter Manager
Auto-detects wireless adapters and configures monitor mode
Used by all wireless-dependent reconnaissance tools
"""

import subprocess
import os
import sys
import re
import time

class WirelessManager:
    """
    Automatic wireless adapter detection and monitor mode management
    Supports airmon-ng, iw, and iwconfig methods
    """

    def __init__(self):
        self.interfaces       = {}   # {iface: info_dict}
        self.monitor_iface    = None
        self.original_iface   = None
        self._check_root()

    # ------------------------------------------------------------------ #
    # Root / dependency checks
    # ------------------------------------------------------------------ #

    def _check_root(self):
        if os.geteuid() != 0:
            print("[!] Root required for monitor mode operations")
            print("[!] Run with: sudo python3 wireless.py")
            sys.exit(1)

    def check_dependencies(self):
        """Check for required and optional wireless tools"""
        required = ['ip', 'iw']
        optional = ['airmon-ng', 'airodump-ng', 'iwconfig']

        print("\n[*] Checking wireless tool dependencies...")

        all_ok = True
        for tool in required:
            path = subprocess.run(['which', tool], capture_output=True).returncode
            if path != 0:
                print(f"[!] Missing required: {tool}")
                all_ok = False
            else:
                print(f"[+] Found: {tool}")

        for tool in optional:
            path = subprocess.run(['which', tool], capture_output=True).returncode
            status = "found" if path == 0 else "not found (optional)"
            print(f"[~] {tool}: {status}")

        if not all_ok:
            print("\n[!] Install missing tools:")
            print("    sudo apt install iw iproute2 aircrack-ng wireless-tools")
        return all_ok

    # ------------------------------------------------------------------ #
    # Interface discovery
    # ------------------------------------------------------------------ #

    def discover_interfaces(self):
        """Discover all wireless interfaces using multiple methods"""
        found = {}

        # Method 1 — /sys/class/net
        try:
            for iface in os.listdir('/sys/class/net'):
                if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                    found[iface] = {'method': 'sysfs', 'mode': 'unknown'}
        except Exception:
            pass

        # Method 2 — iw dev
        try:
            out = subprocess.run(['iw', 'dev'], capture_output=True, text=True).stdout
            current = None
            for line in out.splitlines():
                m = re.match(r'\s*Interface\s+(\S+)', line)
                if m:
                    current = m.group(1)
                    if current not in found:
                        found[current] = {}
                if current:
                    if 'type' in line.lower():
                        mode = line.split()[-1]
                        found[current]['mode'] = mode
                    if 'addr' in line.lower():
                        mac = line.split()[-1]
                        found[current]['mac'] = mac
        except Exception:
            pass

        # Method 3 — iwconfig fallback
        if not found:
            try:
                out = subprocess.run(['iwconfig'], capture_output=True,
                                     text=True, stderr=subprocess.STDOUT).stdout
                for line in out.splitlines():
                    if 'IEEE 802.11' in line:
                        iface = line.split()[0]
                        found[iface] = {'method': 'iwconfig'}
            except Exception:
                pass

        self.interfaces = found
        return found

    # ------------------------------------------------------------------ #
    # Mode helpers
    # ------------------------------------------------------------------ #

    def get_interface_mode(self, iface):
        """Return current mode of an interface (managed/monitor/etc.)"""
        try:
            out = subprocess.run(['iw', 'dev', iface, 'info'],
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                if 'type' in line.lower():
                    return line.split()[-1].lower()
        except Exception:
            pass

        try:
            out = subprocess.run(['iwconfig', iface], capture_output=True,
                                 text=True, stderr=subprocess.STDOUT).stdout
            if 'Mode:Monitor' in out:
                return 'monitor'
            if 'Mode:Managed' in out:
                return 'managed'
        except Exception:
            pass

        return 'unknown'

    def supports_monitor_mode(self, iface):
        """Check if adapter supports monitor mode via iw phy info"""
        try:
            # Get phy for this interface
            out = subprocess.run(['iw', 'dev', iface, 'info'],
                                 capture_output=True, text=True).stdout
            phy = None
            for line in out.splitlines():
                if 'wiphy' in line:
                    phy = 'phy' + line.split('wiphy')[-1].strip()
                    break

            if phy:
                phy_out = subprocess.run(['iw', 'phy', phy, 'info'],
                                         capture_output=True, text=True).stdout
                return 'monitor' in phy_out.lower()
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------ #
    # Monitor mode enable / disable
    # ------------------------------------------------------------------ #

    def _kill_interfering(self):
        """Kill processes that interfere with monitor mode"""
        print("[*] Killing interfering processes (NetworkManager, wpa_supplicant)...")
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'],
                           capture_output=True, check=False)
        except FileNotFoundError:
            # Manual kill
            for proc in ['wpa_supplicant', 'NetworkManager']:
                subprocess.run(['pkill', '-f', proc],
                               capture_output=True, check=False)
            time.sleep(1)

    def enable_monitor_mode(self, iface):
        """
        Enable monitor mode using best available method.
        Returns monitor interface name on success, None on failure.
        """
        print(f"\n[*] Enabling monitor mode on {iface}...")

        # Already in monitor mode?
        if self.get_interface_mode(iface) == 'monitor':
            print(f"[+] {iface} already in monitor mode")
            self.monitor_iface   = iface
            self.original_iface  = iface
            return iface

        self._kill_interfering()

        # Try airmon-ng first (most reliable)
        if subprocess.run(['which', 'airmon-ng'], capture_output=True).returncode == 0:
            result = subprocess.run(['airmon-ng', 'start', iface],
                                    capture_output=True, text=True)
            print(result.stdout)

            # airmon-ng may rename interface → wlan0mon
            for candidate in [f'{iface}mon', iface, 'wlan0mon', 'wlan1mon']:
                if os.path.exists(f'/sys/class/net/{candidate}'):
                    if self.get_interface_mode(candidate) == 'monitor':
                        self.monitor_iface  = candidate
                        self.original_iface = iface
                        print(f"[+] Monitor interface ready: {candidate}")
                        return candidate

        # Manual iw method
        print(f"[*] Trying manual iw method for {iface}...")
        try:
            subprocess.run(['ip',  'link', 'set', iface, 'down'], check=True)
            subprocess.run(['iw',   iface, 'set', 'monitor', 'none'], check=True)
            subprocess.run(['ip',  'link', 'set', iface, 'up'], check=True)
            time.sleep(1)

            if self.get_interface_mode(iface) == 'monitor':
                self.monitor_iface  = iface
                self.original_iface = iface
                print(f"[+] Monitor mode enabled: {iface}")
                return iface
        except subprocess.CalledProcessError as e:
            print(f"[!] iw method failed: {e}")

        print(f"[!] Could not enable monitor mode on {iface}")
        return None

    def disable_monitor_mode(self):
        """Restore interface to managed mode"""
        if not self.monitor_iface:
            return

        iface = self.monitor_iface
        print(f"\n[*] Disabling monitor mode on {iface}...")

        if subprocess.run(['which', 'airmon-ng'], capture_output=True).returncode == 0:
            subprocess.run(['airmon-ng', 'stop', iface], capture_output=True)
        else:
            subprocess.run(['ip',  'link', 'set', iface, 'down'], capture_output=True)
            subprocess.run(['iw',   iface, 'set', 'type', 'managed'], capture_output=True)
            subprocess.run(['ip',  'link', 'set', iface, 'up'], capture_output=True)

        # Restart NetworkManager
        subprocess.run(['systemctl', 'start', 'NetworkManager'],
                       capture_output=True, check=False)
        print("[+] Monitor mode disabled — managed mode restored")
        self.monitor_iface = None

    # ------------------------------------------------------------------ #
    # Channel management
    # ------------------------------------------------------------------ #

    def set_channel(self, iface, channel):
        """Set wireless channel"""
        try:
            subprocess.run(['iw', 'dev', iface, 'set', 'channel', str(channel)],
                           capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            try:
                subprocess.run(['iwconfig', iface, 'channel', str(channel)],
                               capture_output=True)
                return True
            except Exception:
                return False

    def hop_channels(self, iface, channels=None, interval=0.5):
        """
        Channel hopping for comprehensive wireless coverage
        
        Args:
            iface: Monitor mode interface
            channels: List of channels (default: 1-14 for 2.4GHz)
            interval: Seconds per channel
        """
        if channels is None:
            channels = list(range(1, 14))   # 2.4 GHz

        print(f"[*] Channel hopping on {iface} "
              f"(channels {channels[0]}-{channels[-1]}, {interval}s each)")

        while True:
            for ch in channels:
                if self.set_channel(iface, ch):
                    print(f"\r[*] Channel: {ch:2d}", end='', flush=True)
                time.sleep(interval)

    # ------------------------------------------------------------------ #
    # Auto-setup (main entry point)
    # ------------------------------------------------------------------ #

    def auto_setup(self):
        """
        Fully automatic wireless adapter detection and monitor mode setup.
        Returns monitor interface name or None.
        """
        print("\n" + "="*55)
        print("  Wireless Adapter Auto-Detection & Monitor Mode Setup")
        print("="*55)

        self.check_dependencies()

        print("\n[*] Scanning for wireless interfaces...")
        interfaces = self.discover_interfaces()

        if not interfaces:
            print("\n[!] No wireless interfaces detected")
            print("[!] Ensure your wireless adapter is connected (USB/PCIe)")
            return None

        print(f"\n[+] Detected {len(interfaces)} wireless interface(s):")
        for iface, info in interfaces.items():
            mode = self.get_interface_mode(iface)
            mac  = info.get('mac', 'unknown')
            print(f"    • {iface:<12} mode={mode:<10} mac={mac}")

        # Prefer already-in-monitor-mode interfaces
        for iface in interfaces:
            if self.get_interface_mode(iface) == 'monitor':
                print(f"\n[+] Using existing monitor interface: {iface}")
                self.monitor_iface  = iface
                self.original_iface = iface
                return iface

        # Find first adapter that supports monitor mode
        for iface in interfaces:
            print(f"\n[*] Testing {iface} for monitor mode support...")
            if self.supports_monitor_mode(iface):
                print(f"[+] {iface} supports monitor mode")
                result = self.enable_monitor_mode(iface)
                if result:
                    return result
            else:
                print(f"[-] {iface} does not support monitor mode")

        print("\n[!] No adapter with monitor mode support found")
        print("[!] Try: sudo apt install aircrack-ng")
        return None

    def get_monitor_interface(self):
        """Return currently active monitor interface"""
        return self.monitor_iface


# ------------------------------------------------------------------ #
# Standalone run
# ------------------------------------------------------------------ #

if __name__ == '__main__':
    wm = WirelessManager()
    monitor = wm.auto_setup()

    if monitor:
        print(f"\n[+] Ready — monitor interface: {monitor}")
        print("[*] Press Ctrl+C to disable monitor mode and exit\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            wm.disable_monitor_mode()
    else:
        print("\n[!] Monitor mode setup failed")
        sys.exit(1)
