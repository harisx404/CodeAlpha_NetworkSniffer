"""
filters.py
==========
Packet filtering engine supporting BPF and CIDR IP validation.
"""

import ipaddress
from typing import Optional

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6
try:
    from scapy.layers.dns import DNS
except ImportError:
    DNS = None

from src.config import Config

class PacketFilter:
    """Handles both Python-level packet filtering and BPF generation."""

    def __init__(self, config: Config):
        self.config = config
        self._total_seen = 0
        self._total_passed = 0
        self._bpf_string = self._build_bpf_string()

    def should_capture(self, packet: Packet) -> bool:
        """Evaluate whether a packet matches the configured filters."""
        self._total_seen += 1
        
        try:
            if self.config.filter_protocol and not self._check_protocol(packet):
                return False
            if self.config.filter_src_ip and not self._check_src_ip(packet):
                return False
            if self.config.filter_dst_ip and not self._check_dst_ip(packet):
                return False
            if self.config.filter_port and not self._check_port(packet):
                return False
                
            self._total_passed += 1
            return True
        except Exception:
            # On any filtering error, fail open (let packet through)
            self._total_passed += 1
            return True

    def _check_protocol(self, packet: Packet) -> bool:
        """Check if packet matches the protocol filter."""
        proto = self.config.filter_protocol.lower()
        if proto == "tcp":
            return packet.haslayer(TCP)
        if proto == "udp":
            return packet.haslayer(UDP)
        if proto == "icmp":
            return packet.haslayer(ICMP)
        if proto == "arp":
            return packet.haslayer(ARP)
        if proto == "ip":
            return packet.haslayer(IP) or packet.haslayer(IPv6)
        if proto == "http":
            return packet.haslayer(TCP) and (packet[TCP].dport in [80, 8080] or packet[TCP].sport in [80, 8080])
        if proto == "https":
            return packet.haslayer(TCP) and (packet[TCP].dport in [443, 8443] or packet[TCP].sport in [443, 8443])
        if proto == "dns":
            return packet.haslayer(UDP) and (packet[UDP].dport == 53 or packet[UDP].sport == 53)
        if proto == "ssh":
            return packet.haslayer(TCP) and (packet[TCP].dport == 22 or packet[TCP].sport == 22)
        if proto == "ftp":
            return packet.haslayer(TCP) and (packet[TCP].dport in [20, 21] or packet[TCP].sport in [20, 21])
        if proto == "smtp":
            return packet.haslayer(TCP) and (packet[TCP].dport in [25, 587] or packet[TCP].sport in [25, 587])
            
        return True # Unknown protocol filter, don't drop

    def _check_ip_match(self, packet_ip: str, filter_ip: str) -> bool:
        """Helper to match IP address string against exact or CIDR filter."""
        try:
            if "/" in filter_ip:
                network = ipaddress.ip_network(filter_ip, strict=False)
                addr = ipaddress.ip_address(packet_ip)
                return addr in network
            return packet_ip == filter_ip
        except ValueError:
            # Invalid IP/CIDR in filter or packet, fail closed (don't match)
            return False

    def _check_src_ip(self, packet: Packet) -> bool:
        """Check if packet source IP matches filter."""
        if packet.haslayer(IP):
            return self._check_ip_match(packet[IP].src, self.config.filter_src_ip)
        if packet.haslayer(IPv6):
            return self._check_ip_match(packet[IPv6].src, self.config.filter_src_ip)
        if packet.haslayer(ARP):
            return self._check_ip_match(packet[ARP].psrc, self.config.filter_src_ip)
        return False

    def _check_dst_ip(self, packet: Packet) -> bool:
        """Check if packet destination IP matches filter."""
        if packet.haslayer(IP):
            return self._check_ip_match(packet[IP].dst, self.config.filter_dst_ip)
        if packet.haslayer(IPv6):
            return self._check_ip_match(packet[IPv6].dst, self.config.filter_dst_ip)
        if packet.haslayer(ARP):
            return self._check_ip_match(packet[ARP].pdst, self.config.filter_dst_ip)
        return False

    def _check_port(self, packet: Packet) -> bool:
        """Check if packet source or destination port matches filter."""
        port = self.config.filter_port
        if packet.haslayer(TCP):
            return packet[TCP].sport == port or packet[TCP].dport == port
        if packet.haslayer(UDP):
            return packet[UDP].sport == port or packet[UDP].dport == port
        return False

    def _build_bpf_string(self) -> str:
        """Generate a Berkeley Packet Filter (BPF) string from config."""
        if self.config.bpf_filter:
            return self.config.bpf_filter
            
        parts = []
        proto = self.config.filter_protocol.lower()
        if proto in ["tcp", "udp", "icmp", "arp"]:
            parts.append(proto)
            
        if self.config.filter_src_ip and "/" not in self.config.filter_src_ip:
            parts.append(f"src host {self.config.filter_src_ip}")
            
        if self.config.filter_dst_ip and "/" not in self.config.filter_dst_ip:
            parts.append(f"dst host {self.config.filter_dst_ip}")
            
        if self.config.filter_port:
            parts.append(f"port {self.config.filter_port}")
            
        return " and ".join(parts)

    def get_bpf_filter(self) -> Optional[str]:
        """Return the BPF string if one exists, else None."""
        return self._bpf_string if self._bpf_string else None

    def get_stats(self) -> dict:
        """Return statistics on filtered packets."""
        passed = self._total_passed
        filtered = self._total_seen - passed
        rate = round((filtered / max(self._total_seen, 1)) * 100, 1)
        return {
            "total_seen": self._total_seen,
            "total_passed": passed,
            "total_filtered": filtered,
            "filter_rate": rate
        }

    def is_active(self) -> bool:
        """Return True if any filtering is active."""
        return bool(self.config.filter_protocol or self.config.filter_src_ip or 
                    self.config.filter_dst_ip or self.config.filter_port or self.config.bpf_filter)
