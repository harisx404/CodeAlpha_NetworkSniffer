import pytest
from scapy.all import IP, TCP, UDP, Ether, ICMP, DNS, DNSQR
from src.config import Config

@pytest.fixture
def base_config():
    return Config()

@pytest.fixture
def sample_tcp_packet():
    """Create a sample TCP/IP packet for testing."""
    return Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / \
           IP(src="192.168.1.10", dst="10.0.0.5", ttl=64) / \
           TCP(sport=12345, dport=80, flags="S", seq=1000)

@pytest.fixture
def sample_udp_packet():
    """Create a sample UDP/IP packet for testing."""
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=5353) / b"payload"

@pytest.fixture
def sample_icmp_packet():
    """Create a sample ICMP packet."""
    return Ether() / IP(src="1.1.1.1", dst="8.8.8.8") / ICMP(type=8)

@pytest.fixture
def sample_dns_packet():
    """Create a sample DNS query packet."""
    return Ether() / IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
