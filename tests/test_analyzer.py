import pytest
from src.analyzer import PacketAnalyzer

def test_analyzer_tcp(sample_tcp_packet):
    analyzer = PacketAnalyzer()
    result = analyzer.analyze(sample_tcp_packet)
    
    assert result["protocol"] == "TCP"
    assert result["src_ip"] == "192.168.1.10"
    assert result["dst_ip"] == "10.0.0.5"
    assert result["src_port"] == 12345
    assert result["dst_port"] == 80
    assert result["protocol_detail"] == "HTTP"  # Port 80
    assert "SYN" in result["flags"]

def test_analyzer_udp(sample_udp_packet):
    analyzer = PacketAnalyzer()
    result = analyzer.analyze(sample_udp_packet)
    
    assert result["protocol"] == "UDP"
    assert result["src_ip"] == "10.0.0.1"
    assert result["src_port"] == 53
    assert result["dst_port"] == 5353
    assert result["protocol_detail"] == "DNS"  # Port 53

def test_analyzer_icmp(sample_icmp_packet):
    analyzer = PacketAnalyzer()
    result = analyzer.analyze(sample_icmp_packet)
    
    assert result["protocol"] == "ICMP"
    assert result["icmp_type"] == 8
    assert result["icmp_type_name"] == "Echo Request"

def test_analyzer_dns(sample_dns_packet):
    analyzer = PacketAnalyzer()
    result = analyzer.analyze(sample_dns_packet)
    
    assert result["protocol"] == "UDP"
    assert result["protocol_detail"] == "DNS"
    assert "example.com" in result["dns_queries"]
