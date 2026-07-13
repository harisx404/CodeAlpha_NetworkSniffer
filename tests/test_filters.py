import pytest
from src.filters import PacketFilter
from src.config import Config

def test_protocol_filter_tcp(sample_tcp_packet, sample_udp_packet):
    config = Config(filter_protocol="tcp")
    filter_engine = PacketFilter(config)
    
    assert filter_engine.should_capture(sample_tcp_packet) is True
    assert filter_engine.should_capture(sample_udp_packet) is False

def test_protocol_filter_udp(sample_tcp_packet, sample_udp_packet):
    config = Config(filter_protocol="udp")
    filter_engine = PacketFilter(config)
    
    assert filter_engine.should_capture(sample_tcp_packet) is False
    assert filter_engine.should_capture(sample_udp_packet) is True

def test_ip_filter_exact(sample_tcp_packet):
    config = Config(filter_src_ip="192.168.1.10")
    filter_engine = PacketFilter(config)
    assert filter_engine.should_capture(sample_tcp_packet) is True
    
    config2 = Config(filter_src_ip="10.0.0.1")
    filter_engine2 = PacketFilter(config2)
    assert filter_engine2.should_capture(sample_tcp_packet) is False

def test_ip_filter_cidr(sample_tcp_packet):
    config = Config(filter_src_ip="192.168.1.0/24")
    filter_engine = PacketFilter(config)
    assert filter_engine.should_capture(sample_tcp_packet) is True

def test_port_filter(sample_tcp_packet):
    config = Config(filter_port=80)
    filter_engine = PacketFilter(config)
    assert filter_engine.should_capture(sample_tcp_packet) is True
    
    config2 = Config(filter_port=443)
    filter_engine2 = PacketFilter(config2)
    assert filter_engine2.should_capture(sample_tcp_packet) is False

def test_bpf_generation():
    config = Config(filter_protocol="tcp", filter_port=80, filter_src_ip="1.1.1.1")
    filter_engine = PacketFilter(config)
    bpf = filter_engine.get_bpf_filter()
    assert "tcp" in bpf
    assert "port 80" in bpf
    assert "src host 1.1.1.1" in bpf
