import pytest
from src.utils import format_mac, format_bytes, format_duration, get_service_name, validate_ip

def test_format_mac():
    assert format_mac("00:11:22:aa:bb:cc") == "00:11:22:AA:BB:CC"
    assert format_mac(None) == "00:00:00:00:00:00"

def test_format_bytes():
    assert format_bytes(500) == "500 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1500 * 1024) == "1.5 MB"
    assert format_bytes(-1) == "0 B"

def test_format_duration():
    assert format_duration(0) == "00:00:00"
    assert format_duration(65) == "00:01:05"
    assert format_duration(3600) == "01:00:00"

def test_get_service_name():
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(99999) == "Unknown"
    assert get_service_name(None) == "Unknown"

def test_validate_ip():
    assert validate_ip("192.168.1.1") is True
    assert validate_ip("8.8.8.8") is True
    assert validate_ip("999.999.999.999") is False
    assert validate_ip("invalid") is False
    assert validate_ip("") is False
