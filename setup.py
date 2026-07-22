from setuptools import setup, find_packages

setup(
    name="packet-vision-network-sniffer",
    version="1.0.0",
    description="PacketVision Network Sniffer — High-performance real-time network packet inspection and protocol analysis engine",
    author="Muhammad Haris (@harisx404)",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.0.0",
        "colorama>=0.4.6"
    ],
    entry_points={
        "console_scripts": [
            "packet-sniffer=main:main"
        ]
    },
    python_requires=">=3.9",
)
