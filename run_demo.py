# Demo script - shows programmatic use of the sniffer
import time
import sys

from src.config import Config
from src.sniffer import PacketSniffer

def run_demo():
    print("Starting Network Sniffer Demo...")
    print("This will capture 20 packets and save them to a JSON file.")
    
    config = Config(
        packet_count=20,
        timeout=30.0,
        output_format="json",
        output_file="demo_capture.json",
        verbose=True
    )
    
    sniffer = PacketSniffer(config)
    
    try:
        # Start the sniffer (this starts the daemon threads and returns immediately)
        sniffer.start()
        
        # Keep the main thread alive so the daemon threads can execute
        while sniffer._running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nDemo interrupted by user.")
        sniffer.stop()
        sys.exit(0)

if __name__ == "__main__":
    run_demo()
