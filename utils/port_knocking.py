"""

"""
from scapy.all import conf
import subprocess
conf.use_pcap = True
print(conf.use_pcap)

class PortKnockMonitor():

    def __init__(self):
        pass
    
    def sniff(self, device: str, filter: str):
        result = subprocess.run(["./sniffer", device, filter], capture_output=True)
        print(result.stdout.decode("utf-8").strip())

if __name__ == "__main__":
    monitor = PortKnockMonitor()
    monitor.sniff("enp2s0", "port 443")
