"""

"""
import subprocess

class PortKnockMonitor():

    def __init__(self):
        pass
    
    def sniff(self, filter: str, device: str):
        result = subprocess.run(["./sniffer", "enp2s0"], capture_output=True)
        print(result.stdout.decode("utf-8"))

if __name__ == "__main__":
    monitor = PortKnockMonitor()
    monitor.sniff("port 443", "enp2s0")
