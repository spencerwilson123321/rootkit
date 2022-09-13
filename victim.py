from socket import socket, AF_INET, SOCK_STREAM

address = ("10.65.98.206", 8000)
backlog = 5
buffsize = 1024

listening_socket = socket(AF_INET, SOCK_STREAM)
listening_socket.bind(address)
listening_socket.listen(backlog)
command_socket, addr = listening_socket.accept()

print("Connection from: ", addr)
while True:
    msg_bytes = command_socket.recv(buffsize)
    if not msg_bytes:
        break
    command = msg_bytes.decode("utf-8")
    if command == "stop":
        print("received stop command!")
    if command == "start":
        print("received start command!")
    if command == "quit":
        print("received quit command!")
        print("quitting...")
        command_socket.close()
        break
listening_socket.close()
