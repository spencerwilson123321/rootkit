from constants import MENU_STRING

def printMenu():
    print("Welcome to the rootkit terminal!")
    print("Enter 'help' for a list of commands.")

def printHelp():
    print("Possible Commands:")
    print("start < keylogger | tbd > \t Starts the keylogger.")
    print("stop < keylogger | tbd > \t Stops the keylogger.")
    print("transfer < keylogger | tbd > \t Transfers the keylogger to this host.")
    print("help \t\t\t\t Displays this help screen.")
    print("clear \t\t\t\t Clears the terminal screen.")
    print("quit \t\t\t\t Disconnect and end the terminal session.")
