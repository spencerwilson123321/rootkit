
def printMenu():
    print("Welcome to the rootkit terminal!")
    print("Enter 'help' for a list of commands.")

def printHelp():
    print("Possible Commands:")
    print("start keylogger " + 3*"\t" + " Starts the keylogger.")
    print("stop keylogger " + 4*"\t" + " Stops the keylogger.")
    print("transfer keylogger " + 3*"\t" + " Transfers the keylogger to this host.")
    print("watch < directory path | file path > \t Watches the given file or directory for changes.")
    print("help " + 5*"\t" + " Displays this help screen.")
    print("clear " + 5*"\t" + " Clears the terminal screen.")
    print("quit " + 5*"\t" + " Disconnect and end the terminal session.")
