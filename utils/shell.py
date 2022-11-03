"""
    This module contains functions for displaying menus, clearing 
    the screen, and contains values which are useful for parsing commands.
"""
from os import system


"""
    Useful string constants used for parsing commands in the shell prompt.
"""
HELP = "help"
CLEAR = "clear"
EXIT = "exit"
WATCH = "watch"
START = "start"
STOP = "stop"
TRANSFER = "transfer"
KEYLOGGER = "keylogger"
LIST = "list"
WGET = "wget"
EXECUTE = "execute"
STEAL = "steal"


def clear_screen() -> None:
    """
        Clears the terminal screen.

        This function will only work on Linux systems.

        Parameters
        ----------
        None

        Returns
        -------
        None
    """
    system("clear")


def print_welcome() -> None:
    """
        Prints the shell welcome message.

        Clears the terminal screen and then prints the shell welcome message.

        Parameters
        ----------
        None

        Returns
        -------
        None
    """
    clear_screen()
    print("Welcome to the Rootkit Command Shell!")
    print("Enter 'help' for a list of commands")


def print_help() -> None:
    """
        Prints the shell help message.

        Lists all of the possible shell commands and their usage.

        Parameters
        ----------
        None

        Returns
        -------
        None
    """
    print("Possible Commands:")
    print("help " + 5*"\t" + " Displays this help screen.")
    print("clear " + 5*"\t" + " Clears the terminal screen.")
    print("exit " + 5*"\t" + " End the terminal session.")
    print("keylogger [stop | start | transfer]" + 1*"\t" + " Stop, start, or get keylogger on rootkit.")
    print("watch [dirpath | filepath]" + 2*"\t" + " Watch the given directory or file for changes.")
    print("execute [command]" + 2*"\t" + " Execute given command as root on victim, get output.")
    print("steal [filepath]" + 2*"\t" + " Transfer the given file from the victim to the contoller.")
