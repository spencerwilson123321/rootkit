"""
    This module contains code for using the shell interpreter which is used in the main.py file.
"""
from os import system

# Useful string constants
HELP = "help"
CLEAR = "clear"
EXIT = "exit"
WATCH = "watch"
START = "start"
STOP = "stop"
GET = "get"
KEYLOGGER = "keylogger"
LIST = "list"
WGET = "wget"

def clear_screen():
    system("clear")

def print_menu():
    clear_screen()
    print("Welcome to the Rootkit Command Shell!")
    print("Enter 'help' for a list of commands")

def print_help():
    print("Possible Commands:")
    print("help " + 4*"\t" + " Displays this help screen.")
    print("clear " + 4*"\t" + " Clears the terminal screen.")
    print("exit " + 4*"\t" + " End the terminal session.")
    print("keylogger [stop | start | get]" + 1*"\t" + " Stop, start, or get keylogger on rootkit.")
    print("watch [dirpath | filepath]" + 1*"\t" + " Watch the given directory or file for changes.")
    print("list dirpath" + 3*"\t" + " Attempts to list the contents of the given 'dirpath'.")
    print("wget url dirpath" + 2*"\t" + " Downloads the resource from 'url' to the given 'dirpath'.")
