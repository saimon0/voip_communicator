import pyaudio
import socket
import logic

# Pyaudio Initialization
chunk = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 10240


p = pyaudio.PyAudio()
stream = p.open(format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                output=True,
                frames_per_buffer=chunk)


# Socket Initialization
host = '192.168.1.64'
port = 12345
size = 4096
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
