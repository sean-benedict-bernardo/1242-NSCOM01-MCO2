import sys
import os
import socket
import random
from audio import AudioStream
from time import sleep
import threading

from headers import RTPPacket
import tkinter as tk


class Sender:
    IDLE = 0
    PLAYING = 1
    PAUSED = 2

    def __init__(self, filename):
        self.filename = filename
        self.audio = AudioStream(filename)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dest_ip = socket.gethostbyname(socket.gethostname())
        self.dest_port = 6969

        self.pause_event = threading.Event()
        self.pause_event.set()  # Initially not paused

        self.audio_thread = threading.Thread(target=self.send, daemon=True)

        self.state = self.IDLE

        self.gui()

    def gui(self):
        """GUI for the sender."""

        def play():
            if self.state == self.PLAYING:
                return

            print("Play button clicked")

            if self.state == self.PAUSED:
                print("Resuming playback")
                self.state = self.PLAYING
                self.pause_event.set()
            else:
                print("Starting playback")
                self.state = self.PLAYING

                self.audio = AudioStream(self.filename)
                self.audio_thread = threading.Thread(target=self.send, daemon=True)
                self.audio_thread.start()

        def pause():
            if self.state == self.PAUSED:
                return
            
            if self.state != self.PLAYING:
                print("Cannot pause, not playing")
                return

            print("Pause button clicked")
            self.state = self.PAUSED
            self.pause_event.clear()

        def stop():
            if self.state == self.IDLE:
                return

            print("Stop button clicked")
            # Add logic to stop sending audio
            self.state = self.IDLE
            # reinitialize the audio stream
            self.audio = AudioStream(self.filename)

        root = tk.Tk()
        root.title("Audio Sender")

        play_button = tk.Button(root, text="Play", command=play)
        play_button.pack(pady=10)

        pause_button = tk.Button(root, text="Pause", command=pause)
        pause_button.pack(pady=10)

        stop_button = tk.Button(root, text="Stop", command=stop)
        stop_button.pack(pady=10)

        root.mainloop()

    def send(self):
        while True:
            if self.state == self.PAUSED:
                self.pause_event.wait()

            if self.state == self.IDLE:
                return

            frame, frame_num = self.audio.next_frame()
            if not frame:
                print("No more frames or paused")
                self.state = self.IDLE
                break

            # encode the frame into an RTP packet
            packet = RTPPacket()
            packet.encode(2, 0, 0, 1, frame_num, 0, 10, 0, frame)

            self.socket.sendto(packet.getpacket(), (self.dest_ip, self.dest_port))
            sleep_time = self.audio.FRAME_DURATION / 1000

            # can we binary search the optimal rate for the audio? the answer is sorta,
            # ideally the sleep time should be 100% but considering network latency
            # this is the equilibrium between not hearing choppy audio and
            # not flooding the client buffer with packets
            sleep(sleep_time * 0.9745)


if __name__ == "__main__":
    audio_list = []

    # List all .wav files in the current directory and subdirectories
    for root, dirs, files in os.walk("."):
        for file in files:
            if file.endswith(".wav"):
                audio_list.append(file)

    # check if sys arg is an integer

    sender = Sender("files/iris_theme.wav")

    # if len(sys.argv) > 1 and sys.argv[1].isdigit():
    #     index = int(sys.argv[1])
    #     sender = Sender("files/" + audio_list[index % len(audio_list)])
    # else:
    #     sender = Sender("files/" + audio_list[2])
