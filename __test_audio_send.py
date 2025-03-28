import sys
import os
import socket
import random
from audio import AudioStream
from time import sleep

from headers import RTPPacket


class Sender:
    def __init__(self, filename):
        self.audio = AudioStream(filename)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dest_ip = socket.gethostbyname(socket.gethostname())
        self.dest_port = 6969

    def send(self):
        while True:
            frame, frame_num = self.audio.next_frame()
            if not frame:
                break

            # encode the frame into an RTP packet
            packet = RTPPacket()
            packet.encode(2, 0, 0, 1, frame_num, 0, 0, 0, frame)

            self.socket.sendto(packet.getpacket(), (self.dest_ip, self.dest_port))
            sleep_time = self.audio.FRAME_DURATION / 1000

            # if frame_num == 300:
            #     print("300th sent, testing delay")
            #     sleep(1)

            # if 300 <= frame_num and frame_num <= 400 and frame_num % 7 == 0:
            #     print(f"{frame_num}th sent, testing jitter")
            #     sleep(random.uniform(0.1, 0.5))

            if frame_num == 2000:
                print("2000th sent, exiting programm")
                break

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

    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        index = int(sys.argv[1])
        sender = Sender("files/" + audio_list[index % len(audio_list)])
    else:
        sender = Sender("files/" + audio_list[2])
    sender.send()
 