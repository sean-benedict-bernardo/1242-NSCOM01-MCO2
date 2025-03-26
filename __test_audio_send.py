import socket
from audio import AudioStream
from time import sleep

from headers import RTPPacket


class Sender:
    def __init__(self):
        self.audio = AudioStream("files/dang-zerRog.wav")
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
            
            # can we binary search the optimal rate for the audio? the answer is sorta,
            # ideally the sleep time should be 100 but considering network latency
            # this is the equilibrium between not hearing choppy audio and
            # not flooding the client buffer with packets


            if frame_num == 300:
                print("300th sent, testing delay")
                sleep(1)

            if frame_num == 500:
                print("500th sent, exiting programm")
                break


            sleep(sleep_time * 0.975)


if __name__ == "__main__":
    sender = Sender()
    sender.send()
