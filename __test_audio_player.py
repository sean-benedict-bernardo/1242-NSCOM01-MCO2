import socket
from audio import AudioStream, AudioPlayer
import headers
import time

class TestBench:

    def __init__(self, file_path: str):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = socket.gethostbyname(socket.gethostname())

        self.audio_stream = AudioStream(file_path)
        self.audio_player = AudioPlayer()

        self.num_timeout = 0

        self.listen_rtp()

    def listen_rtp(self):
        self.socket.bind((self.ip, 6969))
        self.socket.settimeout(3)

        current_frame = 0

        while True:
            try:
                data, addr = self.socket.recvfrom(4096)

                packet = headers.RTPPacket()

                packet.decode(data)
                payload = packet.getpayload()

                # ignore extraneous packets
                if not payload:
                    continue

                # ignore out of sequence frames
                if packet.seqnum() < current_frame:
                    continue

                self.audio_player.play_audio_packet(payload)
            except socket.timeout:
                # close audio player to save resources
                if self.audio_player.playing:
                    self.audio_player.stop()
                    print("Closing audio player")

                self.num_timeout += 1

                if self.num_timeout > 3:
                    break
                

    def close(self):
        self.audio_player.stop()


if __name__ == "__main__":
    file_path = "files/iris_theme.wav"

    audio_file = TestBench(file_path)
