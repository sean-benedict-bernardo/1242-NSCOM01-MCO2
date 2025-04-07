import socket
from audio import AudioStream, AudioPlayer
import headers
import time
import threading


class TestBench:

    def __init__(self, file_path: str):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = socket.gethostbyname(socket.gethostname())

        self.audio_stream = AudioStream(file_path)
        self.audio_player = AudioPlayer()

        self.num_timeout = 0

        self.rtp_thread = threading.Thread(target=self.listen_rtp, daemon=True)
        self.last_packet_time = time.time()

        self.rtp_thread.start()
        self.rtp_thread.join()

    def listen_rtp(self):
        self.socket.bind((self.ip, 6969))
        self.socket.settimeout(1)

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

                self.last_packet_time = time.time()

                if self.num_timeout != 0:
                    self.num_timeout = 0
                self.audio_player.play_audio_packet(payload)
            except socket.timeout:
                # close audio player to save resources
                if self.audio_player.playing:
                    self.audio_player.stop()

                self.num_timeout += 1

                if time.time() - self.last_packet_time > 10:
                    break

    def close(self):
        self.audio_player.stop()


if __name__ == "__main__":
    file_path = "files/iris_theme.wav"

    audio_file = TestBench(file_path)
