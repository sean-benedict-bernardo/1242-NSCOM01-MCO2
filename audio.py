import pyaudio
import threading
import wave

from headers import RTPPacket


class AudioStream:
    FRAME_DURATION = 20  # milliseconds

    def __init__(self, filename: str):
        self.filename = filename
        try:
            with wave.open(filename, "rb") as f:
                self.sample_rate = f.getframerate()
                self.channels = f.getnchannels()
                self.samples_per_frame = int(
                    self.sample_rate * (self.FRAME_DURATION / 1000)
                )
                self.file_data = f.readframes(f.getnframes())
                self.pointer = 0
        except Exception:
            raise IOError
        self.frame_num = 0

    def next_frame(self) -> tuple[bytes, int]:
        """Get next frame."""
        frame = self.file_data[
            self.pointer : self.pointer + self.samples_per_frame * self.channels * 2
        ]

        self.pointer += self.samples_per_frame * self.channels * 2

        if frame:
            self.frame_num += 1
        return frame, self.frame_num - 1

    def get_frame_num(self):
        """Get frame number."""
        return self.frameNum


class AudioPackets:
    def __init__(self, filename: str, seq_num: int):
        self.data = AudioStream(filename)
        self.seq_num = seq_num

    def construct_packet(self) -> bytes:
        """Construct RTP packet."""
        version = 2
        padding = 0
        extension = 0
        cc = 0
        marker = 0
        pt = 0  # 0 for PCMU
        data, seqnum = self.data.next_frame()
        ssrc = 0

        rtp_packet = RTPPacket()
        rtp_packet.encode(
            version, padding, extension, cc, seqnum, marker, pt, ssrc, data
        )

        return rtp_packet.get_packet()


class AudioPlayer:
    def __init__(self, ):
        self.audio = pyaudio.PyAudio()
        self.stream = None
        self.audio_queue = []  # our buffer
        self.playing = False
        self.lock = threading.Lock()

    def _play_from_queue(self):
        while self.playing:
            # we want to cache the least three packets in the 
            # to be played buffer to increase smoothness of audio
            # trade off this is the last 3 packets will effectively be ignored
            if len(self.audio_queue) > 3:
                audio_data = self.audio_queue.pop(0)
                self.stream.write(audio_data)
                print(len(self.audio_queue)) # DEBUG
            else:
                continue

    def play_audio_packet(self, audio_data: bytes) -> int:
        """Plays audio and returns number of packets in buffer"""
        with self.lock:
            if not self.stream:
                self.stream = self.audio.open(
                    format=self.audio.get_format_from_width(2),
                    channels=2,
                    rate=44100,
                    output=True,
                )
                self.playing = True
                threading.Thread(target=self._play_from_queue, daemon=True).start()

            self.audio_queue.append(audio_data)
            return len(self.audio_queue)

    def stop(self):
        with self.lock:
            self.playing = False
            if self.stream:
                self.stream.stop_stream()
                self.stream.close()
                self.stream = None
