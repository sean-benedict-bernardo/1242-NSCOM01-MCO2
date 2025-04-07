import pyaudio
import threading
import wave
import ffmpeg

from headers import RTPPacket

def generate_buffer_salt():
    """Generate a random salt for the buffer."""
    import random
    salt = hex(random.randint(0, 1000000))[2:].upper()
    return salt
    


class AudioStream:
    FRAME_DURATION = 20  # milliseconds

    def __init__(self, filename: str, ac: int = 1, ar: int = 44100):
        self.filename = filename
        self.BUFFERFILE = f"files/__buffer{generate_buffer_salt()}__.wav"

        try:
            # Payload type 10
            file_input = ffmpeg.input(self.filename)
            file_output = file_input.output(
                self.BUFFERFILE,
                format="wav",
                acodec="pcm_s16le",
                ac=ac,
                ar=ar,
            )
            file_output.run(quiet=True, overwrite_output=True)
        except ffmpeg.Error:
            raise IOError("Error converting audio to wav format")

        try:
            with wave.open(self.BUFFERFILE, "rb") as f:
                self.sample_rate = f.getframerate()
                self.channels = f.getnchannels()
                self.samples_per_frame = int(
                    self.sample_rate * (self.FRAME_DURATION / 1000)
                )
                self.frame_len = self.samples_per_frame * self.channels * 2
                self.file_data = f.readframes(f.getnframes())
                self.pointer = 0
        except Exception:
            raise IOError
        self.frame_num = 0

    def __del__(self):
        """Destructor to remove buffer file."""
        try:
            import os
            # os.remove(self.BUFFERFILE)
        except Exception:
            pass

    def next_frame(self) -> tuple[bytes, int]:
        """Get next frame."""

        frame = self.file_data[self.pointer : self.pointer + self.frame_len]

        # move pointer to next fram
        self.pointer += self.frame_len

        if frame:
            self.frame_num += 1
        return frame, self.frame_num - 1
    
    def all_frames(self) -> list[bytes]:
        """Get all frames."""
        frames = []
        while self.pointer < len(self.file_data):
            frame, _ = self.next_frame()
            frames.append(frame)
        return frames

    def get_frame_num(self):
        """Get frame number."""
        return self.frameNum
    

class AudioPlayer:
    def __init__(
        self, encoding: str = "PCM", channels: int = 1, rate: int = 44100
    ):
        self.audio = pyaudio.PyAudio()
        self.stream = None
        self.audio_queue = []  # our buffer
        self.playing = False
        self.lock = threading.Lock()  # to ensure that the audio queue is thread safe

        # encoding standards
        self.encoding = encoding
        self.channels = channels
        self.rate = rate

    def _play_from_queue(self):
        while self.playing:
            # we want to cache the last packet to be played
            # in buffer to increase smoothness of audio when packet loss occurs
            # trade off this is the last packet will effectively be ignored
            try:
                if len(self.audio_queue) > 1:
                    audio_data = self.audio_queue.pop(0)
                    self.stream.write(audio_data)
                    # print(len(self.audio_queue))  # DEBUG
                else:
                    continue
            except Exception:
                self.stop()

    def play_audio_packet(self, audio_data: bytes) -> int:
        """Plays audio and returns number of packets in buffer"""
        with self.lock:
            if not self.stream:
                self.stream = self.audio.open(
                    format=self.audio.get_format_from_width(2),
                    channels=self.channels,
                    rate=self.rate,
                    output=True,
                )

                print(self.audio.get_format_from_width(2), self.channels, self.rate)

                self.playing = True
                # start thread to play audio
                threading.Thread(target=self._play_from_queue, daemon=True).start()

            self.audio_queue.append(audio_data)
            return len(self.audio_queue)

    def stop(self):
        with self.lock:
            self.playing = False
            if self.stream:
                try:
                    self.stream.stop_stream()
                except Exception:
                    pass

                self.stream.close()
                self.stream = None
