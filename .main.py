import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as tkmb
import socket, threading, random, os
import headers

import pyaudio
import numpy as np

from headers import SIPPacket, RTPPacket, RTCPPacket
from audio import AudioStream, AudioPlayer
import time

APPNAME = "SKOIP"
SIP_PACKET_SIZE = 1024
RTP_PACKET_SIZE = 8192


def log_message(client: tuple, protocol: str, message: str):
    print(f"===== {client[0]}:{client[1]} | {protocol} =====")
    print(f"{message}", end="\n\n")


def make_dir():
    if not os.path.exists("files"):
        print("Creating files directory, put .wav files in here.")
        os.makedirs("files")


class Client:
    IDLE = 0
    CALLING = 1
    IN_CALL = 2

    SIP_PORT = 5060

    def __init__(self, host_ip: str = socket.gethostbyname(socket.gethostname())):
        make_dir()

        # set up the client state
        self.current_state = self.IDLE

        # ip address
        self.ip = host_ip
        self.dest_ip = ""

        # sip socket
        self.sip_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sip_server = threading.Thread(target=self.listen_sip)
        self.sip_server.daemon = True  # ties the thread to the main thread

        # rtp socket
        self.rtp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_server = threading.Thread(target=self.listen_rtp)
        self.rtp_server.daemon = True  # ties the thread to the main thread

        # rtcp socket
        self.rtcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtcp_server = threading.Thread(target=self.listen_rtcp)
        self.rtcp_server.daemon = True  # ties the thread to the main thread

        # thread synchronization
        self.active_call = threading.Event()
        self.is_mic_on = threading.Event()
        self.is_playing = threading.Event()

        self.last_packet_time = time.time()
        self.last_rtcp_time = time.time()

        # rtcp stats
        self.rtcp_stats = {
            # sender report content
            "packets_sent": 0,
            "octets_sent": 0,
            "last_packet_time": 0,
            "packets_received": 0,
            # reader report content
            "packets_lost": 0,
            "fraction_lost": 0,
            "last_seqnum": 0,
            "interarrival_jitter": 0,
            "last_SR": 0,
        }

        self.received_stats = {
            # sender report content
            "packets_sent": 0,
            "octets_sent": 0,
            "last_packet_time": 0,
            "packets_received": 0,
            # reader report content
            "packets_lost": 0,
            "fraction_lost": 0,
            "last_seqnum": 0,
            "interarrival_jitter": 0,
            "last_SR": 0,
        }

        self.call = {}
        self.cseq = 1

        self.keep_threads = True

        # set master window
        self.master = tk.Tk()
        self.master.title(APPNAME)
        self.master.protocol("WM_DELETE_WINDOW", self.onclose)

        # start the SIP server
        try:
            self.sip_server.start()
        except Exception:
            self.keep_threads = False
            self.sip_server.join()
            self.master.destroy()

        # create the widgets
        self.make_widgets()

        self.widgets["my_ip"].config(text=f"{self.ip}:{self.SIP_PORT}")

        self.master.mainloop()

    def onclose(self):
        if self.current_state == self.IN_CALL:
            self.end_call()

        self.keep_threads = False
        print("Closing...")
        exit(0)

    def display_message(self, message):
        """display a message to the user"""
        tkmb.showinfo(title=APPNAME, message=message)

    def display_error(self, message):
        """display an error message to the user"""
        tkmb.showerror(title=APPNAME, message=message)

    def display_prompt(self, message) -> bool:
        """display a prompt to the user"""
        return tkmb.askyesno(title=APPNAME, message=message)

    def toggle_call_button(self):
        """toggle the call button"""
        if self.current_state != self.IN_CALL:
            self.widgets["conn_btn"]["state"] = "normal"
            self.widgets["term_btn"]["state"] = "disabled"
        else:
            self.widgets["conn_btn"]["state"] = "disabled"
            self.widgets["term_btn"]["state"] = "normal"

    def toggle_mic_button(self):
        """toggle the mic button"""
        if self.is_mic_on.is_set():
            self.widgets["mic_on_btn"]["state"] = "disabled"
            self.widgets["mic_off_btn"]["state"] = "normal"
            self.widgets["mic_status"].config(text="Mic Status: Open")
        else:
            self.widgets["mic_on_btn"]["state"] = "normal"
            self.widgets["mic_off_btn"]["state"] = "disabled"
            self.widgets["mic_status"].config(text="Mic Status: Closed")

    def toggle_button(self, button_name: str):
        """disable a button"""
        button = self.widgets[button_name]
        if button["state"] == "normal":
            button["state"] = "disabled"
        else:
            button["state"] = "normal"

    def placeholder(self):
        """placeholder function for buttons that have not been implemented yet"""
        pass

    def make_widgets(self):
        # create the widgets for the client

        standard_font = ("Calibri", 12)

        self.widgets = {}

        self.widgets["title_label"] = tk.Label(
            self.master, text="Skoip RTP Client", font=standard_font
        )
        self.widgets["title_label"].grid(row=0, column=0, columnspan=5)

        self.widgets["subtitle_label"] = tk.Label(
            self.master, text="by Bernardo and Strebel", font=standard_font
        )
        self.widgets["subtitle_label"].grid(row=1, column=0, columnspan=5)

        # horizontal separator
        self.widgets["separator_1"] = ttk.Separator(self.master, orient="horizontal")
        self.widgets["separator_1"].grid(row=2, column=0, columnspan=5, sticky="ew")

        self.widgets["my_ip_label"] = tk.Label(
            self.master, text="Your IP:", font=standard_font
        )
        self.widgets["my_ip_label"].grid(row=3, column=0, sticky="e")

        self.widgets["my_ip"] = tk.Label(
            self.master, text=f"{self.ip}:{self.SIP_PORT}", font=standard_font
        )
        self.widgets["my_ip"].grid(row=3, column=1, columnspan=4, sticky="w")

        self.widgets["recipient_ip_label"] = tk.Label(
            self.master, text="Recipient IP:", font=standard_font
        )
        self.widgets["recipient_ip_label"].grid(row=4, column=0, sticky="e")

        self.widgets["recipient_ip_entry"] = tk.Entry(self.master, font=standard_font)
        # DEBUG: set default IP address to localhost
        self.widgets["recipient_ip_entry"].insert(0, self.ip)

        self.widgets["recipient_ip_entry"].bind("<Return>", lambda: self.connect())

        self.widgets["recipient_ip_entry"].grid(
            row=4, column=1, columnspan=3, sticky="e"
        )

        # TODO: Update button and command depending on current state
        self.widgets["conn_btn"] = tk.Button(
            self.master, text="Connect", font=standard_font, command=self.connect
        )
        self.widgets["conn_btn"].grid(row=4, column=4)

        self.widgets["term_btn"] = tk.Button(
            self.master,
            text="End Call",
            font=standard_font,
            command=lambda: self.end_call(True),
        )
        self.widgets["term_btn"].grid(row=4, column=5)

        # horizontal separator
        self.widgets["separator_2"] = ttk.Separator(self.master, orient="horizontal")
        self.widgets["separator_2"].grid(row=5, column=0, columnspan=5, sticky="ew")

        self.widgets["audio_file_label"] = tk.Label(
            self.master, text="Enter audio filename\nto transmit:", font=standard_font
        )
        self.widgets["audio_file_label"].grid(row=6, column=0, sticky="w")

        self.widgets["audio_file_entry"] = tk.Entry(self.master, font=standard_font)
        self.widgets["audio_file_entry"].grid(row=6, column=1, columnspan=3, sticky="e")

        # TODO: set button to send audio file
        self.widgets["audio_send_btn"] = tk.Button(
            self.master, text="Transmit", font=standard_font, command=self.send_audio
        )
        self.widgets["audio_send_btn"].grid(row=6, column=4)

        # horizontal separator
        self.widgets["separator_3"] = ttk.Separator(self.master, orient="horizontal")
        self.widgets["separator_3"].grid(row=7, column=0, columnspan=5, sticky="ew")

        # TODO: set button to open mic
        self.widgets["mic_on_btn"] = tk.Button(
            self.master, text="Open Mic", font=standard_font, command=self.open_mic
        )
        self.widgets["mic_on_btn"].grid(row=8, column=0)

        self.widgets["mic_off_btn"] = tk.Button(
            self.master, text="Close Mic", font=standard_font, command=self.close_mic
        )
        self.widgets["mic_off_btn"].grid(row=8, column=1)

        self.widgets["mic_status"] = tk.Label(
            self.master, text="Mic Status: Closed", font=standard_font
        )
        self.widgets["mic_status"].grid(row=8, column=2, columnspan=2)

        self.toggle_call_button()

    """
    Auxiliary Methods Below
    """

    def is_same_ip(self) -> bool:
        """Verify if the IP address is the same as the local IP address."""
        return self.ip == self.dest_ip

    """
    Controller Methods Below
    """

    def connect(self):
        """Connect to the recipient IP."""
        dest_ip = self.widgets["recipient_ip_entry"].get()

        def is_valid_ip(ip: str) -> bool:
            """Verify if IP address is valid IPv4 address."""

            octets = ip.split(".")

            if len(octets) != 4:
                return False

            for octet in octets:
                if not octet.isdigit() or int(octet) < 0 or int(octet) > 255:
                    return False

            return True

        # verify if the IP is valid
        if not is_valid_ip(dest_ip):
            self.display_error("Please enter a valid IP address.")
            return

        self.dest_ip = dest_ip
        self.dest_sip_port = (
            self.SIP_PORT if not self.is_same_ip() else self.SIP_PORT + 2
        )

        # send an INVITE request
        self.send_invite((self.dest_ip, self.dest_sip_port))

    def accept_call(self, sip_packet: SIPPacket):
        """Accept an incoming call."""
        self.current_state = self.IN_CALL
        self.dest_ip = sip_packet.src_ip
        self.call["rtp_port"] = sip_packet.body["m"]["port"]
        self.call["rtcp_port"] = sip_packet.body["m"]["port"] + 1
        self.call["Call-ID"] = sip_packet.call_id
        self.call["Branch"] = sip_packet.branch

        # extract codec information from the SIP packet
        self.call["codec"] = {}

        self.call["codec"]["type"] = sip_packet.body["a"]["codec_type"]
        self.call["codec"]["rate"] = sip_packet.body["a"]["codec_rate"]
        self.call["codec"]["channels"] = sip_packet.body["a"]["codec_channels"]

        self.active_call.set()

        self.rtp_server = threading.Thread(
            target=self.listen_rtp,
            args=(
                self.call["rtp_port"],
                self.call["codec"]["type"],
                self.call["codec"]["channels"],
                self.call["codec"]["rate"],
            ),
            daemon=True,
        )

        self.rtcp_server = threading.Thread(
            target=self.listen_rtcp,
            args=(self.call["rtcp_port"],),
            daemon=True,
        )

        self.toggle_call_button()

        self.rtp_server.start()
        self.rtcp_server.start()

    def end_call(self, initiate=False):
        print("Ending call...")
        if self.current_state == self.IDLE:
            self.display_error("No active call.")
            return

        if initiate:
            bye = SIPPacket()
            self.cseq += 1
            bye.encode(
                is_response=False,
                method="BYE",
                src_ip=self.ip,
                dest_ip=self.dest_ip,
                call_id=self.call["Call-ID"],
                branch=self.call["Branch"],
                cseq=self.cseq,
            )

            self.sip_socket.sendto(bye.getpacket(), (self.dest_ip, self.dest_sip_port))
            log_message(
                (self.dest_ip, self.dest_sip_port), "SIP Sent", bye.getpacket().decode()
            )

        if self.is_playing.is_set():
            self.is_playing.clear()

        # clear event, enabling the servers to close
        self.active_call.clear()

        self.current_state = self.IDLE
        self.dest_ip = ""
        self.call = {}

        self.rtp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_server = threading.Thread(target=self.listen_rtp)

        self.toggle_call_button()

    def send_audio(self):
        # get file from entry box
        filename = self.widgets["audio_file_entry"].get()

        file_path = "files/" + filename

        if self.current_state != self.IN_CALL or self.dest_ip == "":
            self.display_error("No active call.")
            return

        # check if file exists
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            self.display_error("File not found.")
        else:
            # set is_playing state to stop listening while sending
            self.is_playing.clear()
            send_rtp_thread = threading.Thread(target=self.send_rtp, args=(file_path,))
            send_rtp_thread.start()

    def open_mic(self):
        """Open the microphone."""
        if self.current_state != self.IN_CALL:
            self.display_error("No active call.")
            return

        if self.is_mic_on.is_set():
            self.display_error("Microphone is already open.")
            return

        self.is_mic_on.set()
        self.toggle_mic_button()

        mic_thread = threading.Thread(target=self.send_mic_audio, daemon=True)
        mic_thread.start()

    def close_mic(self):
        """Close the microphone."""
        if not self.is_mic_on.is_set():
            self.display_error("Microphone is already closed.")
            return

        self.is_mic_on.clear()
        self.toggle_mic_button()

    """
    SIP Methods
    """

    def send_invite(self, addr: tuple):
        """send an INVITE request"""

        def make_call_id():
            self.call["Call-ID"] = str(hex(random.randint(1000000000, 9999999999)))[2:]

        def make_branch():
            cookie = "z9hG4bK"  # RFC 3261
            self.call["Branch"] = (
                cookie + str(hex(random.randint(1000000000, 9999999999)))[2:10]
            )

        def select_rtp_port():
            return 51125

            # cycle until a port is found
            while True:

                # select a random port between 49152 and 65535; though while RFC 3551 specifies that RTP ports can be from 1024 to 65535
                # we use ports 49152 to 65535 as defined in RFC 6334 to ensure that we don't conflict with other applications
                # RFC 3551 also defines that RTP ports should be even and the next port (+1) is used for RTCP
                candidate = random.randint(49152, 65535) & 0xFFFE  # even number

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    # check if candidate (RTP) and next port (RTCP) are free
                    if (
                        s.connect_ex(("localhost", candidate)) != 0
                        and s.connect_ex(("localhost", candidate + 1)) != 0
                    ):
                        return candidate

        # create a new call
        make_call_id()
        make_branch()

        self.call["rtp_port"] = select_rtp_port()
        self.call["rtcp_port"] = self.call["rtp_port"] + 1

        invite_msg = SIPPacket()

        invite_msg.encode(
            is_response=False,
            method="INVITE",
            src_ip=self.ip,
            dest_ip=addr[0],
            rtp_port=self.call["rtp_port"],
            call_id=self.call["Call-ID"],
            branch=self.call["Branch"],
            cseq=self.cseq,
            codec_type="LPCM",
            codec_rate=44100,
            codec_channels=1,
        )

        # log_message(addr, "SIP Sent", invite_msg.getpacket().decode())

        print(self.sip_socket)

        self.sip_socket.sendto(invite_msg.getpacket(), addr)

        self.current_state = self.CALLING
        self.toggle_call_button()

    def handle_sip(self, message: SIPPacket, addr: tuple):
        """Handle SIP messages."""

        log_message(addr, "SIP Received", message.getpacket().decode())

        if (
            self.current_state == self.IN_CALL
            and hasattr(message, "method")
            and message.method == "INVITE"
        ):
            # send 486: Busy Here
            response = SIPPacket()
            response.encode(
                is_response=True,
                res_code=486,
                src_ip=self.ip,
                dest_ip=addr[0],
                call_id=message.call_id,
                branch=message.branch,
                cseq=message.cseq,
            )

            self.sip_socket.sendto(response.getpacket(), addr)
            log_message(addr, "SIP Sent", response.getpacket().decode())
            return

        rtp_port = 0
        codec_type, codec_rate, codec_channels = "", 0, 0

        if hasattr(message, "body") and message.body["m"] and message.body["a"]:
            rtp_port = message.body["m"]["port"]
            codec_type = message.body["a"]["codec_type"]
            codec_rate = message.body["a"]["codec_rate"]
            codec_channels = message.body["a"]["codec_channels"]

        if not message.is_response:
            match message.method:
                case "INVITE":
                    # send 180: Ringing
                    response = SIPPacket()
                    response.encode(
                        is_response=True,
                        res_code=180,
                        src_ip=self.ip,
                        dest_ip=addr[0],
                        call_id=message.call_id,
                        branch=message.branch,
                        cseq=message.cseq,
                    )

                    self.sip_socket.sendto(response.getpacket(), addr)
                    log_message(addr, "SIP Sent", response.getpacket().decode())

                    # let user confirm if they want to accept the call
                    confirm_call = self.display_prompt(
                        f"Incoming call from {addr[0]}:{addr[1]}.\nDo you want to accept?"
                    )

                    response = SIPPacket()
                    if confirm_call:
                        response.encode(
                            is_response=True,
                            res_code=200,
                            src_ip=self.ip,
                            dest_ip=addr[0],
                            rtp_port=rtp_port,
                            call_id=message.call_id,
                            branch=message.branch,
                            cseq=message.cseq,
                            codec_type=codec_type,
                            codec_rate=codec_rate,
                            codec_channels=codec_channels,
                        )
                    else:
                        response.encode(
                            is_response=True,
                            res_code=200 if confirm_call else 603,
                            src_ip=self.ip,
                            dest_ip=addr[0],
                            rtp_port=rtp_port,
                            call_id=message.call_id,
                            branch=message.branch,
                        )

                    self.sip_socket.sendto(response.getpacket(), addr)
                    log_message(addr, "SIP Sent", response.getpacket().decode())

                case "ACK":
                    if (
                        self.current_state == self.CALLING
                        or self.current_state == self.IDLE
                    ):
                        self.display_message("Call Accepted. Starting RTP stream.")
                        self.accept_call(message)
                    elif self.current_state == self.IN_CALL:
                        self.display_error("Call already accepted.")

                case "BYE":
                    if self.current_state != self.IN_CALL:
                        self.display_error("No active call.")
                        return
                    else:
                        self.display_message("Terminating call.")

                    # send 200 OK
                    response = SIPPacket()
                    response.encode(
                        is_response=True,
                        res_code=200,
                        src_ip=self.ip,
                        dest_ip=addr[0],
                        call_id=message.call_id,
                        branch=message.branch,
                        cseq=message.cseq,
                    )

                    self.end_call()
                    self.sip_socket.sendto(response.getpacket(), addr)
                    self.cseq = 0
                    log_message(addr, "SIP Sent", response.getpacket().decode())
        else:
            match message.res_code:
                case 100:
                    self.current_state = self.CALLING
                    self.display_message("SIP message 100: Trying")
                case 180:
                    self.current_state = self.CALLING
                    self.display_message("SIP message 180: Ringing")
                case 200:
                    if self.current_state == self.CALLING:
                        self.display_message("Call Accepted. Starting RTP stream.")

                        # send ACK
                        ack = SIPPacket()
                        ack.encode(
                            is_response=False,
                            method="ACK",
                            src_ip=self.ip,
                            dest_ip=addr[0],
                            call_id=message.call_id,
                            branch=message.branch,
                            cseq=self.cseq,
                            rtp_port=message.body["m"]["port"],
                            codec_type=codec_type,
                            codec_rate=codec_rate,
                            codec_channels=codec_channels,
                        )

                        self.sip_socket.sendto(ack.getpacket(), addr)

                        log_message(addr, "SIP Sent", ack.getpacket().decode())

                        self.accept_call(message)
                    elif self.current_state == self.IN_CALL:
                        self.display_message("Ending call.")
                        self.end_call()
                case 486:
                    self.display_error("Recipient is busy.")
                    self.current_state = self.IDLE
                case 603:
                    self.display_error("Recipient declined.")
                    self.current_state = self.IDLE
            self.toggle_call_button()

    def listen_sip(self):
        # listen for SIP messages
        while True:
            try:
                self.sip_socket.bind((self.ip, self.SIP_PORT))
                break
            except OSError:
                print(
                    f"Port {self.SIP_PORT} is already in use. Trying {self.SIP_PORT + 2}..."
                )
                self.SIP_PORT += 2
        # forces loop to check keep_threads every second
        self.sip_socket.settimeout(1)

        try:
            while self.keep_threads:
                try:
                    data, addr = self.sip_socket.recvfrom(SIP_PACKET_SIZE)

                    # parse the SIP packet
                    extracted = SIPPacket()
                    extracted.decode(data)

                    # handle the SIP packet
                    self.handle_sip(extracted, addr)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    self.display_message("Client is unreachable")
                    self.current_state = self.IDLE
                    self.toggle_call_button()
        finally:
            self.sip_socket.close()

    """
    RTP Methods
    """

    def listen_rtp(self, port: int, encoding: str, channels: int, rate: int):
        """Listen for RTP packets."""

        self.rtp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_listen_socket.bind((self.ip, port))
        self.rtp_listen_socket.settimeout(1)
        current_frame = 0

        print(self.rtp_listen_socket)

        audio_player = AudioPlayer(encoding, channels, rate)

        while self.active_call.is_set():
            # check if more than 5 seconds since the last rtcp packet
            if time.time() - self.rtcp_stats["last_SR"] > 5:
                self.send_rtcp_rr()
                self.send_rtcp_sr()

            try:
                data, addr = self.rtp_listen_socket.recvfrom(RTP_PACKET_SIZE)

                packet = RTPPacket()

                packet.decode(data)
                payload = packet.getpayload()

                # ignore extraneous packets or packets from unrecognized sources
                if not payload:
                    continue

                # ignore out of sequence frames
                if packet.seqnum() < current_frame:
                    continue

                # detect packet loss
                if packet.seqnum() > current_frame + 1:
                    self.rtcp_stats["packets_lost"] += 1
                    self.rtcp_stats["fraction_lost"] += 1
                self.rtcp_stats["last_seqnum"] = packet.seqnum()
                self.rtcp_stats["packets_received"] += 1

                current_frame = packet.seqnum()

                self.last_packet_time = time.time()
                print("listen_rtp: ", self.last_packet_time, "PLAYING")

                audio_player.play_audio_packet(payload)
            except socket.timeout:
                print("listen_rtp: ", time.time())
                pass  # do nothing
            except ConnectionResetError:
                self.display_message("Client closed connection")
                self.keep_threads = False
                self.listen_rtp_socket.close()
                break
            except Exception as e:
                print(e)
        self.rtp_listen_socket.close()

    def send_rtp(self, filename: str):
        """Send RTP packets to the recipient."""

        if self.call["rtp_port"] == 0 or self.is_mic_on.is_set():
            return

        audio = None
        try:
            audio = AudioStream(
                filename, self.call["codec"]["channels"], self.call["codec"]["rate"]
            )
        except Exception as e:
            self.display_error(f"Error opening audio file: {e}")
            return

        self.is_playing.set()

        while self.is_playing.is_set():
            if self.call["rtp_port"] == 0:
                return

            frame, frame_num = audio.next_frame()
            if not frame:
                print(f"Finished sending {filename}.")
                self.is_playing.clear()
                break

            # encode the frame into an RTP packet
            packet = RTPPacket()
            packet.encode(2, 0, 0, 1, frame_num, 0, 11, 0, frame)

            self.rtp_send_socket.sendto(
                packet.getpacket(), (self.dest_ip, self.call["rtp_port"])
            )
            self.rtcp_stats["packets_sent"] += 1
            self.rtcp_stats["octets_sent"] += len(frame)
            sleep_time = audio.FRAME_DURATION / 1000

            # can we binary search the optimal rate for the audio? the answer is sorta,
            # ideally the sleep time should be 100% but considering network latency
            # this is the equilibrium between not hearing choppy audio and
            # not flooding the client buffer with packets
            time.sleep(sleep_time * 0.9745)

    def send_mic_audio(self):
        """Send audio from the microphone."""

        if self.current_state != self.IN_CALL:
            self.display_error("No active call.")
            return

        pa = pyaudio.PyAudio()
        mic_stream = pa.open(
            format=pyaudio.paInt16,
            channels=self.call["codec"]["channels"],
            rate=self.call["codec"]["rate"],
            input=True,
            frames_per_buffer=512,
        )

        seqnum = 0

        # check if the mic is loud enough to be sent

        def is_loud_enough(data):
            """Check if the audio data is loud enough."""
            threshold = 30
            audio_data = np.frombuffer(data, dtype=np.int16)
            volume = np.linalg.norm(audio_data) / len(audio_data)
            return volume > threshold

        # flushing mechanism to prevent choppy mic audio
        packet = []

        try:
            while self.is_mic_on.is_set():
                payload = mic_stream.read(512, exception_on_overflow=False)

                if not is_loud_enough(payload):
                    continue

                packet = RTPPacket()
                packet.encode(2, 0, 0, 1, seqnum, 0, 10, 0, payload)
                seqnum += 1

                self.rtp_send_socket.sendto(
                    packet.getpacket(), (self.dest_ip, self.call["rtp_port"])
                )
                self.last_packet_time = time.time()
                self.rtcp_stats["packets_sent"] += 1
        finally:
            mic_stream.stop_stream()
            mic_stream.close()
            pa.terminate()

    """
    RTCP Methods
    """

    def send_rtcp_sr(self):
        """Send RTCP SR packets."""
        rtcp = RTCPPacket(
            payload_type=200, report_count=1, length=0, ssrc=12435, version=2
        )
        rtcp.encode_sr(
            self.rtcp_stats["last_packet_time"],
            self.rtcp_stats["packets_sent"],
            self.rtcp_stats["octets_sent"],
        )
        self.rtcp_socket.sendto(
            rtcp.getpacket(), (self.dest_ip, self.call["rtcp_port"])
        )

        self.rtcp_stats["last_SR"] = int(time.time())

    def send_rtcp_rr(self):
        """Send RTCP RR packets."""
        rtcp = RTCPPacket(
            payload_type=201, report_count=1, length=0, ssrc=12435, version=2
        )

        # perform calculations for the RTCP stats

        if self.received_stats["packets_received"] == 0:
            self.rtcp_stats["fraction_lost"] = 0
        else:
            self.rtcp_stats["fraction_lost"] = (
                self.received_stats["packets_lost"]
                / self.received_stats["packets_received"]
            )
            self.rtcp_stats["fraction_lost"] = int(
                self.rtcp_stats["fraction_lost"] * 256
            )

        if self.rtcp_stats["last_SR"] == 0:
            dlsr = 0
        else:
            dlsr = int(time.time()) - self.rtcp_stats["last_SR"]

        rtcp.encode_rr(
            self.rtcp_stats["fraction_lost"],
            self.rtcp_stats["packets_received"],
            self.rtcp_stats["packets_lost"],
            self.rtcp_stats["interarrival_jitter"],
            self.rtcp_stats["last_SR"],
            dlsr,
        )

        self.rtcp_stats["fraction_lost"] = 0

        self.rtcp_socket.sendto(
            rtcp.getpacket(), (self.dest_ip, self.call["rtcp_port"])
        )
        self.last_rtcp_time = time.time()

    def listen_rtcp(self, port: int):
        self.rtcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtcp_socket.bind((self.ip, port))
        self.rtcp_socket.settimeout(1)

        while self.active_call.is_set():
            try:
                data, addr = self.rtcp_socket.recvfrom(RTP_PACKET_SIZE)
                packet = RTCPPacket(200)
                packet.decode(data)

                if packet.payload_type == 200:
                    # sender report
                    self.received_stats["last_SR"] = packet.last_sr
                    self.received_stats["packets_sent"] = packet.sender_packet_count
                    self.received_stats["octets_sent"] = packet.sender_octet_count
                elif packet.payload_type == 201:
                    # receiver report
                    self.received_stats["fraction_lost"] = packet.fraction_lost
                    self.received_stats["interarrival_jitter"] = (
                        packet.interarrival_jitter
                    )
                    self.received_stats["last_SR"] = packet.last_sr
                    self.received_stats["dlsr"] = packet.dlsr
                # print RTCP packet
                print(packet.getpacket().decode())
            except socket.timeout:
                continue
            except ConnectionResetError:
                self.display_message("Client closed connection")
                break
            except Exception as e:
                print(e)
        pass


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        host_ip = sys.argv[1]
    else:
        host_ip = socket.gethostbyname(socket.gethostname())

    client = Client(host_ip)
