import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as tkmb
import socket, threading, random, os
import headers

from headers import SIPPacket, RTPPacket
from audio import AudioStream, AudioPlayer
import time

APPNAME = "SKOIP"
SIP_PACKET_SIZE = 1024


def log_message(client: tuple, protocol: str, message: str):
    print(f"===== {client[0]}:{client[1]} | {protocol} =====")
    print(f"{message}")


def make_dir():
    if not os.path.exists("files"):
        print("Creating files directory, put .wav files in here.")
        os.makedirs("files")


class Client:
    IDLE = 0
    CALLING = 1
    IN_CALL = 2

    SIP_PORT = 5060

    def __init__(self):
        make_dir()

        # set up the client state
        self.current_state = self.IDLE

        # ip address
        self.ip = socket.gethostbyname(socket.gethostname())
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
        self.rtcp_server = threading.Thread(target=self.listen_rtp)
        self.rtcp_server.daemon = True  # ties the thread to the main thread

        # threading locks
        self.stop_send = threading.Event()
        self.stop_send.set()

        self.last_packet_time = time.time()
        self.last_rtcp_time = time.time()

        self.active_call = False
        self.call = {}
        self.cseq = 1

        self.keep_threads = True

        # set master window
        self.master = tk.Tk()
        self.master.title(APPNAME)
        self.master.protocol("WM_DELETE_WINDOW", self.onclose)

        # create the widgets
        self.make_widgets()

        # start the SIP server
        try:
            self.sip_server.start()
        except Exception:
            self.keep_threads = False
            self.sip_server.join()
            self.master.destroy

        self.master.mainloop()

    def onclose(self):
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

        self.widgets["recipient_ip_entry"].bind("<Return>", lambda e: self.connect())

        self.widgets["recipient_ip_entry"].grid(
            row=4, column=1, columnspan=3, sticky="e"
        )

        # TODO: Update button and command depending on current state
        self.widgets["conn_term_btn"] = tk.Button(
            self.master, text="Connect", font=standard_font, command=self.connect
        )
        self.widgets["conn_term_btn"].grid(row=4, column=4)

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
        self.widgets["mic_btn"] = tk.Button(
            self.master, text="Open Mic", font=standard_font, command=self.placeholder
        )
        self.widgets["mic_btn"].grid(row=8, column=0)

        self.widgets["mic_status"] = tk.Label(
            self.master, text="Mic Status: Closed", font=standard_font
        )
        self.widgets["mic_status"].grid(row=8, column=1)

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
        self.active_call = True
        self.dest_ip = sip_packet.src_ip
        self.call["rtp_port"] = sip_packet.body["m"]["port"]
        self.call["rtcp_port"] = sip_packet.body["m"]["port"] + 1
        self.call["Call-ID"] = sip_packet.call_id
        self.call["Branch"] = sip_packet.branch

        print(self.call)

        self.rtp_server = threading.Thread(
            target=self.listen_rtp, args=(self.call["rtp_port"],), daemon=True
        )
        self.rtp_server.start()

    def send_audio(self):
        # get file from entry box
        filename = self.widgets["audio_file_entry"].get()

        file_path = "files/" + filename

        if self.active_call == False or self.dest_ip == "":
            self.display_error("No active call.")
            return

        # check if file exists
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            self.display_error("File not found.")
        else:
            self.stop_send.clear()
            send_rtp_thread = threading.Thread(target=self.send_rtp, args=(file_path,))
            send_rtp_thread.start()
            send_rtp_thread.join()

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

        # disable the connect button
        self.toggle_button("conn_term_btn")

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
        )

        print(invite_msg.getpacket().decode())

        self.sip_socket.sendto(invite_msg.getpacket(), addr)
        # instruct listen sip to wait for a response

    def handle_sip(self, message: SIPPacket, addr: tuple):
        """Handle SIP messages."""

        log_message(addr, "SIP Received", message.getpacket().decode())

        if self.active_call:
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
                    response.encode(
                        is_response=True,
                        res_code=200 if confirm_call else 603,
                        src_ip=self.ip,
                        dest_ip=addr[0],
                        rtp_port=message.body["m"]["port"],
                        call_id=message.call_id,
                        branch=message.branch,
                        cseq=message.cseq,
                    )

                    self.sip_socket.sendto(response.getpacket(), addr)
                    log_message(addr, "SIP Sent", response.getpacket().decode())

                    if confirm_call:
                        self.toggle_button("conn_term_btn")
                        self.active_call = True
                        self.accept_call(message)

                case "BYE":
                    if not self.active_call:
                        return

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

                    self.sip_socket.sendto(response.getpacket(), addr)
                    log_message(addr, "SIP Sent", response.getpacket().decode())

                    self.active_call = False
                    self.toggle_button("conn_term_btn")
        else:
            match message.res_code:
                case 100:
                    self.display_message("SIP message 100: Trying")
                case 180:
                    self.display_message("SIP message 180: Ringing")
                case 200:
                    self.display_message("Call Accepted. Starting RTP stream.")
                    self.accept_call(message)
                case 486:
                    self.display_error("Recipient is busy.")
                    self.toggle_button("conn_term_btn")
                case 603:
                    self.display_error("Recipient declined.")
                    self.toggle_button("conn_term_btn")

    def listen_sip(self):
        # listen for SIP messages
        while True:
            try:
                self.sip_socket.bind((self.ip, self.SIP_PORT))
                self.widgets["my_ip"].config(text=f"{self.ip}:{self.SIP_PORT}")
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
                    self.toggle_button("conn_term_btn")
        finally:
            self.sip_socket.close()

    """
    RTP Methods
    """

    def listen_rtp(self, port: int):
        """Listen for RTP packets."""

        self.rtp_listen_socket.bind((self.ip, port))
        self.rtp_listen_socket.settimeout(1)

        current_frame = 0

        audio_player = AudioPlayer()

        while self.keep_threads:
            try:
                data, addr = self.rtp_listen_socket.recvfrom(4096)

                packet = RTPPacket()

                packet.decode(data)
                payload = packet.getpayload()

                # ignore extraneous packets or packets from unrecognized sources
                if not payload:
                    continue

                # ignore out of sequence frames
                if packet.seqnum() < current_frame:
                    continue

                # if not is_from_rtp_port(packet):
                #     continue

                self.last_packet_time = time.time()

                audio_player.play_audio_packet(payload)
            except socket.timeout:
                pass  # do nothing
            except ConnectionResetError:
                self.display_message("Client closed connection")
                self.keep_threads = False
                self.sip_socket.close()
                break
            except Exception as e:
                print(e)
        pass

    def send_rtp(self, filename: str):
        """Send RTP packets to the recipient."""

        if self.call["rtp_port"] == 0:
            return

        audio = None
        try:
            audio = AudioStream(filename)
        except Exception as e:
            self.display_error(f"Error opening audio file: {e}")
            return

        # Load all frames into memory
        all_frames = audio.all_frames()
        all_packets = []
        if not all_frames:
            self.display_error("No frames to send.")
            return
        else:
            for frame, index in all_frames:
                packet = RTPPacket()
                packet.encode(2, 0, 0, 1, index, 0, 10, 0, frame)
                all_packets.append(packet.getpacket())

        # send the packets
        while True:
            if len(all_packets) == 0:
                break
            packet = all_packets.pop(0)

            if not packet:
                print("No more frames or paused")
                break

            self.rtp_send_socket.sendto(
                packet.getpacket(), (self.dest_ip, self.call["rtp_port"])
            )

            sleep_time = audio.FRAME_DURATION / 1000

            # can we binary search the optimal rate for the audio? the answer is sorta,
            # ideally the sleep time should be 100% but considering network latency
            # this is the equilibrium between not hearing choppy audio and
            # not flooding the client buffer with packets
            time.sleep(sleep_time * 0.9745)
        """
        while True:
            if self.call["rtp_port"] == 0:
                return

            frame, frame_num = audio.next_frame()
            if not frame:
                print("No more frames or paused")
                break

            print(frame_num)

            # encode the frame into an RTP packet
            packet = RTPPacket()
            packet.encode(2, 0, 0, 1, frame_num, 0, 10, 0, frame)

            self.rtp_send_socket.sendto(
                packet.getpacket(), (self.dest_ip, self.call["rtp_port"])
            )
            sleep_time = audio.FRAME_DURATION / 1000

            # can we binary search the optimal rate for the audio? the answer is sorta,
            # ideally the sleep time should be 100% but considering network latency
            # this is the equilibrium between not hearing choppy audio and
            # not flooding the client buffer with packets
            time.sleep(sleep_time * 0.9745)
        """

    """
    RTCP Methods
    """

    def listen_rtcp(self):
        pass


if __name__ == "__main__":
    client = Client()
