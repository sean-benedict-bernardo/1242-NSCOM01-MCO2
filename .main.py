import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as tkmb
import socket
import threading
import random

import headers

APPNAME = "SKOIP"

SIP_PORT = 5060


def log_message(client: str, message: str):
    print(f"{client}: {message}")


class Client:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = socket.gethostbyname(socket.gethostname())
        self.sip_server = threading.Thread(target=self.listen_sip)
        self.sip_server.daemon = True  # ties the thread to the main thread

        self.active_call = None  # thread of active call, this will be used by sip server to send 486: Busy
        self.call = {}
        self.call["id"] = None  # call id of active call
        self.cseq = 1  # cseq of active call

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

        self.widgets["my_ip"] = tk.Label(self.master, text=self.ip, font=standard_font)
        self.widgets["my_ip"].grid(row=3, column=1, columnspan=4, sticky="w")

        self.widgets["recipient_ip_label"] = tk.Label(
            self.master, text="Recipient IP:", font=standard_font
        )
        self.widgets["recipient_ip_label"].grid(row=4, column=0, sticky="e")

        self.widgets["recipient_ip_entry"] = tk.Entry(self.master, font=standard_font)
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
            self.master, text="Transmit", font=standard_font, command=self.placeholder
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
            self.display_message("Please enter a valid IP address.")
            return
        
        # send an INVITE request
        # TODO:
        # self.send_invite((dest_ip, SIP_PORT))

        

    """
    SIP Methods
    """

    def send_invite(self, addr: tuple):
        """send an INVITE request"""

        def make_call_id():
            call_id = str(hex(random.randint(1000000000, 9999999999)))[2:]
            return call_id

        fields = headers.make_sip_headers(self.ip, addr[0], make_call_id(), self.cseq)
        self.cseq += 1

        body = headers.make_sdp_body()
        fields["Content-Type"] = "application/sdp"
        fields["Content-Length"] = len(body)

        message = headers.make_sip_request("INVITE", fields=fields)

        pass

    def send_sip(self, method: str, fields: dict, addr: tuple):
        # send a SIP request message
        message = headers.make_sip_request(method, fields=fields)
        self.socket.sendto(message, addr)
        log_message(addr, f"Sent SIP message: {message.decode()}")

    def handle_sip(self, message: bytes, addr: tuple):
        """Handle SIP messages."""

        parsed_message = headers.parse_sip_message(message)
        print(parsed_message)

        pass

    def listen_sip(self):
        # listen for SIP messages
        self.socket.bind((self.ip, SIP_PORT))
        # forces loop to check keep_threads every second
        self.socket.settimeout(1)

        try:
            while self.keep_threads:
                try:
                    data, addr = self.socket.recv(1024)
                    log_message(addr, f"Received SIP message: {data.decode()}")

                    if self.active_call:
                        # send 486: Busy Here
                        msg = headers.make_sip_response(486)

                        self.socket.sendto(msg, addr)
                        log_message(addr, f"Sent SIP message: {msg.decode()}")
                except socket.timeout:
                    continue
        finally:
            self.socket.close()


    """
    RTP Methods
    """


    """
    RTCP Methods
    """


if __name__ == "__main__":
    client = Client()
