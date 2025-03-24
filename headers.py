"""
This file is responsible for the parsing and creating of headers for SIP, RTP, and RTSP packets.
"""

from time import time

RESPONSE_MESSAGES = {
    100: "Trying",
    180: "Ringing",
    200: "OK",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    415: "Unsupported Media Type",
    420: "Bad Extension",
    481: "Call Leg/Transaction Does Not Exist",
    486: "Busy Here",
    487: "Request Terminated",
    488: "Not Acceptable Here",
    500: "Internal Server Error",
    501: "Not Implemented",
    505: "Version Not Supported",
}

class SipPacket:
    """
    This class abstracts SIP packets and includes SDP body.
    """

    def __init__(self, is_response: bool, method: str | None, res_code: int | None, src_ip: str, dest_ip: str, rtp_port: int, call_id: str, cseq: int):
        self.is_response = is_response
        self.src_ip = src_ip
        self.dest_ip = dest_ip

        if is_response:
            self.response = res_code
        else:
            self.method = method

        self.call_id = call_id
        self.cseq = cseq

        self.fields = {
            "Via": "SIP/2.0/UDP",
            "From": f"<sip:{src_ip}>",
            "To": f"<sip:{dest_ip}>",
            "Call-ID": call_id,
            "CSeq": f"{cseq}",
            "Contact": f"<sip:{src_ip}>",
        }

        self.body = {
            "v": 0,
            "o": "- 0 0 IN IP4 " + src_ip,
            "s": "SKOIP Call",
            "c": "IN IP4",
            "t": "0 0",
            "m": f"audio {rtp_port} RTP/AVP 0",
        }

    def __init__(self, packet: bytes):
        extracted = self.decode(packet)

        self.src_ip = extracted["src_ip"]
        self.dest_ip = extracted["dest_ip"]
        self.method = extracted["method"]
        self.call_id = extracted["call_id"]
        self.cseq = extracted["cseq"]
        self.fields = extracted["fields"]
        self.body = extracted["body"]

    def encode(self):
        message = ""

        if self.is_response:
            message += "SIP/2.0 200 OK\r\n"


        pass

    def decode(self, byte_stream):
        """Decode the SIP packet."""
        msg_str = byte_stream.decode()
        headers, body = msg_str.split("\r\n\r\n")

        headers = headers.split("\r\n")
        body = body.split("\r\n")

        packet = {}

        # check first line if it is a request or response
        if "SIP/2.0" in lines[0]:
            is_response = True
            method = None

    def getmessage(self):
        """Return SIP message."""

        return self.message


class RtpPacket:
    """
    This class abstracts RTP packets. Implementation taken from
    [Lab#9] Programming Task: Streaming Video with RTSP and RTP.
    """

    HEADER_SIZE = 12

    header = bytearray(HEADER_SIZE)

    def __init__(self):
        pass

    def encode(
        self, version, padding, extension, cc, seqnum, marker, pt, ssrc, payload
    ):
        """Encode the RTP packet with header fields and payload."""
        timestamp = int(time())
        header = bytearray(self.HEADER_SIZE)

        #   0                   1                   2                   3
        #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #  |V=2|P|X|  CC   |M|     PT      |       sequence number         |
        #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #  |                           timestamp                           |
        #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #  |           synchronization source (SSRC) identifier            |
        #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        # evil bit level hacking

        header[0] = (
            (version << 6) & 0xFF  # 2 bits
            | (padding << 5) & 0xFF  # 1 bit
            | (extension << 4) & 0xFF  # 1 bit
            | cc & 0xFF  # 4 bits
        ) & 0xFF  # 8 bits

        header[1] = (marker << 7 | pt) & 0xFF  # 1 bit + 7 bits

        header[2] = (seqnum >> 8) & 0xFF
        header[3] = seqnum & 0xFF

        # timestamp
        header[4] = (timestamp >> 24) & 0xFF
        header[5] = (timestamp >> 16) & 0xFF
        header[6] = (timestamp >> 8) & 0xFF
        header[7] = timestamp & 0xFF

        header[8] = (ssrc >> 24) & 0xFF
        header[9] = (ssrc >> 16) & 0xFF
        header[10] = (ssrc >> 8) & 0xFF
        header[11] = ssrc & 0xFF

        self.header = header
        self.payload = payload

    def decode(self, byte_stream):
        """Decode the RTP packet."""
        self.header = bytearray(byte_stream[: self.HEADER_SIZE])
        self.payload = byte_stream[self.HEADER_SIZE :]

    def version(self):
        """Return RTP version."""
        return int(self.header[0] >> 6)

    def seqnum(self):
        """Return sequence (frame) number."""
        seq_num = self.header[2] << 8 | self.header[3]
        return int(seq_num)

    def timestamp(self):
        """Return timestamp."""
        timestamp = (
            self.header[4] << 24
            | self.header[5] << 16
            | self.header[6] << 8
            | self.header[7]
        )
        return int(timestamp)

    def payloadtype(self):
        """Return payload type."""
        pt = self.header[1] & 127
        return int(pt)

    def getpayload(self):
        """Return payload."""
        return self.payload

    def getpacket(self):
        """Return RTP packet."""
        return self.header + self.payload
