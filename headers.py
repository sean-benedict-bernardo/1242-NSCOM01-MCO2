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


class SIPPacket:
    """
    This class abstracts SIP packets and includes SDP body.
    """

    _hasinit = False

    def __init__(
        self,
        is_response: bool = False,
        method: str | None = None,
        res_code: int | None = None,
        src_ip: str = 0,
        dest_ip: str = 0,
        rtp_port: int = 0,
        call_id: str = "",
        cseq: int = 0,
        packet: bytes = b"",
    ):
        if packet != b"":
            self._frompacket(packet)
            return

        print("Creating new SIP packet")

        self.is_response = is_response
        self.src_ip = src_ip
        self.dest_ip = dest_ip

        if is_response:
            self.response = res_code
        else:
            self.method = method.upper()

        self.call_id = call_id
        self.cseq = cseq

        self.fields = {
            "Via": "SIP/2.0/UDP " + src_ip,
            "From": f"<sip:{src_ip}>",
            "To": f"<sip:{dest_ip}>",
            "Call-ID": call_id,
            "CSeq": f"{cseq}",
            "Contact": f"<sip:{src_ip}>",
        }

        if method and method in ("INVITE", "ACK"):
            self.body = {
                "v": 0,
                "o": "- 0 0 IN IP4 " + src_ip,
                "s": "SKOIP Call",
                "c": "IN IP4",
                "t": "0 0",
                "m": f"audio {rtp_port} RTP/AVP 0",
            }

    def _frompacket(self, packet: bytes):
        extracted = self.decode(packet)

        self.is_response = extracted["is_response"]
        if self.is_response:
            self.response = extracted["method"]
        else:
            self.method = extracted["method"]

        self.src_ip = extracted["From"].strip("<sip:>")
        self.dest_ip = extracted["To"].strip("<sip:>")
        self.call_id = extracted["Call-ID"]
        self.cseq = int(extracted["CSeq"].split(" ")[0])

        self.fields = {
            "Via": extracted["Via"],
            "From": extracted["From"],
            "To": extracted["To"],
            "Call-ID": extracted["Call-ID"],
            "CSeq": extracted["CSeq"],
            "Contact": extracted["Contact"],
        }

        if "body" in extracted:
            self.body = extracted.get("body", {})

    def encode(self) -> bytes:
        message = ""

        if self.is_response:
            message += f"SIP/2.0 {self.response} {RESPONSE_MESSAGES[self.response]}\r\n"
        else:
            message += f"{self.method} sip:{self.dest_ip} SIP/2.0\r\n"

        # encode fields
        for key, val in self.fields.items():
            message += f"{key}: {val}\r\n"

        if hasattr(self, "body") and self.body:
            message += "\r\n"
            for key, val in self.body.items():
                message += f"{key}={val}\r\n"

        return message.encode()

    def decode(self, byte_stream):
        """Decode the SIP packet."""
        msg_str = byte_stream.decode().split("\r\n\r\n")

        headers, body = "", ""

        headers = msg_str[0].split("\r\n")
        if len(msg_str) == 2:
            body = msg_str[1].strip("\r\n").split("\r\n")

        decoded_msg = {}

        # check first line if it is a request or response
        req_res_line = headers.pop(0).split(" ")

        if req_res_line[0] == "SIP/2.0":
            decoded_msg["is_response"] = True
            decoded_msg["method"] = int(req_res_line[1])
        else:
            decoded_msg["is_response"] = False
            decoded_msg["method"] = req_res_line[0]

        # decode headers
        for header in headers:
            header = header.split(": ")

            if len(header) < 2:
                continue

            key, val = header[0], header[1]
            decoded_msg[key] = val

        # decode body
        if body:
            decoded_msg["body"] = {}
            for line in body:
                line = line.split("=")
                if len(line) < 2:
                    continue
                key, val = line[0], line[1]
                decoded_msg["body"][key] = val

        return decoded_msg

    def getmessage(self):
        """Return SIP message."""

        return self.encode().decode()


if __name__ == "__main__":
    """Test SIP packet encoding and decoding."""
    sip_inv = SIPPacket(
        is_response=False,
        method="INVITE",
        res_code=None,
        src_ip="0.0.0.0",
        dest_ip="1.1.1.1",
        rtp_port=1234,
        call_id="1234",
        cseq=1,
    )

    sip_ack = SIPPacket(
        is_response=True,
        method="ACK",
        res_code=200,
        src_ip="1.1.1.1",
        dest_ip="0.0.0.0",
        rtp_port=1234,
        call_id="1234",
        cseq=1,
    )

    sip_trying = SIPPacket(
        is_response=True,
        method="TRYING",
        res_code=100,
        src_ip="1.1.1.1",
        dest_ip="0.0.0.0",
        rtp_port=1234,
        call_id="1234",
        cseq=1,
    )

    print(sip_inv.encode().decode())
    print(sip_ack.encode().decode())

    decode_test = SIPPacket(packet=sip_trying.encode())

    print(decode_test.getmessage())


class RTPPacket:
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
