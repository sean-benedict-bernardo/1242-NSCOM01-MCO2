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
    603: "Decline",
}


class ResponseClass:
    PROVISIONAL = 1
    SUCCESS = 2
    REDIRECTION = 3
    CLIENT_ERROR = 4
    SERVER_ERROR = 5
    GLOBAL_FAILURE = 6

    @staticmethod
    def get_response_class(response_code: int) -> int:
        """Get response class."""
        return response_code // 100

    @staticmethod
    def print_message(response_code: int) -> str:
        """Print response message."""
        return RESPONSE_MESSAGES.get(response_code, "Unknown Response Code")


class SIPPacket:
    """
    This class abstracts SIP packets and includes SDP body.
    """

    def __getitem__(self, item: str) -> str | None:
        """Get header field."""
        return self.fields.get(item, None)

    def encode(
        self,
        is_response: bool = False,
        method: str | None = None,
        res_code: int | None = None,
        src_ip: str = 0,
        dest_ip: str = 0,
        rtp_port: int = 0,
        call_id: str = "",
        branch: str = "",
        cseq: int = 0,
        codec_type: str = "LPCM",
        codec_pt: int = 10,
        codec_rate: int = 0,
        codec_channels: int = 0,
    ) -> bytes:

        self.is_response = is_response
        self.src_ip = src_ip
        self.dest_ip = dest_ip

        if self.is_response:
            self.res_code = res_code
        else:
            self.method = str(method).upper()

        self.call_id = call_id
        self.cseq = cseq

        self.fields = {
            "Via": f"SIP/2.0/UDP {src_ip};branch={branch}",
            "From": f"<sip:{src_ip}>",
            "To": f"<sip:{dest_ip}>",
            "Call-ID": str(call_id),
            "CSeq": f"{cseq}",
            "Contact": f"<sip:{src_ip}>",
            "Max-Forwards": "70",
            "User-Agent": "SKOIP/0.1",
        }

        if method and method == "INVITE" or is_response and res_code == 200:
            # SDP body
            self.fields["Content-Type"] = "application/sdp"
            self.body = {
                "v": "0",
                "o": "- 0 0 IN IP4 " + src_ip,
                "s": "SKOIP Call",
                "c": "IN IP4",
                "t": "0 0",
                "m": f"audio {rtp_port} RTP/AVP {codec_pt}",
                "a": f"rtpmap:0 {codec_type}/{codec_rate}/{codec_channels}",
            }
            # add length of
            self.fields["Content-Length"] = str(
                sum(len(key) + len(str(val)) + 2 for key, val in self.body.items())
            )

    def decode(self, packet: bytes) -> None:
        """Decode the SIP packet."""

        msg_str = packet.decode().split("\r\n\r\n")

        headers, body = "", ""

        headers = msg_str[0].split("\r\n")
        if len(msg_str) == 2:
            body = msg_str[1].strip("\r\n").split("\r\n")

        self.fields = {}

        # check first line if request line is a request or response
        req_res_line = headers.pop(0).split(" ")
        self.is_response = req_res_line[0] == "SIP/2.0"

        if req_res_line[0] == "SIP/2.0":
            self.res_code = int(req_res_line[1])
        else:
            self.method = req_res_line[0]

        # decode headers
        for header in headers:
            header = header.split(": ")

            if len(header) < 2:
                continue

            key, val = header[0], header[1]
            self.fields[key] = val

            sip_prefix = "sip:"
            match key:
                case "CSeq":
                    self.cseq = int(val)
                case "Call-ID":
                    self.call_id = val
                case "From":
                    self.src_ip = val.split(sip_prefix)[1].split(">")[0]
                case "To":
                    self.dest_ip = val.split(sip_prefix)[1].split(">")[0]
                case "Via":
                    self.branch = val.split(";")[1].split("=")[1]
                case "Contact":
                    self.src_ip = val.split(sip_prefix)[1].split(">")[0]

        # decode body
        if body:
            self.body = {}
            for line in body:
                line = line.split("=")
                if len(line) < 2:
                    continue
                key, val = line[0], line[1]

                if key == "m":
                    val = val.split(" ")
                    self.body[key] = {
                        "media": val[0],
                        "port": int(val[1]),
                        "proto": val[2],
                        "fmt": val[3],
                    }
                elif key == "a":
                    if "rtpmap" in val:
                        codec_info = val.split(" ")[1].split("/")
                        self.body[key] = {
                            "codec_type": codec_info[0],
                            "codec_rate": int(codec_info[1]),
                            "codec_channels": int(codec_info[2]),
                        }
                    else:
                        self.body[key] = val.split(":")[1]
                else:
                    self.body[key] = val

    def getpacket(self):
        """Return SIP packet."""
        message = ""

        if self.is_response:
            message += f"SIP/2.0 {self.res_code} {RESPONSE_MESSAGES[self.res_code]}\r\n"
        else:
            message += f"{self.method} sip:{self.dest_ip} SIP/2.0\r\n"

        # encode fields
        for key, val in self.fields.items():
            message += f"{key}: {val}\r\n"

        if hasattr(self, "body") and self.body:
            message += "\r\n"
            for key, val in self.body.items():
                if key == "m" and isinstance(val, dict):
                    val = f"{val['media']} {val['port']} {val['proto']} {' '.join(val['fmt'])}"
                elif key == "Via" and isinstance(val, dict):
                    val = f"{val['protocol']};branch={val['branch']}"

                message += f"{key}={val}\r\n"

        return message.encode()


if __name__ == "__main__":
    """Test SIP packet encoding and decoding."""
    sip_inv = SIPPacket()
    sip_inv.encode(
        is_response=False,
        method="INVITE",
        res_code=None,
        src_ip="0.0.0.0",
        dest_ip="1.1.1.1",
        rtp_port=1235,
        call_id="1234",
        cseq=1,
    )

    sip_ack = SIPPacket()
    sip_ack.encode(
        is_response=True,
        method="ACK",
        res_code=200,
        src_ip="1.1.1.1",
        dest_ip="0.0.0.0",
        rtp_port=1235,
        call_id="1234",
        cseq=1,

    )

    sip_trying = SIPPacket()
    sip_trying.decode(sip_inv.getpacket())

    # print(vars(sip_trying))

    # accessing the body of the SIP packet

    # print headers

    for key, val in sip_trying.fields.items():
        print(f"{key} := {val}")

    # print body

    for key, val in sip_trying.body.items():
        print(f"{key} := {val}")

    # decode_test = SIPPacket(packet=sip_trying.getpacket())

    # print(decode_test.getmessage())


class RTPPacket:
    """
    This class abstracts RTP packets. Implementation taken from
    [Lab#9] Programming Task: Streaming Video with RTSP and RTP.
    """

    HEADER_SIZE = 12

    header = bytearray(HEADER_SIZE)

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


RTCP_PAYLOAD_TYPES = {
    200: "RTCP Sender Report",
    201: "RTCP Reader Report",
}


class RTCPPacket:
    HEADER_SIZE = 4

    header = bytearray(HEADER_SIZE)

    def encode(self, PT, reports: list):
        """Encode the RTCP packet."""

        #   0                   1                   2                   3
        #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |V=2|P|    RC   |   PT=200      |             length            |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        self.version = 2
        self.padding = 0
        self.extension = 0
        self.report_count = len(reports)
        self.ssrc = 0
        self.payload_type = PT

        self.header[0] = (
            (self.version << 6) | (self.padding << 5) | (self.report_count & 0x1F)
        )

        self.header[1] = self.payload_type & 0xFF
        self.header[2] = 0
        self.header[3] = 0
        # length is in 32 bit words
