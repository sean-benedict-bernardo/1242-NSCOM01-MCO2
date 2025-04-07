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
        codec_pt: int = 11,
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

        if method and method in ("INVITE", "ACK") or is_response and res_code == 200:
            # SDP body
            self.fields["Content-Type"] = "application/sdp"
            self.body = {
                "v": "0",
                "o": "- 0 0 IN IP4 " + src_ip,
                "s": "SKOIP Call",
                "c": "IN IP4",
                "t": "0 0",
                # "m": f"audio {rtp_port} RTP/AVP {codec_pt}",
                "m": {
                    "media": "audio",
                    "port": rtp_port,
                    "proto": "RTP/AVP",
                    "fmt": codec_pt,
                },
                # f"rtpmap:0 {codec_type}/{codec_rate}/{codec_channels}"
                "a": {
                    "codec_pt": codec_pt,
                    "codec_type": codec_type,
                    "codec_rate": int(codec_rate),
                    "codec_channels": int(codec_channels),
                },
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
                        codec_pt = val.split(":")[1].split(" ")[0]
                        codec_info = val.split(" ")[1].split("/")
                        self.body[key] = {
                            "codec_pt": int(codec_pt),
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
                    val = f"{val['media']} {val['port']} {val['proto']} {val['fmt']}"
                elif key == "a" and isinstance(val, dict):
                    # "rtpmap": f"{codec_pt} {codec_type}/{codec_rate}/{codec_channels}",
                    val = f"rtpmap:{val['codec_pt']} {val['codec_type']}/{val['codec_rate']}/{val['codec_channels']}"

                message += f"{key}={val}\r\n"

        return message.encode()


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


def ntp_timestamp() -> int:
    """Get NTP timestamp."""
    # See RFC 1305 for NTP timestamp format
    import time

    ntp_time = int(time.time() + 2208988800)  # RFC 868
    return ntp_time


class RTCPPacket:
    """This class abstracts RTCP packets, specfically Sender Report (SR) and Receiver Report (RR)."""

    HEADER_SIZE = 8

    header = bytearray(HEADER_SIZE)

    def __init__(
        self,
        payload_type: int = 0,
        report_count: int = 0,
        length: int = 0,
        ssrc: int = 0,
        version: int = 2,
    ):
        # decode mode
        if payload_type == 0:
            return

        self.version = version
        self.padding = 0
        self.extension = 0
        self.report_count = report_count
        self.payload_type = payload_type
        self.ssrc = ssrc

        # RTCP common header format
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |V=2|P|    RC   |   PT=200      |             length            |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                  SSRC of sender (SSRC_1)                      | found in both SR and RR
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        self.header[0] = (
            (self.version << 6) | (self.padding << 5) | (self.report_count & 0x1F)
        )

        if payload_type == 200:
            length = 24 // 4 - 1  # length in 32-bit words
        elif payload_type == 201:
            length = 32 // 4 - 1  # length in 32-bit words

        # this is either 200 or 201 for RTCP SR or RR
        self.header[1] = self.payload_type & 0xFF
        self.header[2] = (length >> 8) & 0xFF
        self.header[3] = length & 0xFF

        # SSRC of sender (SSRC_1)
        self.header[4:8] = ssrc.to_bytes(4, byteorder="big")

    def _encode_report_block(
        self,
        fraction_lost: int = 0,
        total_lost: int = 0,
        extended_highest_seq_num: int = 0,
        interarrival_jitter: int = 0,
        last_sr: int = 0,
        dlsr: int = 0,
    ) -> bytes:
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
        # |                 SSRC_1 (SSRC of first source)                 |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # | fraction lost |       cumulative number of packets lost       |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |           extended highest sequence number received           |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                      interarrival jitter                      |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                         last SR (LSR)                         |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                   delay since last SR (DLSR)                  |
        # +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
        report = bytearray(24)

        self.ssrc = int(self.ssrc)
        self.fraction_lost = int(fraction_lost)
        self.cumulative_packets_lost = int(total_lost)
        self.extended_highest_seq_num = int(extended_highest_seq_num)
        self.interarrival_jitter = int(interarrival_jitter)
        self.last_sr = last_sr
        self.dlsr = dlsr

        # SSRC_1
        report[0:4] = int(self.ssrc).to_bytes(4, byteorder="big")
        # fraction lost
        report[4] = fraction_lost & 0xFF
        # cumulative number of packets lost
        report[5:8] = total_lost.to_bytes(2, byteorder="big")
        # extended highest sequence number received
        report[8:12] = extended_highest_seq_num.to_bytes(2, byteorder="big")
        # interarrival jitter
        report[12:16] = interarrival_jitter.to_bytes(4, byteorder="big")
        # last SR (LSR)
        report[16:20] = last_sr.to_bytes(4, byteorder="big")
        # delay since last SR (DLSR)
        report[20:24] = dlsr.to_bytes(4, byteorder="big")

        return bytes(report)

    def _decode_report_block(self, payload: bytes) -> None:
        """Decode the RTCP report block."""
        print(payload)

        # decode SSRC_1
        self.ssrc = int.from_bytes(payload[0:4], byteorder="big")
        # fraction lost
        self.fraction_lost = payload[4] & 0xFF
        # cumulative number of packets lost
        self.cumulative_packets_lost = int.from_bytes(payload[5:8], byteorder="big")
        # extended highest sequence number received
        self.extended_highest_seq_num = int.from_bytes(payload[8:12], byteorder="big")
        # interarrival jitter
        self.interarrival_jitter = int.from_bytes(payload[12:16], byteorder="big")
        # last SR (LSR)
        self.last_sr = int.from_bytes(payload[16:20], byteorder="big")
        # delay since last SR (DLSR)
        self.dlsr = int.from_bytes(payload[20:24], byteorder="big")

    def encode_sr(
        self, last_packet_time: int, packet_count: int, octet_count: int
    ) -> None:
        """Encode the RTCP Sender Report packet."""

        # After common SR/RR headers
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |              NTP timestamp, most significant word             |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |             NTP timestamp, least significant word             |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                         RTP timestamp                         |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                     sender's packet count                     |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                      sender's octet count                     |
        # +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

        self.payload = bytearray(20)

        # Encode NTP timestamp in payload
        self.payload[0:4] = ntp_timestamp().to_bytes(4, byteorder="big")
        self.payload[4:8] = int(0).to_bytes(4, byteorder="big")  # RTP timestamp

        self.payload[8:12] = last_packet_time.to_bytes(4, byteorder="big")
        self.payload[12:16] = packet_count.to_bytes(4, byteorder="big")
        self.payload[16:20] = octet_count.to_bytes(4, byteorder="big")

    def encode_rr(
        self,
        fraction_lost: int = 0,
        total_lost: int = 0,
        extended_highest_seq_num: int = 0,
        interarrival_jitter: int = 0,
        last_sr: int = 0,
        dlsr: int = 0,
    ):
        """Encode the RTCP packet."""

        self.payload_type = 201  # RTCP RR
        self.payload = self._encode_report_block(
            fraction_lost,
            total_lost,
            extended_highest_seq_num,
            interarrival_jitter,
            last_sr,
            dlsr,
        )

    def _decode_header(self, header_payload: bytes) -> None:
        self.version = header_payload[0] >> 6
        self.padding = (header_payload[0] >> 5) & 1
        self.extension = (header_payload[0] >> 4) & 1
        self.report_count = header_payload[0] & 0x1F
        self.payload_type = header_payload[1] & 0xFF
        self.length = (header_payload[2] << 8) | header_payload[3]
        self.ssrc = int.from_bytes(header_payload[4:8], byteorder="big")

    def decode_sender_info(self, payload: bytes) -> None:
        """Decode the RTCP Sender Report packet."""
        # decode NTP timestamp in payload
        self.ntp_timestamp = int.from_bytes(payload[0:4], byteorder="big")
        self.rtp_timestamp = int.from_bytes(payload[8:12], byteorder="big")
        self.sender_packet_count = int.from_bytes(payload[12:16], byteorder="big")
        self.sender_octet_count = int.from_bytes(payload[16:20], byteorder="big")

    def decode(self, byte_stream: bytes) -> None:
        """Decode the RTCP packet."""
        self.header = bytearray(byte_stream[: self.HEADER_SIZE])
        self.payload = byte_stream[self.HEADER_SIZE :]

        self._decode_header(self.header)

        if self.payload_type == 200:
            self.decode_sender_info(self.payload)
        elif self.payload_type == 201:
            self._decode_report_block(self.payload)

    def getpacket(self):
        """Return RTCP packet."""
        # update header length
        self.header[2] = ((len(self.payload) + self.HEADER_SIZE) // 4 - 1) >> 8
        self.header[3] = ((len(self.payload) + self.HEADER_SIZE) // 4 - 1) & 0xFF

        return self.header + self.payload


if __name__ == "__main__":
    rtp = RTPPacket()
    rtp.encode(2, 0, 0, 1, 0, 0, 10, 0, b"hello world")

    rtcp_test = RTCPPacket(
        payload_type=201, report_count=0, length=0, ssrc=0, version=2
    )
    rtcp_test.encode_rr(
        fraction_lost=0,
        total_lost=0,
        extended_highest_seq_num=0,
        interarrival_jitter=0,
        last_sr=0,
        dlsr=0,
    )

    print(rtcp_test.getpacket())
    rtcp_test_decode = RTCPPacket(payload_type=201)
    rtcp_test_decode.decode(rtcp_test.getpacket())

    # print(rtcp_test.getpacket())

"""
if __name__ == "__main__":
    # Test SIP packet encoding and decoding. 
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
        branch="1234",
        codec_type="LPCM",
        codec_pt=10,
        codec_rate=44100,
        codec_channels=2,
    )

    # print packet
    print(sip_inv.getpacket().decode())

    # sip_ack = SIPPacket()
    # sip_ack.encode(
    #     is_response=True,
    #     method="ACK",
    #     res_code=200,
    #     src_ip="1.1.1.1",
    #     dest_ip="0.0.0.0",
    #     rtp_port=1235,
    #     call_id="1234",
    #     cseq=1,
    # )

    sip_inv2 = SIPPacket()
    sip_inv2.decode(sip_inv.getpacket())

    print("=====================")

    print(sip_inv2.getpacket().decode())

    # decode_test = SIPPacket(packet=sip_trying.getpacket())

    # print(decode_test.getmessage())
"""
