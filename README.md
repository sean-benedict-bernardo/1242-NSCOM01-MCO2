# 1242-NSCOM01-MCO2

A Voice over IP (VoIP) client implementation in Python 3 using SIP, RTP, and audio handling in fulfillment of MCO2 for NSCOM01.

## Authors
- Sean Benedict Bernardo
- Adler Clarence Strebel

## Running the program
1. Clone the repository: `git clone https://github.com/yourusername/1242-NSCOM01-MCO2.git`
2. Install dependencies: `pip install PyAudio numpy`
3. Ensure you have a working microphone and speakers
4. Run the client: `python .main.py` or `python3 .main.py`
5. (Optional) Specify your IP address: `python .main.py 192.168.1.x`

## Features
- Implementation of Session Initiation Protocol (SIP) for call setup and teardown
- Real-time audio streaming using Real-time Transport Protocol (RTP)
- Support for live microphone input with voice activity detection and audio enhancement
- Playback of WAV audio files during calls
- Dynamic noise threshold calculation and recalibration
- End-to-end VoIP communication between two client instances

## Longer description

The SKOIP client uses a working VoIP solution with SIP for signaling and RTP for media transport. The application has a GUI constructed using Tkinter, where users can make calls, send audio files, and use their microphone for real-time voice communication.

The SIP protocol implementation handles INVITE, ACK, and BYE methods for call setup, confirmation, and teardown. It implements SIP headers like Call-ID, Branch, and CSeq for proper dialog management. Error handling includes responses for busy lines (486) and declined calls (603).

For media transport, the client uses RTP for real-time audio transmission. Audio packets are encoded with appropriate headers, including sequence numbers and timestamps, to ensure proper playback. The client can send and receive audio streams, with support for WAV files and live microphone input.

The application uses threading extensively to handle concurrent tasks such as listening for SIP messages, processing RTP streams, and capturing microphone input. Thread synchronization is achieved with events to ensure proper coordination between different components.

## How to use

1. Start two instances of the client on different machines (or on the same machine using different ports)
2. Enter the recipient's IP address in the "Recipient IP" field
3. Click "Connect" to initiate a call
4. When receiving a call, click "Yes" to accept or "No" to decline
5. During a call:
   - Enter a WAV filename in the audio file field and click "Transmit" to send an audio file
   - Click "Open Mic" to start transmitting voice from your microphone
   - Click "Close Mic" to stop microphone transmission
   - Click "End Call" to terminate the call

## Implementation Details

### SIP Protocol
The application implements the following SIP methods:
- INVITE: Initiates a call
- ACK: Confirms call establishment
- BYE: Terminates a call

And response codes:
- 100: Trying
- 180: Ringing
- 200: OK
- 486: Busy Here
- 603: Decline

### RTP Media Transport
- Dynamically selects available ports for RTP transmission
- Implements proper RTP packet formatting with headers
- Handles audio encoding/decoding for transmission
- Manages sequence numbers for packet ordering

### Voice Processing
- Voice Activity Detection (VAD) to eliminate silence transmission
- Dynamic noise threshold calculation and adjustment
- Audio enhancement for clearer voice quality
- Proper resource management for microphone access

## References
- [RFC 3261 (SIP)](https://tools.ietf.org/html/rfc3261)
- [RFC 3550 (RTP)](https://tools.ietf.org/html/rfc3550)
- [RFC 3551 (RTP Audio and Video)](https://tools.ietf.org/html/rfc3551)
- [RFC 8866 (SDP)](https://tools.ietf.org/html/rfc8866)
=======
## Installation and running the project:
1. Clone the repository `git clone `
2. Install PyAudio and ffmpeg-python with `pip install PyAudio ffmpeg-python numpy`
3. Download and install ffmpeg from [ffmpeg.org](https://ffmpeg.org/download.html). Ensure that it works in the command line by running `ffmpeg -version`.
4. Run the project with `python .main.py` or `python3 main.py`

## Project Constraints:
- This project is designed to work with two computers connected to the same local network.
- The two way functionality is broken. At minimum should work for one way communication.
- A known issue is that the audio quality can go down, this is a result of the threading as its implemented in python.


## Test Cases:
For the purposes of this project, the test cases will have two clients running on two different computers, clients A and B. The test cases will be run on the client side and will be tested for the following scenarios:

1. SIP HANDSHAKE (including INVITE, ACK, and relevant SDP)
Note: While 100 Trying is normally the first response to an INVITE, it is not implemented in this project, given the nature of the project being only peer to peer on a local network.
Client A (caller)
```
===== 192.168.5.143:5060 | SIP Sent =====
INVITE sip:192.168.5.143 SIP/2.0
Via: SIP/2.0/UDP 192.168.5.178;branch=z9hG4bK24be4bff
From: <sip:192.168.5.178>
To: <sip:192.168.5.143>
Call-ID: 100c10c7a
CSeq: 1
Contact: <sip:192.168.5.178>
Max-Forwards: 70
User-Agent: SKOIP/0.1
Content-Type: application/sdp
Content-Length: 211

v=0
o=- 0 0 IN IP4 192.168.5.178
s=SKOIP Call
c=IN IP4
t=0 0
m=audio 51125 RTP/AVP 11
a=rtpmap:11 LPCM/44100/1


===== 192.168.5.143:5060 | SIP Received =====
SIP/2.0 180 Ringing
Via: SIP/2.0/UDP 192.168.5.143;branch=z9hG4bK24be4bff
From: <sip:192.168.5.143>
To: <sip:192.168.5.178>
Call-ID: 100c10c7a
CSeq: 1
Contact: <sip:192.168.5.143>
Max-Forwards: 70
User-Agent: SKOIP/0.1


===== 192.168.5.143:5060 | SIP Received =====
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.168.5.143;branch=z9hG4bK24be4bff
From: <sip:192.168.5.143>
To: <sip:192.168.5.178>
Call-ID: 100c10c7a
CSeq: 1
Contact: <sip:192.168.5.143>
Max-Forwards: 70
User-Agent: SKOIP/0.1
Content-Type: application/sdp
Content-Length: 211

v=0
o=- 0 0 IN IP4 192.168.5.143
s=SKOIP Call
c=IN IP4
t=0 0
m=audio 51125 RTP/AVP 11
a=rtpmap:11 LPCM/44100/1


===== 192.168.5.143:5060 | SIP Sent =====
ACK sip:192.168.5.143 SIP/2.0
Via: SIP/2.0/UDP 192.168.5.178;branch=z9hG4bK24be4bff
From: <sip:192.168.5.178>
To: <sip:192.168.5.143>
Call-ID: 100c10c7a
CSeq: 1
Contact: <sip:192.168.5.178>
Max-Forwards: 70
User-Agent: SKOIP/0.1
Content-Type: application/sdp
Content-Length: 211

v=0
o=- 0 0 IN IP4 192.168.5.178
s=SKOIP Call
c=IN IP4
t=0 0
m=audio 51125 RTP/AVP 11
a=rtpmap:11 LPCM/44100/1
```

Client B (callee)
```
===== 192.168.5.178:5060 | SIP Received =====
INVITE sip:192.168.5.143 SIP/2.0
Via: SIP/2.0/UDP 192.168.5.178;branch=z9hG4bKeb9157e9
From: <sip:192.168.5.178>
To: <sip:192.168.5.143>
Call-ID: 1bb4484f5
CSeq: 1
Contact: <sip:192.168.5.178>
Max-Forwards: 70
User-Agent: SKOIP/0.1
Content-Type: application/sdp
Content-Length: 211

v=0
o=- 0 0 IN IP4 192.168.5.178
s=SKOIP Call
c=IN IP4
t=0 0
m=audio 51125 RTP/AVP 11
a=rtpmap:11 LPCM/44100/1


===== 192.168.5.178:5060 | SIP Sent =====
SIP/2.0 180 Ringing
Via: SIP/2.0/UDP 192.168.5.143;branch=z9hG4bKeb9157e9
From: <sip:192.168.5.143>
To: <sip:192.168.5.178>
Call-ID: 1bb4484f5
CSeq: 1
Contact: <sip:192.168.5.143>
Max-Forwards: 70
User-Agent: SKOIP/0.1


===== 192.168.5.178:5060 | SIP Sent =====
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.168.5.143;branch=z9hG4bKeb9157e9
From: <sip:192.168.5.143>
To: <sip:192.168.5.178>
Call-ID: 1bb4484f5
CSeq: 1
Contact: <sip:192.168.5.143>
Max-Forwards: 70
User-Agent: SKOIP/0.1
Content-Type: application/sdp
Content-Length: 211

v=0
o=- 0 0 IN IP4 192.168.5.143
s=SKOIP Call
c=IN IP4
t=0 0
m=audio 51125 RTP/AVP 11
a=rtpmap:11 LPCM/44100/1


===== 192.168.5.178:5060 | SIP Received =====
ACK sip:192.168.5.143 SIP/2.0
Via: SIP/2.0/UDP 192.168.5.178;branch=z9hG4bKeb9157e9
From: <sip:192.168.5.178>
To: <sip:192.168.5.143>
Call-ID: 1bb4484f5
CSeq: 1
Contact: <sip:192.168.5.178>
Max-Forwards: 70
User-Agent: SKOIP/0.1
Content-Type: application/sdp
Content-Length: 211

v=0
o=- 0 0 IN IP4 192.168.5.178
s=SKOIP Call
c=IN IP4
t=0 0
m=audio 51125 RTP/AVP 11
a=rtpmap:11 LPCM/44100/1
```

2. Teardown (BYE)
Client A (caller)
```
Ending call...
===== 192.168.5.143:5060 | SIP Sent =====
BYE sip:192.168.5.143 SIP/2.0
Via: SIP/2.0/UDP 192.168.5.178;branch=z9hG4bK1265406e
From: <sip:192.168.5.178>
To: <sip:192.168.5.143>
Call-ID: 1a71d14de
CSeq: 2
Contact: <sip:192.168.5.178>
Max-Forwards: 70
User-Agent: SKOIP/0.1


===== 192.168.5.143:5060 | SIP Received =====
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.168.5.143;branch=z9hG4bK1265406e
From: <sip:192.168.5.143>
To: <sip:192.168.5.178>
Call-ID: 1a71d14de
CSeq: 2
Contact: <sip:192.168.5.143>
Max-Forwards: 70
User-Agent: SKOIP/0.1
Content-Type: application/sdp
Content-Length: 203

v=0
o=- 0 0 IN IP4 192.168.5.143
s=SKOIP Call
c=IN IP4
t=0 0
m=audio 0 RTP/AVP 10
a=rtpmap:10 LPCM/0/0
```

Client B (callee)
```
===== 192.168.5.178:5060 | SIP Received =====
BYE sip:192.168.5.143 SIP/2.0
Via: SIP/2.0/UDP 192.168.5.178;branch=z9hG4bK1265406e
From: <sip:192.168.5.178>
To: <sip:192.168.5.143>
Call-ID: 1a71d14de
CSeq: 2
Contact: <sip:192.168.5.178>
Max-Forwards: 70
User-Agent: SKOIP/0.1


Ending call...
===== 192.168.5.178:5060 | SIP Sent =====
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.168.5.143;branch=z9hG4bK1265406e
From: <sip:192.168.5.143>
To: <sip:192.168.5.178>
Call-ID: 1a71d14de
CSeq: 2
Contact: <sip:192.168.5.143>
Max-Forwards: 70
User-Agent: SKOIP/0.1
Content-Type: application/sdp
Content-Length: 203
```

3. RTCP Sender Report (SR)
Note: Client A is the sender thus no terminal output is shown here

Client B (callee)
```
=== Sender Report ===
SSRC: 12435
NTP Timestamp: 3953050484
Last RTP Timestamp: 1744061684
Packet Count: 0
Octet Count: 0

=== Sender Report ===
SSRC: 12435
NTP Timestamp: 3953050494
Last RTP Timestamp: 1744061694
Packet Count: 114
Octet Count: 311290

=== Sender Report ===
SSRC: 12435
NTP Timestamp: 3953050504
Last RTP Timestamp: 1744061704
Packet Count: 418
Octet Count: 933882

=== Sender Report ===
SSRC: 12435
NTP Timestamp: 3953050534
Last RTP Timestamp: 1744061734
Packet Count: 1133
Octet Count: 2398202

=== Sender Report ===
SSRC: 12435
NTP Timestamp: 3953050544
Last RTP Timestamp: 1744061744
Packet Count: 1392
Octet Count: 2928634

=== Sender Report ===
SSRC: 12435
NTP Timestamp: 3953050554
Last RTP Timestamp: 1744061754
Packet Count: 1496
Octet Count: 3219444
```