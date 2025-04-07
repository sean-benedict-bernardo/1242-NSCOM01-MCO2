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