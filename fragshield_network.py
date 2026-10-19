#!/usr/bin/env python3
"""FragShield real UDP demo: SECDED-protected UTF-8 messages over UDP.

Computer B: python3 fragshield_network.py receiver
Computer A: python3 fragshield_network.py web --html fragshield.html
"""
import argparse
import base64
import binascii
import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

UDP_DEFAULT_PORT = 5005
WEB_DEFAULT_PORT = 8765
MAX_MESSAGE_BYTES = 2000
MAX_DATAGRAM_BYTES = 60000

# Extended Hamming (13,8): positions 1,2,4,8 are Hamming parity bits;
# position 13 is overall even parity. Positions are numbered from 1.
DATA_POSITIONS = (3, 5, 6, 7, 9, 10, 11, 12)
PARITY_POSITIONS = (1, 2, 4, 8)

def encode_byte(value: int) -> int:
    bits = [0] * 14  # index 1..13
    for bit, pos in enumerate(DATA_POSITIONS):
        bits[pos] = (value >> bit) & 1
    for p in PARITY_POSITIONS:
        x = 0
        for pos in range(1, 13):
            if pos & p and pos != p:
                x ^= bits[pos]
        bits[p] = x
    bits[13] = 0
    for pos in range(1, 13):
        bits[13] ^= bits[pos]
    word = 0
    for pos in range(1, 14):
        word |= bits[pos] << (pos - 1)
    return word

def decode_word(word: int):
    bits = [0] + [(word >> (pos - 1)) & 1 for pos in range(1, 14)]
    syndrome = 0
    for p in PARITY_POSITIONS:
        x = 0
        for pos in range(1, 13):
            if pos & p:
                x ^= bits[pos]
        if x:
            syndrome |= p
    overall = 0
    for pos in range(1, 14):
        overall ^= bits[pos]
    corrected = False
    detected_double = False
    if syndrome and overall:
        if syndrome <= 12:
            bits[syndrome] ^= 1
            corrected = True
        else:
            detected_double = True
    elif not syndrome and overall:
        bits[13] ^= 1
        corrected = True
    elif syndrome and not overall:
        detected_double = True
    value = 0
    for bit, pos in enumerate(DATA_POSITIONS):
        value |= bits[pos] << bit
    return value, corrected, detected_double

def pack_message(message: str, flip: bool = False) -> dict:
    raw = message.encode('utf-8')
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError(f'Message is too long (maximum {MAX_MESSAGE_BYTES} UTF-8 bytes).')
    words = [encode_byte(b) for b in raw]
    if flip and words:
        # Flip one coded bit in the first codeword to demonstrate SECDED correction.
        words[0] ^= 1 << 4
    return {
        'protocol': 'FragShield-UDP-SECDED-v1',
        'payload_bytes': len(raw),
        'crc32': f'{binascii.crc32(raw) & 0xffffffff:08x}',
        'codewords': words,
        'injected_bit_flip': bool(flip and words),
    }

def decode_packet(packet: dict):
    if packet.get('protocol') != 'FragShield-UDP-SECDED-v1':
        raise ValueError('Unsupported FragShield packet protocol.')
    words = packet.get('codewords')
    count = packet.get('payload_bytes')
    if not isinstance(words, list) or not isinstance(count, int) or count < 0 or count > MAX_MESSAGE_BYTES or len(words) != count:
        raise ValueError('Malformed packet: codeword count does not match payload length.')
    output = bytearray()
    corrected = 0
    doubles = 0
    for w in words:
        if not isinstance(w, int) or w < 0 or w >= (1 << 13):
            raise ValueError('Malformed SECDED codeword.')
        value, did_correct, double = decode_word(w)
        output.append(value)
        corrected += int(did_correct)
        doubles += int(double)
    raw = bytes(output)
    expected = str(packet.get('crc32', '')).lower()
    actual = f'{binascii.crc32(raw) & 0xffffffff:08x}'
    crc_ok = expected == actual
    return raw.decode('utf-8', errors='replace'), corrected, doubles, crc_ok, len(raw), actual

def run_receiver(host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f'FragShield UDP receiver listening on {host}:{port}')
    print('Keep this terminal open. Press Ctrl+C to stop.\n')
    try:
        while True:
            data, addr = sock.recvfrom(MAX_DATAGRAM_BYTES)
            print(f'\n[{addr[0]}:{addr[1]}] received {len(data)} UDP datagram bytes')
            try:
                packet = json.loads(data.decode('utf-8'))
                message, corrected, doubles, crc_ok, nbytes, crc = decode_packet(packet)
                print(f'Message: {message}')
                print(f'Payload: {nbytes} bytes | SECDED corrected codewords: {corrected} | double-error detections: {doubles}')
                print(f'CRC32: {crc} | checksum: {"PASS" if crc_ok else "FAIL"}')
                if packet.get('injected_bit_flip'):
                    print('Test mode: sender injected one coded-bit flip before transmission.')
                if not crc_ok:
                    print('WARNING: payload checksum mismatch; the payload may be corrupted.')
            except Exception as exc:
                print(f'Invalid/unreadable FragShield datagram: {exc}')
    except KeyboardInterrupt:
        print('\nReceiver stopped.')
    finally:
        sock.close()

class BridgeHandler(BaseHTTPRequestHandler):
    html_path = Path('fragshield.html').resolve()
    def log_message(self, fmt, *args):
        print('[web] ' + fmt % args)
    def _json(self, status, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ('/', '/fragshield.html'):
            try: body = self.html_path.read_bytes()
            except OSError:
                self._json(500, {'ok': False, 'error': f'Cannot read HTML file: {self.html_path}'}); return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers(); self.wfile.write(body)
        elif path == '/health':
            self._json(200, {'ok': True, 'service': 'FragShield UDP bridge'})
        else: self._json(404, {'ok': False, 'error': 'Not found'})
    def do_POST(self):
        if urlparse(self.path).path != '/api/send':
            self._json(404, {'ok': False, 'error': 'Not found'}); return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 12000: raise ValueError('Invalid request size.')
            req = json.loads(self.rfile.read(length).decode('utf-8'))
            host = str(req.get('host', '')).strip()
            port = req.get('port', UDP_DEFAULT_PORT)
            message = req.get('message', '')
            flip = bool(req.get('flip', False))
            if not host or len(host) > 253: raise ValueError('Enter a valid receiver IP address or hostname.')
            if not isinstance(port, int) or not 1 <= port <= 65535: raise ValueError('UDP port must be from 1 to 65535.')
            if not isinstance(message, str) or not message: raise ValueError('Message cannot be empty.')
            packet = pack_message(message, flip)
            wire = json.dumps(packet, separators=(',', ':')).encode('utf-8')
            if len(wire) > MAX_DATAGRAM_BYTES: raise ValueError('Encoded datagram exceeds UDP size limit.')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sent = sock.sendto(wire, (host, port))
            self._json(200, {'ok': True, 'datagram_bytes': sent, 'payload_bytes': packet['payload_bytes'], 'codewords': len(packet['codewords']), 'flip_injected': packet['injected_bit_flip']})
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            self._json(400, {'ok': False, 'error': str(exc)})
        except OSError as exc:
            self._json(502, {'ok': False, 'error': f'Network send failed: {exc}'})

def run_web(host: str, port: int, html_path: Path):
    BridgeHandler.html_path = html_path.resolve()
    server = ThreadingHTTPServer((host, port), BridgeHandler)
    print(f'FragShield web bridge: http://{host}:{port}/')
    print(f'Serving HTML: {BridgeHandler.html_path}')
    print('Use this page on Computer A. UDP delivery is not guaranteed; check the receiver terminal.')
    print('This bridge binds to localhost only; do not expose it to the public internet. Ctrl+C to stop.')
    try: server.serve_forever()
    except KeyboardInterrupt: print('\nWeb bridge stopped.')
    finally: server.server_close()

def main():
    parser = argparse.ArgumentParser(description='FragShield real UDP network demo')
    sub = parser.add_subparsers(dest='mode', required=True)
    r = sub.add_parser('receiver', help='listen for UDP datagrams on this computer')
    r.add_argument('--host', default='0.0.0.0', help='bind address (default: all network interfaces)')
    r.add_argument('--port', type=int, default=UDP_DEFAULT_PORT)
    w = sub.add_parser('web', help='serve the website and local UDP sender bridge')
    w.add_argument('--host', default='127.0.0.1', help='web bridge bind address (keep localhost)')
    w.add_argument('--port', type=int, default=WEB_DEFAULT_PORT)
    w.add_argument('--html', default='fragshield.html', help='path to upgraded HTML file')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535: parser.error('port must be from 1 to 65535')
    if args.mode == 'receiver': run_receiver(args.host, args.port)
    else:
        p = Path(args.html)
        if not p.is_file(): parser.error(f'HTML file not found: {p}')
        run_web(args.host, args.port, p)
if __name__ == '__main__': main()
