import json
import struct

from .utils import canonical_json

HEADER_SIZE = 4


def recv_exact(sock, size):
    chunks = []
    received = 0

    while received < size:
        chunk = sock.recv(size - received)
        if not chunk:
            raise ConnectionError("Ligacao terminada inesperadamente.")
        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def send_bytes(sock, payload):
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_bytes(sock):
    header = recv_exact(sock, HEADER_SIZE)
    size = struct.unpack("!I", header)[0]
    return recv_exact(sock, size)


def send_json(sock, message):
    send_bytes(sock, canonical_json(message))


def recv_json(sock):
    return json.loads(recv_bytes(sock).decode("utf-8"))

