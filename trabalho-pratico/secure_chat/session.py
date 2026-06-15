import json

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .framing import recv_bytes, send_bytes


class ProtocolError(Exception):
    pass


class SecureChannel:
    def __init__(self, sock, send_key, recv_key, send_prefix, recv_prefix):
        self.sock = sock
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_prefix = send_prefix
        self.recv_prefix = recv_prefix
        self.send_counter = 0
        self.recv_counter = 0

    def _build_nonce(self, prefix, counter):
        return prefix + counter.to_bytes(8, "big")

    def send(self, message):
        plaintext = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
        nonce = self._build_nonce(self.send_prefix, self.send_counter)
        ciphertext = AESGCM(self.send_key).encrypt(nonce, plaintext, None)
        self.send_counter += 1
        send_bytes(self.sock, ciphertext)

    def recv(self):
        ciphertext = recv_bytes(self.sock)
        nonce = self._build_nonce(self.recv_prefix, self.recv_counter)
        try:
            plaintext = AESGCM(self.recv_key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ProtocolError("Falha de autenticacao no canal seguro.") from exc
        self.recv_counter += 1
        return json.loads(plaintext.decode("utf-8"))
