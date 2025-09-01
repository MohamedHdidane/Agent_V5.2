from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
import base64
import hmac

class igider:
    def encrypt(self, data):
        if len(data) == 0:
            return b""
        key = base64.b64decode(self.agent_config["agent_to_server_key"])
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        h = hmac.HMAC(key, hashes.SHA256(), default_backend())
        h.update(iv + ciphertext)
        tag = h.finalize()
        return iv + ciphertext + tag

    def decrypt(self, data):
        if len(data) < 52:
            return b""
        key = base64.b64decode(self.agent_config["server_to_agent_key"])
        iv = data[:16]
        ciphertext = data[16:-32]
        received_tag = data[-32:]
        h = hmac.HMAC(key, hashes.SHA256(), default_backend())
        h.update(iv + ciphertext)
        if not hmac.compare_digest(h.finalize(), received_tag):
            return b""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()
