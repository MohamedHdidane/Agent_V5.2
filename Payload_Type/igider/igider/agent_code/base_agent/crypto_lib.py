class igider:
    def encrypt(self, data):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        if not self.agent_config["enc_key"]["value"] == "none" and len(data) > 0:
            key = base64.b64decode(self.agent_config["enc_key"]["enc_key"])
            iv = os.urandom(12)  # GCM uses 12-byte nonce
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend)
            encryptor = cipher.encryptor()
            ct = encryptor.update(data) + encryptor.finalize()
            tag = encryptor.tag  # GCM authentication tag
            return iv + ct + tag
        else:
            return data

    def decrypt(self, data):
        if not self.agent_config["enc_key"]["value"] == "none":
            if len(data) > 0:
                backend = default_backend()
                key = base64.b64decode(self.agent_config["enc_key"]["dec_key"])
                uuid = data[:36]
                iv = data[36:48]  # 12 bytes for GCM nonce
                ct = data[48:-16]  # Everything except last 16 bytes (tag)
                received_tag = data[-16:]  # GCM tag is 16 bytes
                
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, received_tag), backend)
                decryptor = cipher.decryptor()
                try:
                    pt = decryptor.update(ct) + decryptor.finalize()
                    return (uuid + pt).decode()
                except Exception:  # Authentication failure
                    return ""
            else:
                return ""
        else:
            return data.decode()