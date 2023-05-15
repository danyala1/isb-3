import logging
import os

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

settings = {'initial_file': 'file\initial_file.txt', 'encrypted_file': 'file\encrypted_file.txt', 'decrypted_file': 'file\decrypted_file.txt',
            'symmetric_key': 'key\symmetric_key.txt', 'public_key': 'key\public\key.pem', 'secret_key': 'key\secret\key.pem'}

logging.basicConfig(level="DEBUG")

def generate_key_pair(path_private_key: str,  path_public_key: str, symmetric_key_path: str) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    try:
        with open(path_public_key, 'wb') as f_p, open(path_private_key, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=serialization.NoEncryption()))
    except FileNotFoundError:
        logging.error(f"{path_private_key} not found") if os.path.isfile(
            path_public_key) else logging.error(f"{path_public_key} not found")
    logging.info(f"public key and private key is recorded  in paths: '{path_private_key}' and {path_public_key}")
    symmetric_key = os.urandom(16)
    ciphertext = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    try:
        with open(symmetric_key_path, "wb") as f:
            f.write(ciphertext)
    except FileNotFoundError:
        logging.error(f"{symmetric_key_path} not found")
    logging.info("symmetric_key is recorded")