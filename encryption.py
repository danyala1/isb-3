

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization

import os
import logging
logging.basicConfig(level="DEBUG")
def encryption_info(way_text, private_key_path, encrypted_symmetric_way, way_recorded_encrypted_text):
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None)
    except FileExistsError:
        logging.error(f"{private_key_path} Not found")
    logging.info(f"{private_key_path} read")
    try:
        with open(way_recorded_encrypted_text, "rb") as f:
            encrypted_symmetric_way = f.read()
        symmetric_key = private_key.decrypt(encrypted_symmetric_way, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except FileNotFoundError:
        logging.error(f"{way_recorded_encrypted_text} Not found")
    logging.info(f"{way_recorded_encrypted_text} read")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    logging.info("File was successfully encrypted")
    try:
        with open(way_text, "rb") as f_in, open(way_recorded_encrypted_text, "wb") as f_out:
            f_out.write(iv)
            while chunk := f_in.read(128):
                padded_chunk = padder.update(chunk)
                f_out.write(encryptor.update(padded_chunk))
            f_out.write(encryptor.update(padder.finalize()))
            f_out.write(encryptor.finalize())
    except FileNotFoundError:
        logging.error(f"{way_text} Not found") if os.path.isfile(
            way_recorded_encrypted_text) else logging.error(f"{way_recorded_encrypted_text} Not found")
    logging.info(f"{way_recorded_encrypted_text} is recorded" )