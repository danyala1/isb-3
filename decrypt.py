

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


import logging
import os


logging.basicConfig(level="DEBUG")


def decrypt_data(text_way, private_key_path, encrypted_symmetric_key_way, recorded_decrypted_way):

    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend())
    except FileNotFoundError:
        logging.error(f"{private_key_path} Not found")
    logging.info(f"{private_key_path} is read")
    try:
        with open(encrypted_symmetric_key_way, "rb") as f:
            encrypted_symmetric_key = f.read()
        symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except FileNotFoundError:
        logging.error(f"{text_way} Not found")
    logging.info(f"{encrypted_symmetric_key_way} is read")
    
    try:
        with open(text_way, "rb") as f_in, open(recorded_decrypted_way, "wb") as f_out:
            iv = f_in.read(16)
            cipher = Cipher(algorithms.Camellia(symmetric_key),
                            modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = sym_padding.PKCS7(128).unpadder()
            try:
                with open(recorded_decrypted_way, "wb") as f_out:
                    while chunk := f_in.read(128):
                        decrypted_chunk = decryptor.update(chunk)
                        f_out.write(unpadder.update(decrypted_chunk))
                    f_out.write(unpadder.update(decryptor.finalize()))
                    f_out.write(unpadder.finalize())
            except FileNotFoundError:
                logging.error(f"{recorded_decrypted_way} Not found")
            logging.info(f" text is decrypted")
    except FileNotFoundError:
        logging.error(f"{recorded_decrypted_way} Not found") if os.path.isfile(
            text_way) else logging.error(f"{text_way} Not found")