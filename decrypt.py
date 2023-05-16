from assymetric import Assymmetric
from symmetric import Symmetric

def decrypt_data(encrypted_file: str, private_key: str,
                 symmetric_key: str, decrypted_file, symmetric_key_decrypted: str, size: int) -> None:

    assym_SYM = Assymmetric(
        private_k_file=private_key, decrypted_file=symmetric_key_decrypted, encrypt_file=symmetric_key)
    assym_SYM.decryption()

    sym = Symmetric(size, symmetric_key_decrypted, decrypted_file,
                               encrypted_file)
    sym.decryption()
