from assymetric import Assymmetric
from symmetric import Symmetric

def keys_generator(private_key: str, public_key: str, symmetric_key: str, symmetric_key_decrypted: str, size: int) -> None:

    assym = Assymmetric(
        public_key, private_key, symmetric_key_decrypted, symmetric_key)
    assym.generate_keys()

    symm = Symmetric(size, symmetric_key_decrypted)
    symm.generate_key()

    assym.encryption()