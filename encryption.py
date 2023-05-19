from assymetric import Assymmetric
from symmetric import Symmetric


def encrypt_data(decrypted_file: str, private_key: str, symmetric_key: str, encrypted_file: str, symmetric_key_decrypted, size: int) -> None:
    """Шифрование данных
    Args:
        decrypted_file (str): путь расшифрованному тексту
        private_key (str): путь к закрытому ключу
        symmetric_key (str): путь к симметричному ключу
        encrypted_file (str): путь к зашифрованному тексту
        symmetric_key_decrypted (_type_): путь к симметричному расшифрованному ключу
        size (int): размер ключа
    """
    assym_SYM = Assymmetric(
        private_k_file=private_key, decrypted_file=symmetric_key_decrypted, encrypt_file=symmetric_key)
    assym_SYM.decryption()

    sym = Symmetric(size, symmetric_key_decrypted,
                    decrypted_file, encrypted_file)
    sym.encryption()
