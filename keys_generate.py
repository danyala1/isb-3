from assymetric import Assymmetric
from symmetric import Symmetric
import logging
logging.basicConfig(level=logging.INFO)


def keys_generator(private_key: str, public_key: str, symmetric_key: str, symmetric_key_decrypted: str, size: int) -> None:
    """Генерация ключей

    Параметры:
        private_key(str): путь к закрытому ключу
        public_key(str): путь к открытому ключу
        symmetric_key(str): путь симметричному ключу
        symmetric_key_decrypted(str): путь к симметричному расшифрованному ключу
        size(int): размер ключа
    """
    try:
        assym = Assymmetric(
            public_key, private_key, symmetric_key_decrypted, symmetric_key)
        assym.generate_keys()

        symm = Symmetric(size, symmetric_key_decrypted)
        symm.generate_key()

        assym.encryption()
        logging.info("Ключт были сгенерированны успешно")
    except:
        logging.error("При генерации ключей произошла ошибка")
