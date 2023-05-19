import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


class Assymmetric:
    """Класс Assymmetric для генирации пары асимметричных ключей шифрования"""
    def __init__(self, public_k_file: str = None, private_k_file: str = None, decrypted_file: str = None, encrypt_file: str = None) -> None:
        """Запись путей файлов в поля класса
        Args:
            public_k_file (str, optional): путь к открытому ключу. Defaults to None.
            private_k_file (str, optional): путь к закрытому ключу. Defaults to None.
            decrypted_file (str, optional): путь к расшифрованному файлу. Defaults to None.
            encrypt_file (str, optional): путь к зашифрованному файлу. Defaults to None.
        Returns: None
        """
        self.public_pem = public_k_file
        self.private_pem = private_k_file
        self.encryption_file = encrypt_file
        self.decrypted_file = decrypted_file

    def generate_keys(self) -> None:
        """Генерация пары ключей для асимметричного алгоритма шифрования"""
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key = keys
        public_key = keys.public_key()
        self.private_key_to_file(private_key)
        self.public_key_to_file(public_key)

    def public_key_to_file(self, public_key: str) -> None:
        """Записываем открытый ключ в файл

        Args:
            public_key(str) - открытый ключ

        Returns:
            None
        """
        try:
            with open(self.public_pem, 'wb') as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
        except:
            logging.error(
                f"Ошибка открытия файла: {self.public_pem}")

    def private_key_to_file(self, private_key: str) -> None:
        """Записываем закрытый ключ в файл

        Args:
            private_key (str): закрытый ключ
        """
        try:
            with open(self.private_pem, 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))
        except:
            logging.error(
                f"Ошибка открытия файла: {self.private_pem}")

    def  encryption_text_to_file(self, c_text: bytes) -> None:
        """
        десериализация расшифрованного текста в файл

        Args:
            c_text (bytes): текст в байтах, который записываем в файл
        """

        try:
            with open(self.encryption_file, 'wb') as file:
                file.write(c_text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encryption_file}")

    def decryption_text_to_file(self, data: str) -> None:
        """Запись рашифрованного текста в файл

        Args:
            data (str): текст, который мы записываем в файл 
        """
        try:
            with open(self.decrypted_file, 'wb') as file:
                file.write(data)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypted_file}")

    def __get_public_key(self) -> str:
        """Десериализация открытого ключа\n
        Returns:
                (str) - считанный ключ
        """

        try:
            with open(self.public_pem, 'rb') as pem_in:
                public_bytes = pem_in.read()
            d_public_key = load_pem_public_key(public_bytes)
            return d_public_key
        except:
            logging.error(
                f"Ошибка открытия файла: {self.public_pem}")

    def __get_private_key(self) -> str:
        """Десериализация закрытого ключа\n
        Returns:
            d_private_key(str) - считанный ключ
        """

        try:
            with open(self.private_pem, 'rb') as pem_in:
                private_bytes = pem_in.read()
            d_private_key = load_pem_private_key(private_bytes, password=None,)
            return d_private_key
        except:
            logging.error(
                f"Ошибка открытия файла: {self.private_pem}")

    def __get_encryption_text(self) -> bytes:
        """Десериализация зашифрованного текста\n
        Returns:
        c_text(bytes) - считанный зашифрованный текст
        """
        try:
            with open(self.encryption_file, 'rb') as file:
                c_text = file.read()
                return c_text
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encryption_file}")

    def encryption(self) -> None:
        """Шифрование текста при помощи RSA-OAEP\n
        Retursn:
            None
        """
        data = str()
        try:
            with open(self.decrypted_file, 'rb') as file:
                data = file.read()

            if type(data) != bytes:
                text = bytes(data, "UTF-8")
            else:
                text = data

            public_key = self.__get_public_key()
            c_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(
                algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            self.encryption_text_to_file(c_text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypted_file}")

    def decryption(self) -> None:
        """Дешифрование текста асимметричным алгоритмом
        """
        private_key = self.__get_private_key()
        c_text = self.__get_encryption_text()
        dc_text = private_key.decrypt(c_text, padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.decryption_text_to_file(dc_text)