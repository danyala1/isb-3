import argparse
import json
import logging
import os

from encryption import encrypt_data
from keys_generate import keys_generator
from decrypt import  decrypt_data

def check_size(size: int):
    if size == 128 or size == 192 or size == 256:
        return int(size/8), True
    return 16, False


def get_argument():
    parser = argparse.ArgumentParser(description="Гибридное шифрование с использованием асимметричного и симметричного ключа")
    mode_group = parser.add_mutually_exclusive_group(required=True)
    #mode_group.add_argument(
     #   '-s', '--size', action='store_true', help='Выбрать длинну ключа')
    mode_group.add_argument(
        '-gen', '--generation', action='store_true', help='Сгенерировать ключи')
    mode_group.add_argument(
        '-enc', '--encryption', action='store_true', help='Зашифровать данные')
    mode_group.add_argument(
        '-dec', '--decryption', action='store_true', help='Расшифровать данные')
    args = parser.parse_args()
    return args


def set_config_file(name: str) -> str:

    SENTTING = os.path.join(name)
    settings = str()
    try:
        with open(SENTTING) as json_file:
            settings = json.load(json_file)
    except FileNotFoundError:
        logging.error(
            f"Ошибка открытия файла: {SENTTING} \nЗавершение работы")
        exit()
    return settings


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    args = get_argument()
    mode = (args.generation, args.encryption, args.decryption)
    settings = set_config_file("settings.json")
    size = int(settings["size"])
    flag=False
    if size == 128 or size == 192 or size == 256:
        size = int(size/8)
        flag = True

    if not flag:
        logging.info(
            'Размер ключа введен некорректно -> установлен размер по умолчанию = 128.')
    else:
        logging.info(f'Размер ключа: {size * 8}')

    if(mode == (True, False, False)):
        keys_generator(settings['private_key'], settings['public_key'], settings['symmetric_key'], settings['symmetric_key_decrypted'], size)
        logging.info('Ключи сгенерированы')


    elif(mode == (False, True, False)):
        encrypt_data(settings['src_text_file'], settings['private_key'],
                     settings['symmetric_key'], settings['encrypted_file'], settings["symmetric_key_decrypted"], size)
        logging.info('Данные зашифрованы')
    if(mode == (False, False, True)):
        decrypt_data(settings['encrypted_file'], settings['private_key'],
                     settings['symmetric_key'], settings['decrypted_file'], settings["symmetric_key_decrypted"], size)
        logging.info('Данные расшифрованы')
    else:
        logging.error("Не выбран допустимый режим")