import os
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from scripts.const import Constants
from ctypes import windll, Structure, c_long, byref
from alive_progress import alive_bar


class POINT(Structure):
    _fields_ = [("x", c_long), ("y", c_long)]


def queryMousePosition():
    pt = POINT()
    windll.user32.GetCursorPos(byref(pt))
    return pt.x + pt.y


def generate_salt():
    res = 0
    with alive_bar(600000) as bar:
        for i in range(0, 600000):
            res += queryMousePosition()
            bar()
    Constants.set_salt_size(size=len(str(res)))
    return str(res).encode()


# ? Генерация ключа
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=Constants.KEY_SIZE,  # * Желаемая длинна ключа
        salt=salt,  # * Соль
        iterations=Constants.ITERATIONS,
        backend=default_backend(),  # * Значение по умолчанию
    )
    return kdf.derive(password.encode())


# ? Функция для чтения файла
def read_file(file_name: str) -> bytes:
    with open(file_name, "rb") as f:
        return f.read()


# ? Функция для записи файла
def write_file(file_name: str, data: bytes):
    with open(file_name, "wb") as f:
        f.write(data)


# ? Функция для создания шифратора/дешифратора
def get_cipher(key: bytes, initialization_vector: bytes, encrypt: bool):
    cipher = Cipher(AES256(key), CFB(initialization_vector), backend=default_backend())
    return cipher.encryptor() if encrypt else cipher.decryptor()


# ? Функция шифрования/дешифрования
def process_file(
    data: bytes, key: bytes, initialization_vector: bytes, encrypt: bool
) -> bytes:
    cipher = get_cipher(key, initialization_vector, encrypt)
    return cipher.update(data) + cipher.finalize()


# ? Шифрование файла
def encrypt_file(input_filename: str, output_filename: str, password: str):
    try:
        salt = generate_salt()
        initialization_vector = os.urandom(Constants.IV_SIZE)

        key = generate_key(password, salt)
        plaintext = read_file(input_filename)

        hmac_value = hmac.new(key, plaintext, hashlib.sha256).digest()
        ciphertext = process_file(plaintext, key, initialization_vector, True)

        write_file(
            output_filename, salt + hmac_value + initialization_vector + ciphertext
        )

        print(f"Файл '{input_filename}' успешно зашифрован.")
    except Exception as e:
        print(f"Ошибка при шифровании: {e}")


# ? Расшифрование файла
def decrypt_file(input_filename: str, output_filename: str, password: str):
    try:
        # ? Вырезаем нужные нам параметры
        file_data = read_file(input_filename)
        salt = file_data[: Constants.SALT_SIZE]
        hmac_value = file_data[
            Constants.SALT_SIZE : Constants.SALT_SIZE + Constants.HMAC_SIZE
        ]
        initialization_vector = file_data[
            Constants.SALT_SIZE
            + Constants.HMAC_SIZE : Constants.SALT_SIZE
            + Constants.HMAC_SIZE
            + Constants.IV_SIZE
        ]
        ciphertext = file_data[
            Constants.SALT_SIZE + Constants.HMAC_SIZE + Constants.IV_SIZE :
        ]
        key = generate_key(password, salt)
        decrypted_text = process_file(
            ciphertext, key, initialization_vector, False
        )  # * Расшифровываем данные
        calculated_hmac = hmac.new(
            key, decrypted_text, hashlib.sha256
        ).digest()  # * Вычисление HMAC
        if hmac.compare_digest(hmac_value, calculated_hmac):  # * Сравнение  HMAC
            write_file(output_filename, decrypted_text)
            print(f"Файл '{input_filename}' успешно расшифрован.")
        else:
            print("Ошибка: данные повреждены или пароль неверный.")
    except Exception as e:
        print(f"Ошибка при расшифровании: {e}")
