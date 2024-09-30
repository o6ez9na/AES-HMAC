import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from scripts.const import Constants as const

# Генерация ключа
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=const.KEY_SIZE,
        salt=salt,
        iterations=const.ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Функция для чтения файла
def read_file(file_name: str) -> bytes:
    with open(file_name, 'rb') as f:
        return f.read()

# Функция для записи файла
def write_file(file_name: str, data: bytes):
    with open(file_name, 'wb') as f:
        f.write(data)

# Функция для создания шифратора/дешифратора
def get_cipher(key: bytes, initialization_vector: bytes, encrypt: bool):
    cipher = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), backend=default_backend())
    return cipher.encryptor() if encrypt else cipher.decryptor()

# Функция шифрования/дешифрования
def process_file(data: bytes, key: bytes, initialization_vector: bytes, encrypt: bool) -> bytes:
    cipher = get_cipher(key, initialization_vector, encrypt)
    return cipher.update(data) + cipher.finalize()

# Шифрование файла
def encrypt_file(input_filename: str, output_filename: str, password: str):
    try:
        salt = os.urandom(const.SALT_SIZE)
        initialization_vector = os.urandom(const.IV_SIZE)
        key = generate_key(password, salt)
        plaintext = read_file(input_filename)
        hmac_value = hmac.new(key, plaintext, hashlib.sha256).digest()
        ciphertext = process_file(plaintext, key, initialization_vector, True)
        write_file(output_filename, salt + hmac_value + initialization_vector + ciphertext)
        print(f"Файл '{input_filename}' успешно зашифрован.")
    except Exception as e:
        print(f"Ошибка при шифровании: {e}")

# Расшифрование файла
def decrypt_file(input_filename: str, output_filename: str, password: str):
    try:
        #* Вырезаем нужные нам параметры
        file_data = read_file(input_filename)
        salt = file_data[:const.SALT_SIZE]
        hmac_value = file_data[const.SALT_SIZE:const.SALT_SIZE + const.HMAC_SIZE]
        initialization_vector = file_data[const.SALT_SIZE + const.HMAC_SIZE:const.SALT_SIZE + const.HMAC_SIZE + const.IV_SIZE]
        ciphertext = file_data[const.SALT_SIZE + const.HMAC_SIZE + const.IV_SIZE:]
        key = generate_key(password, salt)
        decrypted_text = process_file(ciphertext, key, initialization_vector, False)
        calculated_hmac = hmac.new(key, decrypted_text, hashlib.sha256).digest()
        if hmac.compare_digest(hmac_value, calculated_hmac):
            write_file(output_filename, decrypted_text)
            print(f"Файл '{input_filename}' успешно расшифрован.")
        else:
            print("Ошибка: данные повреждены или пароль неверный.")
    except Exception as e:
        print(f"Ошибка при расшифровании: {e}")