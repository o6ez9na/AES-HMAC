import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Константы
SALT_SIZE = 32
IV_SIZE = 16
HMAC_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100000

# Генерация ключа
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
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
def get_cipher(key: bytes, iv: bytes, encrypt: bool):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    return cipher.encryptor() if encrypt else cipher.decryptor()

# Функция шифрования/дешифрования
def process_file(data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
    cipher = get_cipher(key, iv, encrypt)
    return cipher.update(data) + cipher.finalize()

# Шифрование файла
def encrypt_file(input_filename: str, output_filename: str, password: str):
    try:
        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)
        key = generate_key(password, salt)
        plaintext = read_file(input_filename)
        hmac_value = hmac.new(key, plaintext, hashlib.sha256).digest()
        ciphertext = process_file(plaintext, key, iv, True)
        write_file(output_filename, salt + hmac_value + iv + ciphertext)
        print(f"Файл '{input_filename}' успешно зашифрован.")
    except Exception as e:
        print(f"Ошибка при шифровании: {e}")

# Расшифрование файла
def decrypt_file(input_filename: str, output_filename: str, password: str):
    try:
        file_data = read_file(input_filename)
        salt = file_data[:SALT_SIZE]
        hmac_value = file_data[SALT_SIZE:SALT_SIZE + HMAC_SIZE]
        iv = file_data[SALT_SIZE + HMAC_SIZE:SALT_SIZE + HMAC_SIZE + IV_SIZE]
        ciphertext = file_data[SALT_SIZE + HMAC_SIZE + IV_SIZE:]
        key = generate_key(password, salt)
        decrypted_text = process_file(ciphertext, key, iv, False)
        calculated_hmac = hmac.new(key, decrypted_text, hashlib.sha256).digest()
        if hmac.compare_digest(hmac_value, calculated_hmac):
            write_file(output_filename, decrypted_text)
            print(f"Файл '{input_filename}' успешно расшифрован.")
        else:
            print("Ошибка: данные повреждены или пароль неверный.")
    except Exception as e:
        print(f"Ошибка при расшифровании: {e}")

# Пример использования
if __name__ == "__main__":
    password = input("Введите пароль: ")
    encrypt_file('input.txt', 'encrypted.txt', password)
    decrypt_file('encrypted.txt', 'decrypted.txt', password)
