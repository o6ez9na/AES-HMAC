import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Константы
SALT_SIZE = 32  # Размер соли в байтах
IV_SIZE = 16  # Размер инициализирующего вектора
HMAC_SIZE = 32  # Размер HMAC
KEY_SIZE = 32  # Размер ключа для AES-256
ITERATIONS = 100000  # Количество итераций для PBKDF2

# Генерация ключа шифрования на основе парольной фразы и соли
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Шифрование данных
def encrypt_file(input_filename: str, output_filename: str, password: str):
    try:
        # Генерация соли и инициализирующего вектора
        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)

        # Генерация ключа на основе соль + пароль
        key = generate_key(password, salt)

        # Открытие файла для чтения и шифрования
        with open(input_filename, 'rb') as f:
            plaintext = f.read()

        # Создание HMAC для проверки целостности
        hmac_value = hmac.new(key, plaintext, hashlib.sha256).digest()

        # Шифрование данных с использованием AES-256 в режиме CFB
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Запись соли, HMAC, инициализирующего вектора и зашифрованных данных в файл
        with open(output_filename, 'wb') as f:
            f.write(salt + hmac_value + iv + ciphertext)

        print(f"Файл '{input_filename}' успешно зашифрован и сохранен как '{output_filename}'.")
    except Exception as e:
        print(f"Ошибка при шифровании: {e}")

# Расшифрование данных
def decrypt_file(input_filename: str, output_filename: str, password: str):
    try:
        with open(input_filename, 'rb') as f:
            file_data = f.read()

        # Извлечение соли, HMAC, инициализирующего вектора и зашифрованного текста
        salt = file_data[:SALT_SIZE]
        hmac_value = file_data[SALT_SIZE:SALT_SIZE + HMAC_SIZE]
        iv = file_data[SALT_SIZE + HMAC_SIZE:SALT_SIZE + HMAC_SIZE + IV_SIZE]
        ciphertext = file_data[SALT_SIZE + HMAC_SIZE + IV_SIZE:]

        # Генерация ключа на основе соль + пароль
        key = generate_key(password, salt)

        # Расшифрование данных с использованием AES-256 в режиме CFB
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

        # Проверка целостности с помощью HMAC
        calculated_hmac = hmac.new(key, decrypted_text, hashlib.sha256).digest()

        if hmac.compare_digest(hmac_value, calculated_hmac):
            with open(output_filename, 'wb') as f:
                f.write(decrypted_text)
            print(f"Файл '{input_filename}' успешно расшифрован и сохранен как '{output_filename}'.")
        else:
            print("Ошибка: данные повреждены или пароль неверный.")
    except Exception as e:
        print(f"Ошибка при расшифровании: {e}")

# Пример использования
if __name__ == "__main__":
    password = input("Введите пароль: ")

    # Шифрование
    encrypt_file('./input.txt', './encrypted.txt', password)

    # Расшифрование
    decrypt_file('./encrypted.txt', './decrypted.txt', password)
