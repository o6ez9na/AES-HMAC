from scripts.scripts import encrypt_file, decrypt_file 

if __name__ == "__main__":
    password = input("Введите пароль: ")
    encrypt_file('./encrypt/input.txt', './encrypt/encrypted.txt', password)
    decrypt_file('./encrypt/encrypted.txt', './decrypt/decrypted.txt', password)
