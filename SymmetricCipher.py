from Crypto import Random
from Crypto.Cipher import AES, Salsa20
from cryptography.fernet import Fernet
import base64

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

# Создаем ключ и сохраняем его в файл
# По умолчанию длина ключа 16 байт (128 бит) - для шифра AES
def write_key(lenght_key=16):
    key = Fernet.generate_key()[:lenght_key]
    with open('crypto.key', 'wb') as key_file:
        key_file.write(key)

# Загружаем ключ 'crypto.key'
def load_key():
    return open('crypto.key', 'rb').read()
        
    
# Создаем вектор инициализации и сохраняем его в файл
def write_iv():
    iv = Random.new().read(AES.block_size)
    with open('crypto.iv', 'wb') as iv_file:
        iv_file.write(iv)

# Загружаем вектор инициализации 'crypto.iv'     
def load_iv():
    return open('crypto.iv', 'rb').read()

class SymmetricCipher():
    def __init__(self, file_name, key=None, iv=None):
        self.file_name = file_name
        self.cur_cipher = None
        if key != None:
            self.key = key
        else:
            self.key=write_key()
            
        if iv != None:
            self.iv = iv
        
    def encryptAES(self, message):
        message = pad(message)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.iv + cipher.encrypt(message)

    def decryptAES(self, ciphertext):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")
    
    def encryptSalsa20(self, message):
        cipher = Salsa20.new(self.key)
        return cipher.nonce + cipher.encrypt(message)

    def decryptSalsa20(self, ciphertext):
        msg_nonce = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = Salsa20.new(self.key, nonce=msg_nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

    def encrypt_file(self, cipher):
        with open(self.file_name, 'rb') as fo:
            plaintext = fo.read()
        self.cur_cipher = cipher
        if cipher == 'AES':
            enc = self.encryptAES(plaintext)
        elif cipher == 'Salsa20':
            enc = self.encryptSalsa20(plaintext)
        with open(self.file_name[:4] + 'sym_enc.txt', 'wb') as fo:
            fo.write(enc)
        return base64.b64encode(enc).decode('cp1251')

    def decrypt_file(self):
        with open(self.file_name[:4] + 'sym_enc.txt', 'rb') as fo:
            ciphertext = fo.read()
        cipher = self.cur_cipher
        if cipher == 'AES':
            dec = self.decryptAES(ciphertext)
        elif cipher == 'Salsa20':
            dec = self.decryptSalsa20(ciphertext)
        with open(self.file_name[:4] + 'sym_dec.txt', 'wb') as fo:
            fo.write(dec)
        return dec.decode('cp1251')

    
if __name__ == "__main__":
    # создадим и запишем в файл параметры
    write_key()
    write_iv()
    # загружаем параметры
    key = load_key()
    iv = load_iv()

    #s = SymmetricCipher(filename, key)
    #s.encrypt_file(cipher='Salsa20')
