from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP 
import base64 

class AsymmetricCipher():
    def __init__(self, file_name):
        self.file_name = file_name
        
        # генерация закрытого и открытого ключа
        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey()
        
    
    # Шифрование открытым ключем
    def encrypt(self, message):
        cipher =  PKCS1_OAEP.new(self.public_key)
        enc_mess = cipher.encrypt(message)
        return base64.b64encode(enc_mess)
    
    # Дешифрование закрытым ключем
    def decrypt(self, ciphertext):
        decoded_message = base64.b64decode(ciphertext + b'===')
        cipher = PKCS1_OAEP.new(self.private_key)
        return cipher.decrypt(decoded_message) 

    def encrypt_file(self):
        with open(self.file_name, 'rb') as fo:
            plaintext = fo.read()
            
        enc = self.encrypt(plaintext)
        
        with open(self.file_name[:4] + ' - enc.txt', 'wb') as fo:
            fo.write(enc)
        return base64.b64encode(enc).decode('cp1251')
        
    def decrypt_file(self):
        with open(self.file_name[:4] + ' - enc.txt', 'rb') as fo:
            ciphertext = fo.read()
            
        dec = self.decrypt(ciphertext)
        
        with open(self.file_name[:4] + ' - dec.txt', 'wb') as fo:
            fo.write(dec)
        return dec.decode('cp1251')
    
    # Вовзращает первым аргументом публичный ключ
    # Вторым аргументом - приватный
    def GetKeys(self):
        pub = self.public_key.exportKey().decode()
        priv = self.private_key.exportKey().decode()
        return pub[26:len(pub) - 24], priv[31:len(priv) - 29]
