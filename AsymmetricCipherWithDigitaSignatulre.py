from Crypto.Hash import MD5 
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5 
import hashlib
import base64
# https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html

class AsymmetricCipherWithDigitalSignature():
    def __init__(self, file_name):
        self.file_name = file_name
        self.digest = None
        self.hash_object = None            # This is an object from the Crypto.Hash package
        
        self.Todo()
        
    # На стороне отправителя
    def Sender(self, message):
        # хэшируем сообщение
        self.hash_object = SHA.new(message)
        
        key = RSA.import_key(open('private_key.der').read())
        
        # с помощью закрытого ключа подписываем хэш
        self.signature = PKCS1_v1_5.new(key).sign(self.hash_object)
        
        print('Signature: ', base64.b64encode(self.signature))
        self.digest = self.hash_object.hexdigest().encode()
        self.WriteSig()
        return self.hash_object, self.signature
    
    # На стороне получателя
    # Принимает хэш и подпись
    def Receiver(self, Hash, Signature):
        key = RSA.import_key(open('public_key.der').read())
        
        verifier = PKCS1_v1_5.new(key)
        
        # проверяет подпись с помощью открытого ключа
        verified = verifier.verify(Hash, Signature)
        self.verified = verified
        self.ver_text = 'Verification correct' if verified else 'Verification failed'
        print(self.ver_text)
            
    # Схема действий
    def Todo(self):
        # генерация ключей
        self.GenerateKeys()
        
        # текст, который будет хэшировать отправитель
        text = self.GetText()
        
        # Отправитель хэширует и подписывает хэш
        Hash, Signature = self.Sender(text)
        
        # Получатель принимает хэш и проверяет подпись
        self.Receiver(Hash, Signature)
        
        self.WriteHash()
    
    def GetText(self):
        with open(self.file_name, 'rb') as fo:
            plaintext = fo.read()
        return plaintext
    
    def WriteHash(self):
        with open(self.file_name[:4] + ' - hash.txt', 'wb') as fo:
            fo.write(self.digest)
    
    def WriteSig(self):
        with open(self.file_name[:4] + ' - signature.txt', 'wb') as fo:
            fo.write(base64.b64encode(self.signature))
    
    def GenerateKeys(self):
        keys = RSA.generate(1024)

        with open('private_key.der', 'wb') as key_file:
            key_file.write(keys.exportKey())
        with open('public_key.der', 'wb') as key_file:
            key_file.write(keys.publickey().exportKey())
            
        self.private_key = keys
        self.public_key = keys.publickey()

    def GetKeys(self):
        pub = self.public_key.exportKey().decode()
        priv = self.private_key.exportKey().decode()
        return pub[26:len(pub) - 24], priv[31:len(priv) - 29]
    
    def GetSignature(self):
        return base64.b64encode(self.signature).decode('cp1251')
    
    def GetDigest(self):
        return self.digest.decode('cp1251')
    
    def GetVerification(self):
        return self.verified, self.ver_text
