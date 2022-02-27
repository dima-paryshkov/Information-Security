from Crypto.Hash import SHA1, MD5, MD2, RIPEMD160

class Hashs():
    def __init__(self, file_name):
        self.file_name = file_name
        self.message = self.GetText()
        
    def sha1(self):
        digest = SHA1.new(self.message).hexdigest().encode()
        self.hash_sha1 = digest
        self.WriteSHA1()
        return digest.decode('cp1251')
        
    def md5(self):
        digest = MD5.new(self.message).hexdigest().encode()
        self.hash_md5 = digest
        self.WriteMD5()
        return digest.decode('cp1251')

    def md2(self):
        digest = MD2.new(self.message).hexdigest().encode()
        self.hash_md2 = digest
        self.WriteMD2()
        return digest.decode('cp1251')

    def ripemd160(self):
        digest = RIPEMD160.new(self.message).hexdigest().encode()
        self.hash_ripemd160 = digest
        self.WriteRIPEMD160()
        return digest.decode('cp1251')
    
    def WriteSHA1(self):
        with open(self.file_name[:4] + ' - hash_SHA1.txt', 'wb') as fo:
            fo.write(self.hash_sha1)

    def WriteMD5(self):
        with open(self.file_name[:4] + ' - hash_MD5.txt', 'wb') as fo:
            fo.write(self.hash_md5)
            
    def WriteMD2(self):
        with open(self.file_name[:4] + ' - hash_MD2.txt', 'wb') as fo:
            fo.write(self.hash_md2)

    def WriteRIPEMD160(self):
        with open(self.file_name[:4] + ' - hash_RIPEMD160.txt', 'wb') as fo:
            fo.write(self.hash_ripemd160)
       
    def GetSHA1(self):
        return self.hash_sha1

    def GetMD5(self):
        return self.hash_md5

    def GetMD5(self):
        return self.hash_md2

    def GetMD5(self):
        return self.hash_ripemd160

    def GetText(self):
        with open(self.file_name, 'rb') as fo:
            plaintext = fo.read()
        return plaintext
