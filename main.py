from turtle import goto
from Crypto.Util import number 
from math import gcd, sqrt
import os
import numpy as np
import PySimpleGUI as sg
import AsymmetricCipherWithDigitaSignatulre
import SymmetricCipher
import AsymmetricCipher
import base64
import Hash

tab1_layout =  [[sg.Text('_'  * 100, size=(30, 1)), sg.T('Initial data'), sg.Text('_'  * 100, size=(29, 1))], 
                [sg.T('Filename\t'),  sg.In(default_text='SC.txt',key='filename', size=(61, 1)), sg.FileBrowse()],
                [sg.T('Key\t'), sg.In(key='Key', size=(70, 1))],
                [sg.T('IV\t'), sg.In(key='IV', size=(70, 1))],
                [sg.Push(), sg.Button('Generate new key and initialization vector'), sg.Button('Encrypt')],
                [sg.Text('_'  * 100, size=(70, 1))],
                [sg.Push(), sg.T('File content'), sg.Push()], 
                [sg.MLine(key='File_content', size=(78,5))], 
                [sg.Push(), sg.T('Encryption AES-128'), sg.Push(), sg.T('Encryption Salsa20'), sg.Push()], 
                [sg.MLine(key='AES', size=(37,5)), sg.Push(), sg.MLine(key='Salsa20', size=(37,5))],
                [sg.Push(), sg.T('Decrypted file'), sg.Push()], 
                [sg.MLine(key='DecFile', size=(78,5))]
                ]    

tab2_layout = [[sg.Text('_'  * 100, size=(30, 1)), sg.T('Initial data'), sg.Text('_'  * 100, size=(29, 1))], 
                [sg.T('Filename\t'),  sg.In(default_text='SC.txt',key='filename2', size=(61, 1)), sg.FileBrowse()],
                [sg.Push(),  sg.Button('Asymmetric encrypt'), sg.Push()],
                [sg.Text('_'  * 100, size=(70, 1))],
                [sg.Push(), sg.T('File content'), sg.Push()], 
                [sg.MLine(key='File_content2', size=(78,5))], 
                [sg.Push(), sg.T('Open key'), sg.Push(), sg.T('Private key'), sg.Push()], 
                [sg.MLine(key='Open_key', size=(37,5)), sg.Push(), sg.MLine(key='Private_key', size=(37,5))],
                [sg.Push(), sg.T('Optimal asymmetric encryption with padding'), sg.Push()], 
                [sg.MLine(key='oaewp', size=(78,5))],
                [sg.Push(), sg.T('Decrypted file'), sg.Push()], 
                [sg.MLine(key='DecFile2', size=(78,5))]
                ]  

tab3_layout = [[sg.Text('_'  * 100, size=(30, 1)), sg.T('Initial data'), sg.Text('_'  * 100, size=(29, 1))], 
                [sg.T('Filename\t'),  sg.In(default_text='SC.txt',key='filename3', size=(61, 1)), sg.FileBrowse()],
                [sg.Push(),  sg.Button('Asymmetric Cipher With Digita Signatulre'), sg.Push()],
                [sg.Text('_'  * 100, size=(70, 1))],
                [sg.Push(), sg.T('File content'), sg.Push()], 
                [sg.MLine(key='File_content3', size=(78,5))], 
                [sg.Push(), sg.T('Open key'), sg.Push(), sg.T('Private key'), sg.Push()], 
                [sg.MLine(key='Open_key3', size=(37,5)), sg.Push(), sg.MLine(key='Private_key3', size=(37,5))],
                [sg.Push(), sg.T('SHA-1'), sg.Push()], 
                [sg.MLine(key='SHA', size=(78,5))],
                [sg.Text('Signature verification: '), sg.Text(key='ver')]
                ]  

tab4_layout = [[sg.Text('_'  * 100, size=(30, 1)), sg.T('Initial data'), sg.Text('_'  * 100, size=(29, 1))], 
                [sg.T('Filename\t'),  sg.In(default_text='SC.txt',key='filename4', size=(61, 1)), sg.FileBrowse()],
                [sg.Push(), sg.Button('SHA-1'), sg.Button('MD5'), sg.Button('MD2'), sg.Button(('RIPEMD-160'), size=(20, 1)), sg.Push()],
                [sg.Text('_'  * 100, size=(70, 1))],
                [sg.Push(), sg.T('File content'), sg.Push()], 
                [sg.MLine(key='File_content4', size=(78,10))], 
                [sg.Push(), sg.T('Hash file'), sg.Push()], 
                [sg.MLine(key='Hash', size=(78,10))]
                ]  

layout = [[sg.TabGroup([[sg.Tab('Symmetric encryption', tab1_layout, tooltip='tip'), sg.Tab('Asymmetric encryption', tab2_layout),
         sg.Tab('Asymmetric Cipher With Digita Signatulre', tab3_layout), sg.Tab('Hash', tab4_layout)]], tooltip='TIP2')]
            ]  
sg.theme('DarkAmber')
sg.theme('BluePurple')

window = sg.Window('LW 3', layout, grab_anywhere=True, finalize=True)

#init
# load param for Symmetric encryption
key = SymmetricCipher.load_key()
iv = SymmetricCipher.load_iv()
window['Key'].Update(key)
window['IV'].Update(base64.b64encode(iv).decode('cp1251'))
window['filename'].Update('SC.txt')
window['filename2'].Update('AC.txt')
window['filename3'].Update('ACDS.txt')
window['filename4'].Update('hash.txt')
while True:    
    event, values = window.read()  
    if event == sg.WIN_CLOSED:           # always,  always give a way out!    
        break  
    if event == 'Encrypt':
        key = SymmetricCipher.load_key()
        iv = SymmetricCipher.load_iv()
        SC = SymmetricCipher.SymmetricCipher(os.path.basename(values['filename']), key, iv)
        a = open(os.path.basename(values['filename']), 'r')
        f = a.read()
        window['File_content'].Update(f)
        window['AES'].Update(SC.encrypt_file(cipher='AES'))
        window['Salsa20'].Update(SC.encrypt_file(cipher='Salsa20'))
        window['DecFile'].Update(SC.decrypt_file())

    if event == 'Generate new key and initialization vector':
        # создадим и запишем в файл параметры
        SymmetricCipher.write_key()
        SymmetricCipher.write_iv()
        # загружаем параметры
        key = SymmetricCipher.load_key()
        iv = SymmetricCipher.load_iv()
        window['Key'].Update(key) 
        window['IV'].Update(base64.b64encode(iv).decode('cp1251'))

    if event == 'Asymmetric encrypt':
        a = open(os.path.basename(values['filename2']), 'r')
        f = a.read()
        window['File_content2'].Update(f)
        AC = AsymmetricCipher.AsymmetricCipher(os.path.basename(values['filename2']))
        openKey, priv = AC.GetKeys()
        window['Open_key'].Update(openKey)
        window['Private_key'].Update(priv)
        window['oaewp'].Update(AC.encrypt_file())
        window['DecFile2'].Update(AC.decrypt_file())
    
    if event == 'Asymmetric Cipher With Digita Signatulre':
        t = os.path.basename(values['filename3'])
        a = open(t, 'r')
        f = a.read()
        a.close()
        window['File_content3'].Update(f)
        ACDS =  AsymmetricCipherWithDigitaSignatulre.AsymmetricCipherWithDigitalSignature(os.path.basename(values['filename3']))
        openKey, priv = ACDS.GetKeys()
        window['Open_key3'].Update(openKey)
        window['Private_key3'].Update(priv)
        window['SHA'].Update(ACDS.GetDigest())
        window['ver'].Update(ACDS.ver_text)

    if event == 'MD5':
        a = open(os.path.basename(values['filename4']), 'r')
        f = a.read()    
        window['File_content4'].Update(f)
        hash = Hash.Hashs(os.path.basename(values['filename4']))
        window['Hash'].Update(hash.md5())

    if event == 'MD2':
        a = open(os.path.basename(values['filename4']), 'r')
        f = a.read()
        window['File_content4'].Update(f)
        hash = Hash.Hashs(os.path.basename(values['filename4']))
        window['Hash'].Update(hash.md2())

    if event == 'SHA-1':
        a = open(os.path.basename(values['filename4']), 'r')
        f = a.read()
        window['File_content4'].Update(f)
        hash = Hash.Hashs(os.path.basename(values['filename4']))
        window['Hash'].Update(hash.sha1())

    if event == 'RIPEMD-160':
        a = open(os.path.basename(values['filename4']), 'r')
        f = a.read()
        window['File_content4'].Update(f)
        hash = Hash.Hashs(os.path.basename(values['filename4']))
        window['Hash'].Update(hash.ripemd160())
    a.close()
    window['filename'].Update(os.path.basename(values['filename']))
    window['filename2'].Update(os.path.basename(values['filename2']))
    window['filename3'].Update(os.path.basename(values['filename3']))
    window['filename4'].Update(os.path.basename(values['filename4']))
