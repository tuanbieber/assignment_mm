from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import os
import zlib
import base64

class Cryptography():

    def __init__(self):
        pass
    
    def AES_Encryptor(self, file_path, key_path, password, progress_bar):
        encrypt_salt_location = key_path
        file_in = open(encrypt_salt_location, "rb")
        salt_from_file = file_in.read() 
        file_in.close()
        encrypt_key = PBKDF2(password, salt_from_file, dkLen=32) 
        file_to_encrypt = file_path
        file_to_encrypt_size = os.path.getsize(file_to_encrypt)
        buffer_size = 65536 # Tạo buffer
        num_of_iteration = file_to_encrypt_size // buffer_size 
        temp = num_of_iteration // 100 
        input_file = open(file_to_encrypt, 'rb')
        output_file = open(file_to_encrypt + '.encrypted', 'wb' )
        cipher_encrypt = AES.new(encrypt_key, AES.MODE_CFB)
        output_file.write(cipher_encrypt.iv)
        buffer = input_file.read(buffer_size)
        count = 0
        value = 1
        while len(buffer) > 0:
            count = count + 1
            if temp == 0 :
                progress_bar.setValue(100)
            else:
                if count % temp == 0:
                    progress_bar.setValue(value)
                    value = value + 1
            ciphered_bytes = cipher_encrypt.encrypt(buffer)
            output_file.write(ciphered_bytes)
            buffer = input_file.read(buffer_size)
        input_file.close()
        output_file.close()
        # os.remove(file_to_encrypt)

    def AES_Decryptor(self, file_path, key_path, password, progress_bar):
        decrypt_salt_location = key_path
        file_in = open(decrypt_salt_location, "rb") # Read bytes
        salt_from_file = file_in.read() # This key should be the same
        file_in.close()
        file_to_decrypt = file_path
        decrypt_key = PBKDF2(password, salt_from_file, dkLen=32) 
        if False: # check whether the password is correct or not
            print('input wrong key, please try again later!')
            return 
        else:
            file_to_decrypt_size = os.path.getsize(file_to_decrypt)
            buffer_size = 65536 # 64kb
            num_of_iteration = file_to_decrypt_size // buffer_size 
            temp = num_of_iteration // 100 
            file_to_decrypt = file_path
            input_file = open(file_to_decrypt + '', 'rb')
            output_file = open(file_to_decrypt.replace('encrypted','') + 'decrypted', 'wb')
            iv = input_file.read(16)
            cipher_encrypt = AES.new(decrypt_key, AES.MODE_CFB, iv=iv)
            buffer = input_file.read(buffer_size)
            count = 0
            value = 1
            while len(buffer) > 0:
                count = count + 1
                if temp == 0 :
                    progress_bar.setValue(100)
                else:
                    if count % temp == 0:
                        progress_bar.setValue(value)
                        value = value + 1
                decrypted_bytes = cipher_encrypt.decrypt(buffer)
                output_file.write(decrypted_bytes)
                buffer = input_file.read(buffer_size)
            input_file.close()
            output_file.close()

    def get_file_hash(self, file_path):
        block_size = 65536
        file_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            fb = f.read(block_size)
            while len(fb) > 0:
                file_hash.update(fb)
                fb = f.read(block_size)
        return file_hash.hexdigest()

    def assert_valid_output(self, input, output):
        # assert self.get_file_hash(input) == self.get_file_hash(output), 'Files are not identical!'
        if self.get_file_hash(input) == self.get_file_hash(output):
            return True
        return False

    def rsa_generating_key_pair(self):
        new_key = RSA.generate(4096, e=65537)
        private_key = new_key.exportKey("PEM")
        public_key = new_key.publickey().exportKey("PEM")
        return private_key, public_key

    def rsa_encrypt_blob(self, file_path, public_key_path, progress_bar):
        fd = open(public_key_path, "rb")
        public_key = fd.read()
        fd.close()
        fd = open(file_path, "rb")
        blob = fd.read()
        fd.close()
        rsa_key = RSA.importKey(public_key)
        rsa_key = PKCS1_OAEP.new(rsa_key)
        blob = zlib.compress(blob)
        file_to_encrypt_size = os.path.getsize(file_path)
        num_of_iteration = file_to_encrypt_size // 470 
        temp = num_of_iteration // 100 
        chunk_size = 470
        offset = 0
        end_loop = False
        encrypted =  "".encode()
        count = 0
        value = 1
        while not end_loop:
            count = count + 1
            if temp == 0 :
                progress_bar.setValue(100)
            else:
                if count % temp == 0:
                    progress_bar.setValue(value)
                    value = value + 1
            chunk = blob[offset:offset + chunk_size]
            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk += " ".encode() * (chunk_size - len(chunk))
            encrypted += rsa_key.encrypt(chunk)
            offset += chunk_size
        if progress_bar.value() < 100:
            progress_bar.setValue(100)
        return base64.b64encode(encrypted)

    def rsa_decrypt_blob(self, file_path, private_key_path, progress_bar):
        fd = open(private_key_path, "rb")
        private_key = fd.read()
        fd.close()
        fd = open(file_path, "rb")
        encrypted_blob = fd.read()
        fd.close()
        rsakey = RSA.importKey(private_key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted_blob = base64.b64decode(encrypted_blob)
        file_to_decrypt_size = os.path.getsize(file_path)
        num_of_iteration = file_to_decrypt_size // 512 
        temp = num_of_iteration // 100 
        chunk_size = 512
        offset = 0
        decrypted = "".encode()
        count = 0
        value = 1
        while offset < len(encrypted_blob):
            count = count + 1
            if temp == 0 :
                progress_bar.setValue(100)
            else:
                if count % temp == 0:
                    progress_bar.setValue(value)
                    value = value + 1
            chunk = encrypted_blob[offset: offset + chunk_size]
            decrypted += rsakey.decrypt(chunk)
            offset += chunk_size
        if progress_bar.value() < 100:
            progress_bar.setValue(100)
        return zlib.decompress(decrypted)

    def DES_Encryptor(self, file_path, key_path, password, progress_bar):
        encrypt_salt_location = key_path
        file_in = open(encrypt_salt_location, "rb") # Read bytes
        salt_from_file = file_in.read() # This key should be the same
        file_in.close()
        encrypt_key = PBKDF2(password, salt_from_file, dkLen=8) 
        file_to_encrypt = file_path
        file_to_encrypt_size = os.path.getsize(file_to_encrypt)
        buffer_size = 65536 # bytes =  64kb
        num_of_iteration = file_to_encrypt_size // buffer_size 
        temp = num_of_iteration // 100 
        input_file = open(file_to_encrypt, 'rb')
        output_file = open(file_to_encrypt + '.encrypted', 'wb' )
        cipher_encrypt = DES.new(encrypt_key, DES.MODE_OFB)
        output_file.write(cipher_encrypt.iv)
        buffer = input_file.read(buffer_size)
        count = 0
        value = 1
        while len(buffer) > 0:
            count = count + 1
            if temp == 0 :
                progress_bar.setValue(100)
            else:
                if count % temp == 0:
                    progress_bar.setValue(value)
                    value = value + 1
            ciphered_bytes = cipher_encrypt.encrypt(buffer)
            output_file.write(ciphered_bytes)
            buffer = input_file.read(buffer_size)
        input_file.close()
        output_file.close()
        # os.remove(file_to_encrypt)

    def DES_Decryptor(self, file_path, key_path, password, progress_bar):
        decrypt_salt_location = key_path
        file_in = open(decrypt_salt_location, "rb") # Read bytes
        salt_from_file = file_in.read() # This key should be the same
        file_in.close()
        file_to_decrypt = file_path
        decrypt_key = PBKDF2(password, salt_from_file, dkLen=8) 
        if False: # check whether the password is correct or not
            print('input wrong key, please try again later!')
            return 
        else:
            file_to_decrypt_size = os.path.getsize(file_to_decrypt)
            buffer_size = 65536 # 64kb
            num_of_iteration = file_to_decrypt_size // buffer_size 
            temp = num_of_iteration // 100 
            file_to_decrypt = file_path
            input_file = open(file_to_decrypt + '', 'rb')
            output_file = open(file_to_decrypt.replace('encrypted','') + 'decrypted', 'wb')
            iv = input_file.read(8)
            cipher_encrypt = DES.new(decrypt_key, DES.MODE_OFB, iv=iv)
            buffer = input_file.read(buffer_size)
            count = 0
            value = 1
            while len(buffer) > 0:
                count = count + 1
                if temp == 0 :
                    progress_bar.setValue(100)
                else:
                    if count % temp == 0:
                        progress_bar.setValue(value)
                        value = value + 1
                decrypted_bytes = cipher_encrypt.decrypt(buffer)
                output_file.write(decrypted_bytes)
                buffer = input_file.read(buffer_size)
            input_file.close()
            output_file.close()