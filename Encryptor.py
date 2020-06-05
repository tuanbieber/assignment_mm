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
        # get salt value from file
        encrypt_salt_location = key_path
        file_in = open(encrypt_salt_location, "rb") # Read bytes
        salt_from_file = file_in.read() # This key should be the same
        file_in.close()
        
        # Dùng PBKDF2 đê kết hợp file key và mật khẩu => tạo ra khóa mã hóa
        encrypt_key = PBKDF2(password, salt_from_file, dkLen=32) 

        file_to_encrypt = file_path

        # Kiểm tra kích thước tập tin
        file_to_encrypt_size = os.path.getsize(file_to_encrypt)

        buffer_size = 65536 # Tạo buffer

        # Đếm số vòng lặp
        num_of_iteration = file_to_encrypt_size // buffer_size 

        temp = num_of_iteration // 100 

        # Mở file vào và file ra
        input_file = open(file_to_encrypt, 'rb')
        output_file = open(file_to_encrypt + '.encrypted', 'wb' )

        # Tạo cipher object và bắt đầu mã hóa dữ liệu
        cipher_encrypt = AES.new(encrypt_key, AES.MODE_CFB)

        # Initially write the iv to the output file
        output_file.write(cipher_encrypt.iv)

        # Keep reading the file into the buffer, encrypting then writing to the new file
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

        # Close the input and output files
        input_file.close()
        output_file.close()
        # os.remove(file_to_encrypt)

    def AES_Decryptor(self, file_path, key_path, password, progress_bar):
        decrypt_salt_location = key_path
        file_in = open(decrypt_salt_location, "rb") # Read bytes
        salt_from_file = file_in.read() # This key should be the same
        file_in.close()

        file_to_decrypt = file_path

        # check if the key is valid
        decrypt_key = PBKDF2(password, salt_from_file, dkLen=32) 

        if False: # check whether the password is correct or not
            print('input wrong key, please try again later!')
            return 
        else:
            # get file size in bytes
            file_to_decrypt_size = os.path.getsize(file_to_decrypt)

            buffer_size = 65536 # 64kb

            # count iterations of the loop
            num_of_iteration = file_to_decrypt_size // buffer_size 

            temp = num_of_iteration // 100 

            file_to_decrypt = file_path
            input_file = open(file_to_decrypt + '', 'rb')
            output_file = open(file_to_decrypt.replace('encrypted','') + 'decrypted', 'wb')
            # Read in the iv
            iv = input_file.read(16)

            # Create the cipher object and encrypt the data
            cipher_encrypt = AES.new(decrypt_key, AES.MODE_CFB, iv=iv)
            # check whether the key is valid or not
            
            # Keep reading the file into the buffer, decrypting then writing to the new file
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

            # Close the input and output files
            input_file.close()
            output_file.close()

        # print('decryption process has finished !')

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
        #Generate a public/ private key pair using 4096 bits key length (512 bytes)
        new_key = RSA.generate(4096, e=65537)

        #The private key in PEM format
        private_key = new_key.exportKey("PEM")

        #The public key in PEM Format
        public_key = new_key.publickey().exportKey("PEM")
        
        return private_key, public_key

    def rsa_encrypt_blob(self, file_path, public_key_path, progress_bar):
        #Use the public key for encryption
        fd = open(public_key_path, "rb")
        public_key = fd.read()
        fd.close()

        #Our candidate file to be encrypted
        fd = open(file_path, "rb")
        blob = fd.read()
        fd.close()

        #Import the Public Key and use for encryption using PKCS1_OAEP
        rsa_key = RSA.importKey(public_key)
        rsa_key = PKCS1_OAEP.new(rsa_key)

        #compress the data first
        blob = zlib.compress(blob)

        # get file size in bytes
        file_to_encrypt_size = os.path.getsize(file_path)

        # count iterations of the loop
        num_of_iteration = file_to_encrypt_size // 470 

        temp = num_of_iteration // 100 

        #In determining the chunk size, determine the private key length used in bytes
        #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
        #in chunks
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

            #The chunk
            chunk = blob[offset:offset + chunk_size]

            #If the data chunk is less then the chunk size, then we need to add
            #padding with " ". This indicates the we reached the end of the file
            #so we end loop here
            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk += " ".encode() * (chunk_size - len(chunk))

            #Append the encrypted chunk to the overall encrypted file
            encrypted += rsa_key.encrypt(chunk)

            #Increase the offset by chunk size
            offset += chunk_size
        if progress_bar.value() < 100:
            progress_bar.setValue(100)
        #Base 64 encode the encrypted file
        return base64.b64encode(encrypted)

    def rsa_decrypt_blob(self, file_path, private_key_path, progress_bar):
        #Use the public key for encryption
        fd = open(private_key_path, "rb")
        private_key = fd.read()
        fd.close()

        #Our candidate file to be encrypted
        fd = open(file_path, "rb")
        encrypted_blob = fd.read()
        fd.close()

        #Import the Private Key and use for decryption using PKCS1_OAEP
        rsakey = RSA.importKey(private_key)
        rsakey = PKCS1_OAEP.new(rsakey)

        #Base 64 decode the data
        encrypted_blob = base64.b64decode(encrypted_blob)

        # get file size in bytes
        file_to_decrypt_size = os.path.getsize(file_path)

        # count iterations of the loop
        num_of_iteration = file_to_decrypt_size // 512 
        temp = num_of_iteration // 100 

        #In determining the chunk size, determine the private key length used in bytes.
        #The data will be in decrypted in chunks
        chunk_size = 512
        offset = 0
        decrypted = "".encode()

        count = 0
        value = 1

        #keep loop going as long as we have chunks to decrypt
        while offset < len(encrypted_blob):
            
            count = count + 1
            if temp == 0 :
                progress_bar.setValue(100)
            else:
                if count % temp == 0:
                    progress_bar.setValue(value)
                    value = value + 1

            #The chunk
            chunk = encrypted_blob[offset: offset + chunk_size]

            #Append the decrypted chunk to the overall decrypted file
            decrypted += rsakey.decrypt(chunk)

            #Increase the offset by chunk size
            offset += chunk_size

        if progress_bar.value() < 100:
            progress_bar.setValue(100)

        #return the decompressed decrypted data
        return zlib.decompress(decrypted)

    def DES_Encryptor(self, file_path, key_path, password, progress_bar):
        # get salt value from file
        encrypt_salt_location = key_path
        file_in = open(encrypt_salt_location, "rb") # Read bytes
        salt_from_file = file_in.read() # This key should be the same
        file_in.close()
        
        # Mã khóa
        encrypt_key = PBKDF2(password, salt_from_file, dkLen=8) 

        file_to_encrypt = file_path

        # Đọc kích thước tập tin cần mã hóa để đồng bộ với progress_bar
        file_to_encrypt_size = os.path.getsize(file_to_encrypt)

        buffer_size = 65536 # bytes =  64kb

        # Đếm số lần lặp cho progress_bar
        num_of_iteration = file_to_encrypt_size // buffer_size 

        temp = num_of_iteration // 100 

        # Mở file vào và file ra
        input_file = open(file_to_encrypt, 'rb')
        output_file = open(file_to_encrypt + '.encrypted', 'wb' )

        # Tạo cipher object và bắt đầu mã hóa dữ liệu
        cipher_encrypt = DES.new(encrypt_key, DES.MODE_OFB)

        # Initially write the iv to the output file
        output_file.write(cipher_encrypt.iv)

        # Keep reading the file into the buffer, encrypting then writing to the new file
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

        # Close the input and output files
        input_file.close()
        output_file.close()
        # os.remove(file_to_encrypt)

    def DES_Decryptor(self, file_path, key_path, password, progress_bar):
        decrypt_salt_location = key_path
        file_in = open(decrypt_salt_location, "rb") # Read bytes
        salt_from_file = file_in.read() # This key should be the same
        file_in.close()

        file_to_decrypt = file_path

        # check if the key is valid
        decrypt_key = PBKDF2(password, salt_from_file, dkLen=8) 

        if False: # check whether the password is correct or not
            print('input wrong key, please try again later!')
            return 
        else:
            # get file size in bytes
            file_to_decrypt_size = os.path.getsize(file_to_decrypt)

            buffer_size = 65536 # 64kb

            # count iterations of the loop
            num_of_iteration = file_to_decrypt_size // buffer_size 

            temp = num_of_iteration // 100 

            file_to_decrypt = file_path
            input_file = open(file_to_decrypt + '', 'rb')
            output_file = open(file_to_decrypt.replace('encrypted','') + 'decrypted', 'wb')

            # Read in the iv
            iv = input_file.read(8)

            # Create the cipher object and encrypt the data
            cipher_encrypt = DES.new(decrypt_key, DES.MODE_OFB, iv=iv)
            # check whether the key is valid or not
            
            # Keep reading the file into the buffer, decrypting then writing to the new file
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

            # Close the input and output files
            input_file.close()
            output_file.close()

        # print('decryption process has finished !')