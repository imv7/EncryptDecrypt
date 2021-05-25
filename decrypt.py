from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === Decrypt ===
file_to_encrypt = 'File.csv'
buffer_size = 65536 # 64kb
key_slack_scan_file = 'key.bin'

# Open the input and output files
input_file = open('encrypted.' + file_to_encrypt , 'rb')
output_file = open('decrypted.' + file_to_encrypt , 'wb')
key_file = open(key_slack_scan_file, 'rb')

# Read in the iv
iv = input_file.read(16)
ik = key_file.read(32)

# Create the cipher object and encrypt the data
cipher_encrypt = AES.new(ik, AES.MODE_CFB, iv=iv)

# Keep reading the file into the buffer, decrypting then writing to the new file
buffer = input_file.read(buffer_size)
while len(buffer) > 0:
    decrypted_bytes = cipher_encrypt.decrypt(buffer)
    output_file.write(decrypted_bytes)
    buffer = input_file.read(buffer_size)

# Close the input and output files
input_file.close()
output_file.close()

# === Proving the data matches (hash the files and compare the hashes) ===
import hashlib

def get_file_hash(file_path):
    block_size = 65536
    file_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        fb = f.read(block_size)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(block_size)
    return file_hash.hexdigest()

assert get_file_hash(file_to_encrypt) == get_file_hash( 'decrypted.' + file_to_encrypt), 'Files are not identical'