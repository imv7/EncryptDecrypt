from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os, sys, stat 

key = get_random_bytes(32) # Use a stored / generated key
key_slack_scan_file = 'key.bin'
my_protected_key = open(key_slack_scan_file, "wb")
my_protected_key.write(key)
my_protected_key.close()
os.chmod(key_slack_scan_file, stat.S_IREAD) 

file_to_encrypt = 'File.csv'
buffer_size = 65536 # 64kb

# === Encrypt ===

# Open the input and output files
input_file = open(file_to_encrypt, 'rb')
output_file = open('encrypted.' + file_to_encrypt, 'wb')

# Create the cipher object and encrypt the data
cipher_encrypt = AES.new(key, AES.MODE_CFB)

# Initially write the iv to the output file
output_file.write(cipher_encrypt.iv)

# Keep reading the file into the buffer, encrypting then writing to the new file
buffer = input_file.read(buffer_size)
while len(buffer) > 0:
    ciphered_bytes = cipher_encrypt.encrypt(buffer)
    output_file.write(ciphered_bytes)
    buffer = input_file.read(buffer_size)

# Close the input and output files
input_file.close()
output_file.close()
