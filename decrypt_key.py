import os, ast
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

def decrypt_key(file_name):
	with open("master_private.pem", "r") as keyfile:
		master = keyfile.read()
		keyfile.close()

	master_key = RSA.importKey(master)

	with open(file_name, "r") as keyfile:
		enc_key = keyfile.read()
		keyfile.close()

	dec_data = master_key.decrypt(enc_key)
	
	with open("output.txt", "w+") as keyfile:
		keyfile.write(dec_data)
		keyfile.close()
