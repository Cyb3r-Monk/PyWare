#Python 2.7
import os
import base64
import ast
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from make_keys import *
from decrypt_key import decrypt_key

#Check if the local private_key exists in order to decrypt the files. if not, exit.
if os.path.exists("private_key.pem") and os.path.getsize("private_key.pem") > 0:
	pass
else:
	print "[*] Private key not found. exiting "
	exit()

#load private key for decrypting the files
with open("private_key.pem", "r") as keyfile:
	local_private = keyfile.read()
	keyfile.close()

local_private_key = RSA.importKey(local_private)


def pad(data):
	return data + b"\0" * (AES.block_size - len(data) % AES.block_size)


def decrypt(plaintext, key):
	iv = plaintext[:AES.block_size]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(plaintext[AES.block_size:])
	return plaintext.rstrip(b"\0")


def decrypt_file(file_name, decrypted_key):
	with open(file_name, 'r') as encrypted_file:
		encrypted_file_content = encrypted_file.read().split("\n")
		cipher_text = encrypted_file_content[1]
		cipher = pad(cipher_text)
		encrypted_file.close()
	crypt = decrypt(cipher, decrypted_key)
	split = crypt.split("\n")
	text = split[0]
	with open(file_name[:-4] + ".dec", 'w') as decrypted_file:
		decrypted_file.write(text + "\n")


def main():
	option = raw_input("Do you want to decrypt your file? [Y/N]: ")
	if option == "Y" or "y":
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
			#get encrypted_key from the first line of the file content
			encrypted_key = ast.literal_eval(file_contents[0])
			decrypted_key = local_private_key.decrypt(encrypted_key).rstrip(b"\0")
			decrypt_file(files, decrypted_key)
		print "[!] Decryption complete"
	else:
		print "decryption aborted"
		exit()

if __name__ == "__main__":
	main()
