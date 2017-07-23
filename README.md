# PyWare

## Server-less Ransomware PoC written in Python

This project started out as an AES and RSA encryption toolkit (See AES-CLI repository)

which quickly sparked my interest in ransomware and key encryption and management.

I wanted to try my hand at a pythonic ransomware proof-of-concept and wanted to see

if I could make it server less. Hope you enjoy


It's simple to setup and run:

Make your RSA master encryption keys (if you don't them already):

		python make_master.py

This saves your master keys in two files: master_private.pem and master_public.pem

Then you can run the main python program by:

		python pyware.py

This will make your local keys if you haven't already and produces two files:

		test.txt.enc and test.txt.dec

		NOTE: This will also encrypt and decrypt any text file you have inside this directory!

You can see the encrypted text file is unreadable and the decrypted file is back to normal
