#!/usr/bin/env python

import argparse
import hashlib
import os

from getpass import getpass
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Initialize cli parser
parser = argparse.ArgumentParser()
# Optional args
## Input/output files
parser.add_argument('-i', '--inf', type=str, default='files/plain')
parser.add_argument('-o', '--outf',type=str, default='/tmp/pfc.out')
## Decrypt flag
parser.add_argument('-d', '--dec', type=bool, default=False)
## Console input
parser.add_argument('-t', '--text',type=bool, default=False)
args = parser.parse_args()

lenIV = 12
lenSalt = 32

def deriveKey(passphrase: str, salt: bytes=None) -> [str, bytes]:
	if salt is None:
		salt = os.urandom(lenSalt)
	
	return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1048576), salt

def encrypt(passphrase: str, plaintext: str) -> str:
	# Encode string to bytes
	plaintext = plaintext.encode("utf8")

	key, salt = deriveKey(passphrase)
	aes = AESGCM(key)
	iv = os.urandom(lenIV)
	ciphertext = aes.encrypt(iv, plaintext, None)

	# Return encrypted output in hexadecimal
	return "%s%s%s" % (hexlify(ciphertext).decode("utf8"), hexlify(iv).decode("utf8"), hexlify(salt).decode("utf8"))

def decrypt(passphrase: str, ciphertext: str) -> str:
	# Decode hexadecimals
	ciphertext = unhexlify(ciphertext)

	# Extract ciphertext body, IV, and salt
	lenData = len(ciphertext)
	salt = ciphertext[lenData - lenSalt:]
	iv = ciphertext[lenData - lenIV - lenSalt : lenData - lenSalt]
	ciphertext = ciphertext[:lenData - lenIV - lenSalt]

	key, _ = deriveKey(passphrase, salt)
	aes = AESGCM(key)
	plaintext = aes.decrypt(iv, ciphertext, None)

	return plaintext.decode("utf8")

if __name__ == '__main__':

	if os.path.isfile(args.inf):
		infile = open(args.inf, 'r+')
		indata = infile.read()
	elif args.text:
		indata = input("Enter plaintext to encrypt: ")
		printout = True
	else:
		print(f'File not found: {args.inf}')
		quit(1)

	# Decryption/encryption
	if args.dec:
		output = decrypt(getpass(), indata)
	else:
		output = encrypt(getpass(), indata)

	# Quit before writing out if -t
	if args.text:
		print(output)
		quit(0)
	elif os.path.isfile(args.outf):
		outfile = open(args.outf, 'w')
	else:
		outfile = open(args.outf, 'x')

	outfile.write(output)
