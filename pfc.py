#!/usr/bin/env python

import argparse
import hashlib
import sys
import os

from getpass import getpass
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Initialize cli parser
parser = argparse.ArgumentParser()
# Input file
parser.add_argument('-i', '--inf', type=str, default='files/plain')
# Output file
parser.add_argument('-o', '--outf',type=str, default='/tmp/pfc.out')
# Decrypt flag
parser.add_argument('-d', '--dec', type=bool, default=False)
# Console input/output
parser.add_argument('-t', '--text',type=bool, default=False)
# Parse arguments
args = parser.parse_args()

lenIV = 12
lenSalt = 32

# deriveKey() derives random key from passphrase using PBKDF2
def deriveKey(passphrase: str, salt: bytes=None) -> [str, bytes]:
	if salt is None:
		salt = os.urandom(lenSalt)
	
	return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1048576), salt

# encrypt() encrypts string using AES256-GCM
def encrypt(passphrase: str, plaintext: str) -> str:
	# Encode string to bytes
	plaintext = plaintext.encode("utf8")

	key, salt = deriveKey(passphrase)
	aes = AESGCM(key)
	iv = os.urandom(lenIV)
	ciphertext = aes.encrypt(iv, plaintext, None)

	# Return encrypted output in hexadecimal string
	return "%s%s%s" % (hexlify(ciphertext).decode("utf8"), hexlify(iv).decode("utf8"), hexlify(salt).decode("utf8"))

# decrypt() decrypts AES256-GCM encrypted and hex-encoded string to plaintext string
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

	# Return decrypted output in string of UTF-8 characters
	return plaintext.decode("utf8")

if __name__ == '__main__':

	# Get input string
	if args.text:
		indata = input("Enter plaintext to encrypt/decrypt: ")
		printout = True
	elif os.path.isfile(args.inf):
		infile = open(args.inf, 'r+')
		indata = infile.read()
	else:
		print(f'File not found: {args.inf}')
		quit(1)

	# Decryption/encryption
	if args.dec:
		output = decrypt(getpass(), indata)
	else:
		output = encrypt(getpass(), indata)

	# Write output string to stdout
	if args.text:
		sys.stdout.write(output + '\n')
		quit(0)
	# Open file for writing
	elif os.path.isfile(args.outf):
		outfile = open(args.outf, 'w')
	# Create file for writing
	else:
		outfile = open(args.outf, 'x')

	# Write output to file opened/created
	outfile.write(output)
