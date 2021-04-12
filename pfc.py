import argparse
import hashlib
import os

from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

defInfile = 'files/plain'
defOutfile = 'files/secret'

# initialize cli parser
parser = argparse.ArgumentParser()

# optional args
parser.add_argument('-i', '--inf', type=str, default=defInfile)
parser.add_argument('-o', '--outf',type=str, default=defOutfile)
parser.add_argument('-d', '--dec', type=bool,default=False)

args = parser.parse_args()

def getPass() -> str:
	passphrase = (input('Enter passphrase: '))
	return str(passphrase)

# deriveKey(), encrypt(), and decrypt() are from https://gist.github.com/renesugar/d8ff6d7609e870d2de5d0d4eb5f9d135#file-aes-py

def deriveKey(passphrase: str, salt: bytes=None) -> [str, bytes]:
    if salt is None:
        salt = os.urandom(32)
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1048576), salt

def encrypt(passphrase: str, plaintext: str) -> str:
    key, salt = deriveKey(passphrase)
    aes = AESGCM(key)
    iv = os.urandom(12)
    plaintext = plaintext.encode("utf8")
    ciphertext = aes.encrypt(iv, plaintext, None)
    return "%s-%s-%s" % (hexlify(salt).decode("utf8"), hexlify(iv).decode("utf8"), hexlify(ciphertext).decode("utf8"))

def decrypt(passphrase: str, ciphertext: str) -> str:
    salt, iv, ciphertext = map(unhexlify, ciphertext.split("-"))
    key, _ = deriveKey(passphrase, salt)
    aes = AESGCM(key)
    plaintext = aes.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf8")

if __name__ == '__main__':

	if os.path.isfile(args.inf):
		infile = open(args.inf, 'r+')
		indata = infile.read()
	else:
		print(f'File not found: {args.inf}')
		quit(1)

	if args.dec:
		output = decrypt(getPass(), indata)
	else:
		output = encrypt(getPass(), indata)

	if os.path.isfile(args.outf):
		outfile = open(args.outf, 'w')
	else:
		outfile = open(args.outf, 'x')

	outfile.write(output)
