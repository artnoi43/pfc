# pfc
pfc is a python clone for my [Go-based file encryption utility, gfc](https://github.com/artnoi43/gfc). It encrypts file using AES256-GCM, and encodes the output to hex.

For now, it only supports passphrase (hashed with PBKDF2 to produce encryption key), and hexadecimal output, but keyfile (256-bit, 32-byte) support and binary output are planned.

The AES256-GCM code (`deriveKey()`, `encrypt()`, `decrypt()`) is copied from this [source](https://gist.github.com/renesugar/d8ff6d7609e870d2de5d0d4eb5f9d135#file-aes-py).

## Dependency
Python standard library and common modules `cryptography` is required for pfc. 

## Usage

    usage: pfc.py [-h] [-i INF] [-o OUTF] [-d DEC]
    -h,
		--help show this help message and exit
	-i <string>
		--infile INF
	-o <string>
		--outfile OUTF
	-d <bool>
		--decrypt BOOL
	-t <bool>
		--text BOOL

> The decrypt and text flags can be in any form, numeric (0, 1), alphabet (T, t, F, f), or string (True, true, False, false).

To encrypt infile `mysecret.txt` to outfile `lol`:

    $ python pfc.py -i mysecret.txt -o lol;

To decrypt infile `lol` to outfile `out`:

    $ python pfc.py -d t -i lol -o out;

To encrypt/decrypt text from standard input, use `-t` (`--text`) flag:

    $ python pfc.py -t 1 -i lol -o out;
