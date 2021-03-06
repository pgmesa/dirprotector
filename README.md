## Directory Protector

Script to encrypt/decrypt files in a directory and (if specified) subdirectories.
It's a minimalistic tool with a simple CLI to allow the user encrypt ('lock' command) the 
files of a directory ('-r' flag to also encrypt subdirectories)
This module uses Fernet python module to encrypt (AES128 with HMAC256) and the PBKDF2HMAC with
SHA256 to derive the password for each file encryption.
It also allows to add a hint file in the process and to reencrypt the directory with the same 
credentials after an unlock, without having to manually lock it again.

### Commands:
    - lock ['-r'] ['-p=<password>'] ['-d=<path>] ['-h=<hint>'] ['-i=<iterations>']
    - unlock ['-p=<password>'] ['-d=<path>] ['-n']