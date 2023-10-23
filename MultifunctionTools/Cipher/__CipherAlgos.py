# Librairies for the normal Cipher and decipher
from Cryptodome.Cipher import AES
from Cryptodome import Random

# Libraries for the Advanced Cipher and Decipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
