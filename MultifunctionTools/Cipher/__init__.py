"""
This module is part of the "MultifunctionTools" module which belongs to "https://github.com/veHRz" and provides access to various functions to help cipher and decipher.
"""

from MultifunctionTools.Hash import * # Library from the TestCrypto module to help Hashing
from MultifunctionTools.Exceptions import * # Library from the TestCrypto module to use custom error

# Librairies for the normal Cipher and decipher
from Cryptodome.Cipher import AES
from Cryptodome import Random

# Libraries for simples other hash algos
from Cryptodome.Hash import SHA224
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import SHA384
from Cryptodome.Hash import SHA512
from Cryptodome.Hash import SHA3_224
from Cryptodome.Hash import SHA3_256
from Cryptodome.Hash import SHA3_384
from Cryptodome.Hash import SHA3_512
from Cryptodome.Hash import BLAKE2s
from Cryptodome.Hash import BLAKE2b
import random

# Libraries for the Advanced Cipher and Decipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

__SIMPLES_OTHER_HASH_ALGOS = [SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, BLAKE2s, BLAKE2b]
SIMPLES_OTHER_HASH_ALGOS = __SIMPLES_OTHER_HASH_ALGOS.copy()

def CipherStrToBytesWithHashOfPassword(stringToCipher: str, password: str | bytes, randomHashAlgoForPassword: bool = True) -> bytes:
    return __CipherToBytesWithHashOfPassword(stringToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword)

def CipherBytesToBytesWithHashOfPassword(bytesToCipher: bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> bytes:
    return __CipherToBytesWithHashOfPassword(bytesToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword)

def CipherStrToHexWithHashOfPassword(stringToCipher: str, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str:
    return __CipherToHexWithHashOfPassword(stringToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword)

def CipherBytesToHexWithHashOfPassword(bytesToCipher: bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str:
    return __CipherToHexWithHashOfPassword(bytesToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword)


def CipherStrToBytesWithPassword(stringToCipher: str, password: str | bytes) -> bytes:
    return __CipherToBytesWithPassword(stringToCipher, password)

def CipherBytesToBytesWithPassword(bytesToCipher: bytes, password: str | bytes) -> bytes:
    return __CipherToBytesWithPassword(bytesToCipher, password)

def CipherStrToHexWithPassword(stringToCipher: str, password: str | bytes) -> str:
    return __CipherToHexWithPassword(stringToCipher, password)

def CipherBytesToHexWithPassword(bytesToCipher: bytes, password: str | bytes) -> str:
    return __CipherToHexWithPassword(bytesToCipher, password)


def __CipherToBytesWithHashOfPassword(strOrBytesToCipher: str | bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> bytes:
    hashAlgo = SHA512
    if randomHashAlgoForPassword:
        hashAlgo = random.choice(__SIMPLES_OTHER_HASH_ALGOS)
    hashPassword = hashAlgo.new()
    if isinstance(password, str):
        password = password.encode("utf-8")
    hashPassword.update(password)
    return __CipherToBytesWithPassword(strOrBytesToCipher, hashPassword.hexdigest())

def __CipherToHexWithHashOfPassword(strOrBytesToCipher: str | bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str:
    return __CipherToBytesWithHashOfPassword(strOrBytesToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword).hex()

def __CipherToBytesWithPassword(strOrBytesToCipher: str | bytes, password: str | bytes) -> bytes:
    passwordHash = BasicHashToBytes(password, hashSize=32, useSha512ForSecurity=False)
    if isinstance(strOrBytesToCipher, str):
        strOrBytesToCipher = strOrBytesToCipher.encode("utf-8")
    stringIV = Random.new().read(AES.block_size)
    stringCipher = AES.new(passwordHash, AES.MODE_CBC, stringIV)
    stringPadding = AES.block_size - len(strOrBytesToCipher) % AES.block_size
    strOrBytesToCipher += bytes([stringPadding]) * stringPadding
    stringCiphered = stringIV + stringCipher.encrypt(strOrBytesToCipher)
    return stringCiphered

def __CipherToHexWithPassword(strOrBytesToCipher: str | bytes, password: str | bytes) -> str:
    return __CipherToBytesWithPassword(strOrBytesToCipher, password).hex()


def DecipherBytesWithPasswordHashed(bytesToDecipher: bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str | bytes:
    if randomHashAlgoForPassword:
        for hashAlgo in __SIMPLES_OTHER_HASH_ALGOS:
            hashPassword = hashAlgo.new()
            if isinstance(password, str):
                password = password.encode("utf-8")
            hashPassword.update(password)
            try:
                return DecipherBytesWithPassword(bytesToDecipher, hashPassword.hexdigest())
            except ValueError:
                pass
        raise BadPassword("Invalid password.")
    hashPassword = SHA512.new()
    hashPassword.update(password.encode("utf-8"))
    return DecipherBytesWithPassword(bytesToDecipher, hashPassword.hexdigest())

def DecipherHexWithPasswordHashed(hexToDecipher: str, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str | bytes:
    return DecipherBytesWithPasswordHashed(bytes().fromhex(hexToDecipher), password, randomHashAlgoForPassword=randomHashAlgoForPassword)

def DecipherBytesWithPassword(bytesToDecipher: bytes, password: str | bytes) -> str | bytes:
    passwordHash = BasicHashToBytes(password, hashSize=32, useSha512ForSecurity=False)
    bytesIV = bytesToDecipher[:AES.block_size]
    bytesDecipher = AES.new(passwordHash, AES.MODE_CBC, bytesIV)
    bytesDeciphered = bytesDecipher.decrypt(bytesToDecipher[AES.block_size:])
    bytesPadding = bytesDeciphered[-1]
    if bytesDeciphered[-bytesPadding:] != bytes([bytesPadding]) * bytesPadding:
        raise BadPassword("Invalid password.")
    try:
        return bytesDeciphered[:-bytesPadding].decode("utf-8")
    except UnicodeDecodeError:
        return bytesDeciphered[:-bytesPadding]

def DecipherHexWithPassword(hexToDecipher: str, password: str | bytes) -> str | bytes:
    return DecipherBytesWithPassword(bytes().fromhex(hexToDecipher), password)


def AdvancedCipherWithSaltPassword(message: str | bytes, password: str | bytes, saltPassword: str | bytes = b'salt_', *, ReturnTheEncryptTextAndTagAsASingleValue: bool = True, useThisCustomSeparatorBetweenCipherTextAndTag: bytes | str | None = None) -> bytes | tuple[bytes, bytes]:
    """
    This function allows you to cipher a string of characters or bytes with one or two passwords.
        - The salt password allows more security when ciphering.
        - You can not use the salt password but it will be set to b'salt' by default for everyone.
        - The program returns by default the ciphered message and the authentication tag combined in the ciphered message but you can set ReturnTheEncryptTextAndTagAsASingleValue to False to have the string and the tag separately.
        - You can choose the separator between the ciphered message and the authentication tag with useThisCustomSeparatorBetweenCipherTextAndTag which can have as value type a bytes or str. If set to None it will default to b'tag'. This only works if the ciphered message and the tag are together.

    :param message: The message to cipher. Should be bytes or str.
    :param password: The password to cipher the message. Should be bytes or str.
    :param saltPassword: A second password for added security. Default value : b'salt_'. Should be bytes or str.
    :param ReturnTheEncryptTextAndTagAsASingleValue: To return the ciphered message and the authentification tag in one bytes string otherwise the program returns them separated. Default value : True. Should be boolean.
    :param useThisCustomSeparatorBetweenCipherTextAndTag: To use a custom sweprator between ciphered message and authentification tag if put together. Default value : None (Use b'tag' by default). Should be bytes or str or None.
    :return: Returns the ciphered message and authentication tag.
    """
    backend = default_backend()
    if isinstance(message, str):
        message = message.encode("utf-8")
    elif not isinstance(message, bytes):
        raise TypeError('"message" should be of type bytes or str.')
    if isinstance(password, str):
        password = password.encode("utf-8")
    elif not isinstance(password, bytes):
        raise TypeError('"password" should be of type bytes or str.')
    if isinstance(saltPassword, str):
        saltPassword = saltPassword.encode("utf-8")
    elif not isinstance(saltPassword, bytes):
        raise TypeError('"saltPassword" should be of type bytes or str.')
    salt = saltPassword
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=backend
    )
    key = kdf.derive(password)
    iv = BasicHashBytesToBytes(password, 32, useSha512ForSecurity=True)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    if ReturnTheEncryptTextAndTagAsASingleValue:
        if useThisCustomSeparatorBetweenCipherTextAndTag is None:
            result = ciphertext + b"tag" + encryptor.tag
        else:
            if isinstance(useThisCustomSeparatorBetweenCipherTextAndTag, str):
                useThisCustomSeparatorBetweenCipherTextAndTag = useThisCustomSeparatorBetweenCipherTextAndTag.encode("utf-8")
            elif not isinstance(useThisCustomSeparatorBetweenCipherTextAndTag, bytes):
                raise TypeError('"useThisCustomSeparatorBetweenCipherTextAndTag" should be of type bytes or str.')
            if (useThisCustomSeparatorBetweenCipherTextAndTag in ciphertext) or (useThisCustomSeparatorBetweenCipherTextAndTag in encryptor.tag):
                raise BadSeparator('''The value of "useThisCustomSeparatorBetweenCipherTextAndTag" is invalid because it is in the ciphered message result or in the authentication tag. Please choose another separator.''')
            result = ciphertext + useThisCustomSeparatorBetweenCipherTextAndTag + encryptor.tag
        return result
    return ciphertext, encryptor.tag

def AdvancedDecipherWithSaltPassword(cipherMessage: bytes, password: str | bytes, saltPassword: str | bytes = b'salt_', *, tagIfTagNotWithCipherText: bytes | None = None, customSeparatorBetweenCipherTextAndTag: bytes | str | None = None) -> bytes | str:
    backend = default_backend()
    if not isinstance(cipherMessage, bytes):
        raise TypeError('"ciphertext" should be of type bytes.')
    if tagIfTagNotWithCipherText is None:
        if customSeparatorBetweenCipherTextAndTag is None:
            cipherMessage, tag = cipherMessage.split(b"tag")
        else:
            if isinstance(customSeparatorBetweenCipherTextAndTag, str):
                customSeparatorBetweenCipherTextAndTag = customSeparatorBetweenCipherTextAndTag.encode('utf-8')
            elif not isinstance(customSeparatorBetweenCipherTextAndTag, bytes):
                raise TypeError('"customSeparatorBetweenCipherTextAndTag" should be of type bytes or str or None.')
            cipherMessage, tag = cipherMessage.split(customSeparatorBetweenCipherTextAndTag)
    else:
        if not isinstance(tagIfTagNotWithCipherText, bytes):
            raise TypeError('"tagIfTagNotWithCipherText" should be of type bytes or None.')
        tag: bytes = tagIfTagNotWithCipherText
    if isinstance(password, str):
        password: bytes = password.encode("utf-8")
    elif not isinstance(password, bytes):
        raise TypeError('"password" should be of type bytes or str.')
    if isinstance(saltPassword, str):
        saltPassword: bytes = saltPassword.encode("utf-8")
    elif not isinstance(saltPassword, bytes):
        raise TypeError('"saltPassword" should be of type bytes or str.')
    salt = saltPassword
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=backend
    )
    key: bytes = kdf.derive(password)
    iv: bytes = BasicHashBytesToBytes(password, 32, useSha512ForSecurity=True)
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(cipherMessage) + decryptor.finalize()
    except (InvalidTag, ValueError):
        raise BadPassword("The password, salt password or tag is invalid and the text could not be decrypted.")
    try:
        return decrypted_message.decode("utf-8")
    except UnicodeDecodeError:
        return decrypted_message
