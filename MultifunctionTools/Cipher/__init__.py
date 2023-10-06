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
    """
    Encrypt a string with a hashed password and return the result as bytes.

    This function takes a string and encrypts it using AES encryption with a hashed version of the provided password. The hashing algorithm used for password hashing can be chosen randomly or specified explicitly.

    :param stringToCipher: The string to be encrypted.
    :type stringToCipher: str
    :param password: The password used for encryption.
    :type password: str | bytes
    :param randomHashAlgoForPassword: Whether to use a random hash algorithm for password hashing. Defaults to True.
    :type randomHashAlgoForPassword: bool

    :return: The encrypted data as bytes.
    :rtype: bytes

    :raises TypeError: If stringToCipher or password is not one of the valid types.

    :examples:

    # Example usage with a string and random hash algorithm
    >>> result = CipherStrToBytesWithHashOfPassword("secret_message", "pass123", randomHashAlgoForPassword=True)
    >>> print(result)  # The encrypted data as bytes with random hash algorithm

    # Example usage with a string and specified hash algorithm
    >>> result = CipherStrToBytesWithHashOfPassword("secret_message", b"pass123", randomHashAlgoForPassword=False)
    >>> print(result)  # The encrypted data as bytes with specified hash algorithm
    """
    return __CipherToBytesWithHashOfPassword(stringToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword)

def CipherBytesToBytesWithHashOfPassword(bytesToCipher: bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> bytes:
    """
    Encrypt bytes with a hashed password and return the result as bytes.

    This function takes bytes and encrypts them using AES encryption with a hashed version of the provided password. The hashing algorithm used for password hashing can be chosen randomly or specified explicitly.

    :param bytesToCipher: The bytes to be encrypted.
    :type bytesToCipher: bytes
    :param password: The password used for encryption.
    :type password: str | bytes
    :param randomHashAlgoForPassword: Whether to use a random hash algorithm for password hashing. Defaults to True.
    :type randomHashAlgoForPassword: bool

    :return: The encrypted data as bytes.
    :rtype: bytes

    :raises TypeError: If bytesToCipher or password is not one of the valid types.

    :examples:

    # Example usage with bytes and random hash algorithm
    >>> result = CipherBytesToBytesWithHashOfPassword(b"binary_data", "secret_key", randomHashAlgoForPassword=True)
    >>> print(result)  # The encrypted data as bytes with random hash algorithm

    # Example usage with bytes and specified hash algorithm
    >>> result = CipherBytesToBytesWithHashOfPassword(b"binary_data", b"secret_key", randomHashAlgoForPassword=False)
    >>> print(result)  # The encrypted data as bytes with specified hash algorithm
    """
    return __CipherToBytesWithHashOfPassword(bytesToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword)

def CipherStrToHexWithHashOfPassword(stringToCipher: str, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str:
    """
    Encrypt a string with a hashed password and return the result as a hexadecimal string.

    This function takes a string and encrypts it using AES encryption with a hashed version of the provided password. The hashing algorithm used for password hashing can be chosen randomly or specified explicitly.

    :param stringToCipher: The string to be encrypted.
    :type stringToCipher: str
    :param password: The password used for encryption.
    :type password: str | bytes
    :param randomHashAlgoForPassword: Whether to use a random hash algorithm for password hashing. Defaults to True.
    :type randomHashAlgoForPassword: bool

    :return: The encrypted data as a hexadecimal string.
    :rtype: str

    :raises TypeError: If stringToCipher or password is not one of the valid types.

    :examples:

    # Example usage with a string and random hash algorithm
    >>> result = CipherStrToHexWithHashOfPassword("secret_message", "pass123", randomHashAlgoForPassword=True)
    >>> print(result)  # The encrypted data as a hexadecimal string with random hash algorithm

    # Example usage with a string and specified hash algorithm
    >>> result = CipherStrToHexWithHashOfPassword("secret_message", b"pass123", randomHashAlgoForPassword=False)
    >>> print(result)  # The encrypted data as a hexadecimal string with specified hash algorithm
    """
    return __CipherToHexWithHashOfPassword(stringToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword)

def CipherBytesToHexWithHashOfPassword(bytesToCipher: bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str:
    """
    Encrypt bytes with a hashed password and return the result as a hexadecimal string.

    This function takes bytes and encrypts them using AES encryption with a hashed version of the provided password. The hashing algorithm used for password hashing can be chosen randomly or specified explicitly.

    :param bytesToCipher: The bytes to be encrypted.
    :type bytesToCipher: bytes
    :param password: The password used for encryption.
    :type password: str | bytes
    :param randomHashAlgoForPassword: Whether to use a random hash algorithm for password hashing. Defaults to True.
    :type randomHashAlgoForPassword: bool

    :return: The encrypted data as a hexadecimal string.
    :rtype: str

    :raises TypeError: If bytesToCipher or password is not one of the valid types.

    :examples:

    # Example usage with bytes and random hash algorithm
    >>> result = CipherBytesToHexWithHashOfPassword(b"binary_data", "secret_key", randomHashAlgoForPassword=True)
    >>> print(result)  # The encrypted data as a hexadecimal string with random hash algorithm

    # Example usage with bytes and specified hash algorithm
    >>> result = CipherBytesToHexWithHashOfPassword(b"binary_data", b"secret_key", randomHashAlgoForPassword=False)
    >>> print(result)  # The encrypted data as a hexadecimal string with specified hash algorithm
    """
    return __CipherToHexWithHashOfPassword(bytesToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword)


def CipherStrToBytesWithPassword(stringToCipher: str, password: str | bytes) -> bytes:
    """
    Encrypt a string with a password and return the result as bytes.

    This function takes a string and encrypts it using AES encryption with the provided password. The result is returned as bytes.

    :param stringToCipher: The string to be encrypted.
    :type stringToCipher: str
    :param password: The password used for encryption.
    :type password: str | bytes

    :return: The encrypted data as bytes.
    :rtype: bytes

    :raises TypeError: If stringToCipher or password is not one of the valid types.

    :examples:

    # Example usage with a string
    >>> result = CipherStrToBytesWithPassword("secret_message", "pass123")
    >>> print(result)  # The encrypted data as bytes
    """
    return __CipherToBytesWithPassword(stringToCipher, password)

def CipherBytesToBytesWithPassword(bytesToCipher: bytes, password: str | bytes) -> bytes:
    """
    Encrypt bytes with a password and return the result as bytes.

    This function takes bytes and encrypts them using AES encryption with the provided password. The result is returned as bytes.

    :param bytesToCipher: The bytes to be encrypted.
    :type bytesToCipher: bytes
    :param password: The password used for encryption.
    :type password: str | bytes

    :return: The encrypted data as bytes.
    :rtype: bytes

    :raises TypeError: If bytesToCipher or password is not one of the valid types.

    :examples:

    # Example usage with bytes
    >>> result = CipherBytesToBytesWithPassword(b"binary_data", "secret_password")
    >>> print(result)  # The encrypted data as bytes
    """
    return __CipherToBytesWithPassword(bytesToCipher, password)

def CipherStrToHexWithPassword(stringToCipher: str, password: str | bytes) -> str:
    """
    Encrypt a string with a password and return the result as a hexadecimal string.

    This function takes a string and encrypts it using AES encryption with the provided password. The result is returned as a hexadecimal string.

    :param stringToCipher: The string to be encrypted.
    :type stringToCipher: str
    :param password: The password used for encryption.
    :type password: str | bytes

    :return: The encrypted data as a hexadecimal string.
    :rtype: str

    :raises TypeError: If stringToCipher or password is not one of the valid types.

    :examples:

    # Example usage with a string
    >>> result = CipherStrToHexWithPassword("secret_message", "pass123")
    >>> print(result)  # The encrypted data as a hexadecimal string
    """
    return __CipherToHexWithPassword(stringToCipher, password)

def CipherBytesToHexWithPassword(bytesToCipher: bytes, password: str | bytes) -> str:
    """
    Encrypt bytes with a password and return the result as a hexadecimal string.

    This function takes bytes and encrypts them using AES encryption with the provided password. The result is returned as a hexadecimal string.

    :param bytesToCipher: The bytes to be encrypted.
    :type bytesToCipher: bytes
    :param password: The password used for encryption.
    :type password: str | bytes

    :return: The encrypted data as a hexadecimal string.
    :rtype: str

    :raises TypeError: If bytesToCipher or password is not one of the valid types.

    :examples:

    # Example usage with bytes
    >>> result = CipherBytesToHexWithPassword(b"binary_data", "secret_password")
    >>> print(result)  # The encrypted data as a hexadecimal string
    """
    return __CipherToHexWithPassword(bytesToCipher, password)


def __CipherToBytesWithHashOfPassword(strOrBytesToCipher: str | bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> bytes:
    """
    Encrypt a string or bytes with a hashed password and return the result as bytes.

    This function takes a string or bytes and encrypts it using AES encryption with a hashed version of the provided password. The hashing algorithm used for password hashing can be chosen randomly or specified explicitly.

    This function is a function that is there to ensure the backward compatibility of the "CipherStrToBytesWithHashOfPassword()" and "CipherBytesToBytesWithHashOfPassword()" functions.

    :param strOrBytesToCipher: The string or bytes to be encrypted.
    :type strOrBytesToCipher: str | bytes
    :param password: The password used for encryption.
    :type password: str | bytes
    :param randomHashAlgoForPassword: Whether to use a random hash algorithm for password hashing. Defaults to True.
    :type randomHashAlgoForPassword: bool

    :return: The encrypted data as bytes.
    :rtype: bytes

    :raises TypeError: If strOrBytesToCipher or password is not one of the valid types.
    """
    hashAlgo = SHA512
    if randomHashAlgoForPassword:
        hashAlgo = random.choice(__SIMPLES_OTHER_HASH_ALGOS)
    hashPassword = hashAlgo.new()
    if isinstance(password, str):
        password = password.encode("utf-8")
    hashPassword.update(password)
    return __CipherToBytesWithPassword(strOrBytesToCipher, hashPassword.hexdigest())

def __CipherToHexWithHashOfPassword(strOrBytesToCipher: str | bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str:
    """
    Encrypt a string or bytes with a hashed password and return the result as a hexadecimal string.

    This function takes a string or bytes and encrypts it using AES encryption with a hashed version of the provided password. The result is returned as a hexadecimal string.

    This function is a function that is there to ensure the backward compatibility of the "CipherStrToHexWithHashOfPassword()" and "CipherBytesToHexWithHashOfPassword()" functions.

    :param strOrBytesToCipher: The string or bytes to be encrypted.
    :type strOrBytesToCipher: str | bytes
    :param password: The password used for encryption.
    :type password: str | bytes
    :param randomHashAlgoForPassword: Whether to use a random hash algorithm for password hashing. Defaults to True.
    :type randomHashAlgoForPassword: bool

    :return: The encrypted data as a hexadecimal string.
    :rtype: str

    :raises TypeError: If strOrBytesToCipher or password is not one of the valid types.
    """
    return __CipherToBytesWithHashOfPassword(strOrBytesToCipher, password, randomHashAlgoForPassword=randomHashAlgoForPassword).hex()

def __CipherToBytesWithPassword(strOrBytesToCipher: str | bytes, password: str | bytes) -> bytes:
    """
    Encrypt a string or bytes with a password and return the result as bytes.

    This function takes a string or bytes and encrypts it using AES encryption with the provided password. The result is returned as bytes.

    This function is a function that is there to ensure the backward compatibility of the "CipherStrToBytesWithPassword()" and "CipherBytesToBytesWithPassword()" functions.

    :param strOrBytesToCipher: The string or bytes to be encrypted.
    :type strOrBytesToCipher: str | bytes
    :param password: The password used for encryption.
    :type password: str | bytes

    :return: The encrypted data as bytes.
    :rtype: bytes

    :raises TypeError: If strOrBytesToCipher or password is not one of the valid types.
    """
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
    """
    Encrypt a string or bytes using AES encryption with a password and return the result as a hexadecimal string.

    This function encrypts the input string or bytes using the AES encryption algorithm in Cipher Block Chaining (CBC) mode with the provided password. The result is returned as a hexadecimal string.

    This function is a function that is there to ensure the backward compatibility of the "CipherStrToHexWithPassword()" and "CipherBytesToHexWithPassword()" functions.

    :param strOrBytesToCipher: The string or bytes to be encrypted.
    :type strOrBytesToCipher: str or bytes
    :param password: The password used for encryption.
    :type password: str or bytes

    :return: A hexadecimal string representing the encrypted data.

    :raises TypeError: If strOrBytesToCipher or password is not of the correct type.
    """
    return __CipherToBytesWithPassword(strOrBytesToCipher, password).hex()


def DecipherBytesWithPasswordHashed(bytesToDecipher: bytes, password: str | bytes, randomHashAlgoForPassword: bool = True) -> str | bytes:
    """
    Decrypt encrypted bytes using AES encryption with a hashed password and return the result as a string.

    This function decrypts the input encrypted bytes using the AES encryption algorithm in Cipher Block Chaining (CBC) mode with a hashed password.
    The hashed password is generated using the specified hashing algorithm or a randomly chosen one if 'randomHashAlgoForPassword' is set to True.
    The result is returned as a string.

    :param bytesToDecipher: The encrypted bytes to be decrypted.
    :type bytesToDecipher: bytes
    :param password: The password used for decryption, which is hashed before decryption.
    :type password: str or bytes
    :param randomHashAlgoForPassword: If True, a random hashing algorithm is used for password hashing; otherwise, SHA512 is used. Default is True.
    :type randomHashAlgoForPassword: bool

    :return: A string representing the decrypted data.

    :raises TypeError: If bytesToDecipher or password is not of the correct type.
    :raises BadPassword: If the provided password is invalid or decryption fails.

    :examples:

    # Example usage to decrypt encrypted bytes with a hashed password and obtain the original string
    >>> encrypted_bytes = CipherStrToBytesWithHashOfPassword('Hello, world!', 'my_secure_password')
    >>> decrypted_string = DecipherBytesWithPasswordHashed(encrypted_bytes, 'my_secure_password')
    >>> print(decrypted_string)
    'Hello, world!'
    """
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
    """
    Decrypt a hexadecimal string using AES encryption with a hashed password and return the result as a string.

    This function decrypts the input hexadecimal string by converting it to bytes and then using the AES encryption algorithm in Cipher Block Chaining (CBC) mode with a hashed password.
    The hashed password is generated using the specified hashing algorithm or a randomly chosen one if 'randomHashAlgoForPassword' is set to True.
    The result is returned as a string.

    :param hexToDecipher: The hexadecimal string to be decrypted.
    :type hexToDecipher: str
    :param password: The password used for decryption, which is hashed before decryption.
    :type password: str or bytes
    :param randomHashAlgoForPassword: If True, a random hashing algorithm is used for password hashing; otherwise, SHA512 is used. Default is True.
    :type randomHashAlgoForPassword: bool

    :return: A string representing the decrypted data.

    :raises TypeError: If hexToDecipher or password is not of the correct type.
    :raises ValueError: If the input hexadecimal string is not valid.
    :raises BadPassword: If the provided password is invalid or decryption fails.

    :examples:

    # Example usage to decrypt a hexadecimal string with a hashed password and obtain the original string
    >>> encrypted_hex = CipherStrToHexWithHashOfPassword('Hello, world!', 'my_secure_password')
    >>> decrypted_string = DecipherHexWithPasswordHashed(encrypted_hex, 'my_secure_password')
    >>> print(decrypted_string)
    'Hello, world!'
    """
    return DecipherBytesWithPasswordHashed(bytes().fromhex(hexToDecipher), password, randomHashAlgoForPassword=randomHashAlgoForPassword)

def DecipherBytesWithPassword(bytesToDecipher: bytes, password: str | bytes) -> str | bytes:
    """
    Decrypt encrypted bytes using AES encryption with a password and return the result as a string.

    This function decrypts the input encrypted bytes using the AES encryption algorithm in Cipher Block Chaining (CBC) mode with the provided password. The result is returned as a string.

    :param bytesToDecipher: The encrypted bytes to be decrypted.
    :type bytesToDecipher: bytes
    :param password: The password used for decryption.
    :type password: str or bytes

    :return: A string representing the decrypted data.

    :raises TypeError: If bytesToDecipher or password is not of the correct type.
    :raises BadPassword: If the provided password is invalid or decryption fails.

    :examples:

    # Example usage to decrypt encrypted bytes with a password and obtain the original string
    >>> encrypted_bytes = CipherStrToBytesWithHashOfPassword('Hello, world!', 'my_secure_password')
    >>> decrypted_string = DecipherBytesWithPassword(encrypted_bytes, 'my_secure_password')
    >>> print(decrypted_string)
    'Hello, world!'
    """
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
    """
    Decrypt a hexadecimal string using AES encryption with a password and return the result as a string.

    This function decrypts the input hexadecimal string by converting it to bytes and then using the AES encryption algorithm in Cipher Block Chaining (CBC) mode with the provided password.
    The result is returned as a string.

    :param hexToDecipher: The hexadecimal string to be decrypted.
    :type hexToDecipher: str
    :param password: The password used for decryption.
    :type password: str or bytes

    :return: A string representing the decrypted data.

    :raises TypeError: If hexToDecipher or password is not of the correct type.
    :raises ValueError: If the input hexadecimal string is not valid.
    :raises BadPassword: If the provided password is invalid or decryption fails.

    :examples:

    # Example usage to decrypt a hexadecimal string with a password and obtain the original string
    >>> encrypted_hex = CipherStrToHexWithHashOfPassword('Hello, world!', 'my_secure_password')
    >>> decrypted_string = DecipherHexWithPassword(encrypted_hex, 'my_secure_password')
    >>> print(decrypted_string)
    'Hello, world!'
    """
    return DecipherBytesWithPassword(bytes().fromhex(hexToDecipher), password)


def AdvancedCipherWithSaltPassword(message: str | bytes, password: str | bytes, saltPassword: str | bytes = b'salt_', *, ReturnTheEncryptTextAndTagAsASingleValue: bool = True, useThisCustomSeparatorBetweenCipherTextAndTag: bytes | str | None = None) -> bytes | tuple[bytes, bytes]:
    """
    Cipher a string of characters or bytes with one or two passwords, providing additional security with a salt password.

    This function allows you to cipher a string of characters or bytes with one or two passwords:
    - The salt password allows for more security when ciphering.
    - The salt password is set to b'salt_' by default.
    - By default, the function returns the ciphered message and the authentication tag combined in a single bytes string. You can change this behavior by setting ReturnTheEncryptTextAndTagAsASingleValue to False to receive the ciphered message and tag separately.
    - You can specify a custom separator between the ciphered message and the authentication tag using useThisCustomSeparatorBetweenCipherTextAndTag. If set to None, it defaults to b'tag'. This option only applies when the ciphered message and the tag are combined.

    :param message: The message to cipher. Should be bytes or str.
    :param password: The password to cipher the message. Should be bytes or str.
    :param saltPassword: A second password for added security. Default value: b'salt_'. Should be bytes or str.
    :param ReturnTheEncryptTextAndTagAsASingleValue: Return the ciphered message and authentication tag as a single bytes string if True, or separately if False. Default value: True. Should be boolean.
    :param useThisCustomSeparatorBetweenCipherTextAndTag: Use a custom separator between the ciphered message and authentication tag if they are combined. Default value: None (Use b'tag' by default). Should be bytes, str, or None.

    :return: Returns the ciphered message and authentication tag.

    :raises TypeError: If message, password, or saltPassword is not of the correct type.
    :raises BadSeparator: If the custom separator is invalid because it exists in the ciphered message or authentication tag.

    :examples:

    # Example usage to cipher a message with a password and salt password
    >>> ciphered_data = AdvancedCipherWithSaltPassword('Hello, world!', 'my_secure_password', 'additional_salt')
    >>> print(ciphered_data)
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
    """
    Decipher a ciphered message with one or two passwords, and an optional tag.

    This function allows you to decipher a ciphered message with one or two passwords:
    - The salt password is used for added security.
    - The salt password is set to b'salt_' by default.
    - If the tag is not included with the ciphered message, you can provide it separately using the tagIfTagNotWithCipherText parameter.
    - You can specify a custom separator between the ciphered message and the tag using customSeparatorBetweenCipherTextAndTag.

    :param cipherMessage: The ciphered message to decipher. Should be bytes.
    :param password: The password to decipher the message. Should be bytes or str.
    :param saltPassword: A second password for added security. Default value: b'salt_'. Should be bytes or str.
    :param tagIfTagNotWithCipherText: The authentication tag if it's not included with the ciphered message. Should be bytes or None.
    :param customSeparatorBetweenCipherTextAndTag: Use a custom separator between the ciphered message and authentication tag. Default value: None (Use b"tag" by default). Should be bytes, str, or None.

    :return: Returns the deciphered message.

    :raises TypeError: If cipherMessage, password, saltPassword, or tagIfTagNotWithCipherText is not of the correct type.
    :raises BadPassword: If the password, salt password, or tag is invalid and the text could not be decrypted.

    :examples:

    # Example usage to decipher a ciphered message with a password and optional tag
    >>> ciphered_data = AdvancedCipherWithSaltPassword('Hello, world!', 'my_secure_password', 'additional_salt')
    >>> deciphered_data = AdvancedDecipherWithSaltPassword(ciphered_data, 'my_secure_password', 'additional_salt')
    >>> print(deciphered_data)
    'Hello, world!'
    """
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
