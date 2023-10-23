from ..Hash import * # Library from the MultifunctionTools module to help Hashing
from ..Exceptions import * # Library from the MultifunctionTools module to use custom error
from .__CipherAlgos import *

__SIMPLES_OTHER_HASH_ALGOS = [SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, BLAKE2s, BLAKE2b]
SIMPLES_OTHER_HASH_ALGOS = __SIMPLES_OTHER_HASH_ALGOS.copy()

def BasicCipherToBytes(toCipher: str | bytes, password: str | bytes) -> bytes:
    """
    Encrypt a string / bytes with a password and return the result as bytes.

    This function takes a string and encrypts it using AES encryption with the provided password. The result is returned as bytes.

    :param toCipher: The string to be encrypted.
    :type toCipher: str | bytes
    :param password: The password used for encryption.
    :type password: str | bytes

    :return: The encrypted data as bytes.
    :rtype: bytes

    :raises TypeError: If toCipher or password is not one of the valid types.

    :examples:

    # Example usage with a string
    >>> result = BasicCipherToBytes("secret_message", "pass123")
    >>> print(result)  # The encrypted data as bytes
    """
    return __BasicCipherAlgo(toCipher, password)

def BasicCipherToHex(toCipher: str | bytes, password: str | bytes) -> str:
    """
    Encrypt a string / bytes with a password and return the result as a hexadecimal string.

    This function takes a string and encrypts it using AES encryption with the provided password. The result is returned as a hexadecimal string.

    :param toCipher: The string to be encrypted.
    :type toCipher: str | bytes
    :param password: The password used for encryption.
    :type password: str | bytes

    :return: The encrypted data as a hexadecimal string.
    :rtype: str

    :raises TypeError: If toCipher or password is not one of the valid types.

    :examples:

    # Example usage with a string
    >>> result = BasicCipherToHex("secret_message", "pass123")
    >>> print(result)  # The encrypted data as a hexadecimal string
    """
    return __BasicCipherAlgo(toCipher, password).hex()

def __BasicCipherAlgo(toCipher: str | bytes, password: str | bytes) -> bytes:
    """
    Encrypt a string or bytes with a password and return the result as bytes.

    This function takes a string or bytes and encrypts it using AES encryption with the provided password. The result is returned as bytes.

    This function is a function that is there to ensure the backward compatibility of the cipher algorithm.

    :param toCipher: The string or bytes to be encrypted.
    :type toCipher: str | bytes
    :param password: The password used for encryption.
    :type password: str | bytes

    :return: The encrypted data as bytes.
    :rtype: bytes

    :raises TypeError: If toCipher or password is not one of the valid types.
    """
    passwordHash = BasicHashToBytes(password, hashSize=32, useSha512ForSecurity=False)
    if isinstance(toCipher, str):
        toCipher = toCipher.encode("utf-8")
    stringIV = Random.new().read(AES.block_size)
    stringCipher = AES.new(passwordHash, AES.MODE_CBC, stringIV)
    stringPadding = AES.block_size - len(toCipher) % AES.block_size
    toCipher += bytes([stringPadding]) * stringPadding
    stringCiphered = stringIV + stringCipher.encrypt(toCipher)
    return stringCiphered

def BasicDecipherBytes(bytesToDecipher: bytes, password: str | bytes) -> str | bytes:
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
    >>> encrypted_bytes = BasicCipherToBytes('Hello, world!', 'my_secure_password')
    >>> decrypted_string = BasicDecipherBytes(encrypted_bytes, 'my_secure_password')
    >>> print(decrypted_string)
    'Hello, world!'
    """
    return __BasicDecipherAlgo(bytesToDecipher, password)

def BasicDecipherHex(hexToDecipher: str, password: str | bytes) -> str | bytes:
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
    >>> encrypted_hex = BasicCipherToHex('Hello, world!', 'my_secure_password')
    >>> decrypted_string = BasicDecipherHex(encrypted_hex, 'my_secure_password')
    >>> print(decrypted_string)
    'Hello, world!'
    """
    return __BasicDecipherAlgo(hexToDecipher, password)

def __BasicDecipherAlgo(toDecipher: bytes | str, password: str | bytes) -> str | bytes:
    """
    Decrypt encrypted bytes / hex string using AES encryption with a password and return the result as a string.

    This function decrypts the input encrypted bytes / hex string using the AES encryption algorithm in Cipher Block Chaining (CBC) mode with the provided password. The result is returned as a string.

    This function is a function that is there to ensure the backward compatibility of the decipher algorithm.

    :param toDecipher: The encrypted bytes / hex string to be decrypted.
    :type toDecipher: bytes | str
    :param password: The password used for decryption.
    :type password: str or bytes

    :return: A string representing the decrypted data.

    :raises TypeError: If toDecipher or password is not of the correct type.
    :raises BadPassword: If the provided password is invalid or decryption fails.
    """
    if isinstance(toDecipher, str):
        toDecipher = bytes.fromhex(toDecipher)
    passwordHash = BasicHashToBytes(password, hashSize=32, useSha512ForSecurity=False)
    bytesIV = toDecipher[:AES.block_size]
    bytesDecipher = AES.new(passwordHash, AES.MODE_CBC, bytesIV)
    bytesDeciphered = bytesDecipher.decrypt(toDecipher[AES.block_size:])
    bytesPadding = bytesDeciphered[-1]
    if bytesDeciphered[-bytesPadding:] != bytes([bytesPadding]) * bytesPadding:
        raise BadPassword("Invalid password.")
    try:
        return bytesDeciphered[:-bytesPadding].decode("utf-8")
    except UnicodeDecodeError:
        return bytesDeciphered[:-bytesPadding]
