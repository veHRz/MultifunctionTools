"""
This module is part of the "TestCrypto" module which belongs to "https://github.com/veHRz" and provides access to various functions to help hashing.
"""

from Crypto.Hash import SHA3_512
from functools import lru_cache

__BASIC_HASHING_CHARS = """azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN0123456789@#&_-!?=+*%~"""
BASIC_HASHING_CHARS = __BASIC_HASHING_CHARS
BASIC_HASHING_VALIDS_TYPES = [str, bytes]


def __BasicHashVerifyChars() -> None:
    """
    Just a function that checks that all the character for the hash are encoded on one byte (which allows to return the same number of bytes as number of letters when using the hash functions).
    """
    for char in __BASIC_HASHING_CHARS:
        if len(char.encode("utf-8")) > 1:
            raise ValueError(f"The character {char} is not valid because it is encoded on more than 1 byte.")


def BasicHashStrToHex(stringToHash: str, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    This function is used to hash a character string and return a hexadecimal string of the desired size.
    :param stringToHash: The string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a hexadecimal string.
    :rtype: str
    """
    return __BasicHashToHex(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)

def BasicHashBytesToHex(bytesToHash: bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    This function is used to hash a bytes string and return a hexadecimal string of the desired size.
    :param bytesToHash: The bytes string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a hexadecimal string.
    :rtype: str
    """
    return __BasicHashToHex(bytesToHash.hex(), hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)

def BasicHashStrToBytes(stringToHash: str, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> bytes:
    """
    This function is used to hash a character string and return a bytes string of the desired size.
    :param stringToHash: The string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a bytes string.
    :rtype: bytes
    """
    return __BasicHashToBytes(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)

def BasicHashBytesToBytes(bytesToHash: bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> bytes:
    """
    This function is used to hash a bytes string and return a bytes string of the desired size.
    :param bytesToHash: The bytes string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a bytes string.
    :rtype: bytes
    """
    return __BasicHashToBytes(bytesToHash.hex(), hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)

def BasicHashStrToStr(stringToHash: str, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    This function is used to hash a character string and return a character string of the desired size.
    :param stringToHash: The string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a character string.
    :rtype: str
    """
    return __BasicHashToStr(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)


def BasicHashBytesToStr(bytesToHash: bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    This function is used to hash a bytes string and return a character string of the desired size.
    :param bytesToHash: The bytes string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a character string.
    :rtype: str
    """
    return __BasicHashToStr(bytesToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)


def BasicHashToHex(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    This function is used to hash a character | bytes string to return a hexadecimal string of the desired size.
    :param stringToHash: The character | bytes string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a hexadecimal string.
    :rtype: str
    """
    return __BasicHashToHex(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)

def BasicHashToBytes(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> bytes:
    """
    This function is used to hash a character | bytes string to return a bytes string of the desired size.
    :param stringToHash: The character | bytes string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a bytes string.
    :rtype: bytes
    """
    return __BasicHashToBytes(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)

def BasicHashToStr(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    This function is used to hash a character | bytes string to return a character string of the desired size.
    :param stringToHash: The character | bytes string to hash.
    :param hashSize: The hash size.
    :param useSha512ForSecurity: Use this to hash the string at the beginning with the SHA512 algorithm. Use this for added security.
    :return: Returns the hash as a character string.
    :rtype: str
    """
    return __BasicHashToStr(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity)


@lru_cache()
def __BasicHashToHex(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    This function is a function that is there to be able to ensure the backward compatibility of the "BasicHashToHex()" function.
    """
    __result = __BasicHashToBytes(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity).hex()
    __intToHex = {0: "0", 1: "1", 2: "2", 3: "3", 4: "4", 5: "5", 6: "6", 7: "7", 8: "8", 9: "9", 10: "a", 11: "b", 12: "c", 13: "d", 14: "e", 15: "f"}
    __hexToInt = {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9, "a": 10, "b": 11, "c": 12, "d": 13, "e": 14, "f": 15}
    __realResult = ""
    for i in range(len(__result)):
        __previous = __hexToInt[__result[i-1]]
        __current = __hexToInt[__result[i]]
        if i == len(__result)-1:
            __next = __hexToInt[__result[0]]
        else:
            __next = __hexToInt[__result[i+1]]
        __realResult += __intToHex[(__previous + __current + __next) % 16]
    return "".join([__realResult[i] for i in range(0, len(__realResult), 2)])

@lru_cache()
def __BasicHashToBytes(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> bytes:
    """
    This function is a function that is there to be able to ensure the backward compatibility of the "BasicHashToBytes()" function.
    """
    return __BasicHashToStr(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity).encode("utf-8")

@lru_cache()
def __BasicHashToStr(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    This function is a function that is there to be able to ensure the backward compatibility of the "BasicHashToStr()" function.
    """
    __BasicHashVerifyChars()
    hashSize = int(hashSize)
    if hashSize <= 0:
        return ""
    if not type(stringToHash) in BASIC_HASHING_VALIDS_TYPES:
        raise TypeError(f"stringToHash type should be in one of the valids types : {BASIC_HASHING_VALIDS_TYPES}")
    if isinstance(stringToHash, bytes):
        stringToHash = stringToHash.hex()
    if useSha512ForSecurity:
        sha512Hash = SHA3_512.new()
        sha512Hash.update(stringToHash.encode("utf-8"))
        stringToHash = sha512Hash.hexdigest()
    parts = [[] for _ in range(hashSize)]
    for i in range(len(stringToHash)):
        parts[i % hashSize].append(stringToHash[i])
    stringHash = ""
    for i in range(len(parts)):
        part = parts[i]
        total = 0
        previous = 0
        if i > 0:
            previous = ord(stringHash[i-1])
        totalPrevious = 0
        for char in stringHash:
            totalPrevious += ord(char)
        totalChar = 0
        for char in stringToHash:
            totalChar += ord(char)
        if len(part) == 0:
            total += int(100*(1+i)*(len(stringToHash)+previous+(totalPrevious*(totalPrevious - totalChar + previous)))-totalChar)
        for y in range(len(part)):
            char = part[y]
            total += int(ord(char)*(len(part)-y+1+i+(y-i*hashSize)+previous+(totalPrevious*(totalPrevious - totalChar + previous)))-totalChar)
        stringHash += __BASIC_HASHING_CHARS[total % len(__BASIC_HASHING_CHARS)]
    return stringHash
