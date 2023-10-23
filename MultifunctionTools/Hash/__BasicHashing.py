from functools import cache

from .__HashAlgos import *

__BASIC_HASHING_CHARS = """azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN0123456789@#&_-!?=+*%~"""
BASIC_HASHING_CHARS = __BASIC_HASHING_CHARS
BASIC_HASHING_VALIDS_TYPES = [str, bytes]


def __BasicHashVerifyChars() -> None:
    """
    This function checks whether the characters used for basic hashing are valid and do not encode to more than 1 byte in UTF-8 encoding.

    :raises ValueError: If any character used for basic hashing encodes to more than 1 byte in UTF-8 encoding.
    """
    for char in __BASIC_HASHING_CHARS:
        if len(char.encode("utf-8")) > 1:
            raise ValueError(f"The character {char} is not valid because it is encoded on more than 1 byte.")

@cache
def BasicHashToHex(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    Calculate a basic hash from a string or bytes and return it as a hexadecimal string.

    :param stringToHash: The string or bytes to be hashed.
    :type stringToHash: str | bytes
    :param hashSize: The size of the hash in characters. Defaults to 16.
    :type hashSize: int
    :param useSha512ForSecurity: Whether to use SHA-512 for additional security. Defaults to False.
    :type useSha512ForSecurity: bool

    :return: The calculated hash as a hexadecimal string.
    :rtype: str

    :examples:

    # Example usage with a string
    >>> result = BasicHashToHex("test_password")
    >>> print(result)  # The calculated hash as a hexadecimal string

    # Example usage with bytes and increased security
    >>> result = BasicHashToHex(b"test_password", useSha512ForSecurity=True)
    >>> print(result)  # The calculated hash as a hexadecimal string with SHA-512 for security
    """
    __result = BasicHashToBytes(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity).hex()
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

@cache
def BasicHashToBytes(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> bytes:
    """
    Calculate a basic hash from a string or bytes and return it as bytes.

    :param stringToHash: The string or bytes to be hashed.
    :type stringToHash: str | bytes
    :param hashSize: The size of the hash in characters. Defaults to 16.
    :type hashSize: int
    :param useSha512ForSecurity: Whether to use SHA-512 for additional security. Defaults to False.
    :type useSha512ForSecurity: bool

    :return: The calculated hash as bytes.
    :rtype: bytes

    :examples:

    # Example usage with a string
    >>> result = BasicHashToBytes("test_password")
    >>> print(result)  # The calculated hash as bytes

    # Example usage with bytes and increased security
    >>> result = BasicHashToBytes(b"test_password", useSha512ForSecurity=True)
    >>> print(result)  # The calculated hash as bytes with SHA-512 for security
    """
    return BasicHashToStr(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity).encode("utf-8")

def BasicHashToStr(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    Calculate a basic hash from a string or bytes and return it as a string.

    :param stringToHash: The string or bytes to be hashed.
    :type stringToHash: str | bytes
    :param hashSize: The size of the hash in characters. Defaults to 16.
    :type hashSize: int
    :param useSha512ForSecurity: Whether to use SHA-512 for additional security. Defaults to False.
    :type useSha512ForSecurity: bool

    :return: The calculated hash as a string.
    :rtype: str

    :examples:

    # Example usage with a string
    >>> result = BasicHashToStr("test_password")
    >>> print(result)  # The calculated hash

    # Example usage with bytes and increased security
    >>> result = BasicHashToStr(b"test_password", useSha512ForSecurity=True)
    >>> print(result)  # The calculated hash with SHA-512 for security
    """
    return __BasicHashAlgo(stringToHash, hashSize, useSha512ForSecurity=useSha512ForSecurity)

def __BasicHashAlgo(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> str:
    """
    Calculate a basic hash from a string or bytes and return it as a string.

    This function calculates a basic hash from the provided string or bytes and returns it as a string of the specified hash size. It can optionally use SHA-512 for additional security.

    This function is there to ensure backward compatibility of the hash algorithm.

    :param stringToHash: The string or bytes to be hashed.
    :type stringToHash: str | bytes
    :param hashSize: The size of the hash in characters. Defaults to 16.
    :type hashSize: int
    :param useSha512ForSecurity: Whether to use SHA-512 for additional security. Defaults to False.
    :type useSha512ForSecurity: bool

    :return: The calculated hash as a string.
    :rtype: str

    :raises TypeError: If stringToHash type is not one of the valid types.
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
            previous = ord(stringHash[i - 1])
        totalPrevious = 0
        for char in stringHash:
            totalPrevious += ord(char)
        totalChar = 0
        for char in stringToHash:
            totalChar += ord(char)
        if len(part) == 0:
            total += int(100 * (1 + i) * (len(stringToHash) + previous + (totalPrevious * (totalPrevious - totalChar + previous))) - totalChar)
        for y in range(len(part)):
            char = part[y]
            total += int(ord(char) * (len(part) - y + 1 + i + (y - i * hashSize) + previous + (totalPrevious * (totalPrevious - totalChar + previous))) - totalChar)
        stringHash += __BASIC_HASHING_CHARS[total % len(__BASIC_HASHING_CHARS)]
    return stringHash
