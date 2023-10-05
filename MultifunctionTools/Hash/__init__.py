"""
This module is part of the "MultifunctionTools" module which belongs to "https://github.com/veHRz" and provides access to various functions to help hashing.
"""

from typing import Literal
import random
from functools import cache

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
from Cryptodome.Protocol.KDF import bcrypt, bcrypt_check
from Cryptodome.Protocol.KDF import scrypt
import argon2

HASH_ALGO_RANDOM: Literal["random"] = "random"
HASH_ALGO_BASIC_HASH: Literal["basic"] = "basic"
HASH_ALGO_SHA224: Literal["sha224"] = "sha224"
HASH_ALGO_SHA256: Literal["sha256"] = "sha256"
HASH_ALGO_SHA384: Literal["sha384"] = "sha384"
HASH_ALGO_SHA512: Literal["sha512"] = "sha512"
HASH_ALGO_SHA3_224: Literal["sha3_224"] = "sha3_224"
HASH_ALGO_SHA3_256: Literal["sha3_256"] = "sha3_256"
HASH_ALGO_SHA3_384: Literal["sha3_384"] = "sha3_384"
HASH_ALGO_SHA3_512: Literal["sha3_512"] = "sha3_512"
HASH_ALGO_BLAKE2S: Literal["blake2s"] = "blake2s"
HASH_ALGO_BLAKE2B: Literal["blake2b"] = "blake2b"
HASH_ALGO_BCRYPT: Literal["bcrypt"] = "bcrypt"
HASH_ALGO_SCRYPT: Literal["scrypt"] = "scrypt"
HASH_ALGO_ARGON2: Literal["argon2"] = "argon2"

__BASIC_HASHING_CHARS = """azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN0123456789@#&_-!?=+*%~"""
BASIC_HASHING_CHARS = __BASIC_HASHING_CHARS
BASIC_HASHING_VALIDS_TYPES = [str, bytes]

ADVANCED_HASHING_CODES = {HASH_ALGO_BASIC_HASH: ["b0"], HASH_ALGO_SHA224: ["224"], HASH_ALGO_SHA256: ["256"], HASH_ALGO_SHA384: ["384"], HASH_ALGO_SHA512: ["512"], HASH_ALGO_SHA3_224: ["3224"], HASH_ALGO_SHA3_256: ["3256"], HASH_ALGO_SHA3_384: ["3384"], HASH_ALGO_SHA3_512: ["3512"], HASH_ALGO_BLAKE2S: ["b2s"], HASH_ALGO_BLAKE2B: ["b2b"], HASH_ALGO_BCRYPT: ["2a", "2b", "2y"], HASH_ALGO_SCRYPT: ["scrypt"], HASH_ALGO_ARGON2: ["argon2id"]}
ADVANCED_HASHING_VALID_ALGOS = [HASH_ALGO_RANDOM, HASH_ALGO_BASIC_HASH, HASH_ALGO_SHA224, HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512, HASH_ALGO_SHA3_224, HASH_ALGO_SHA3_256, HASH_ALGO_SHA3_384, HASH_ALGO_SHA3_512, HASH_ALGO_BLAKE2S, HASH_ALGO_BLAKE2B, HASH_ALGO_BCRYPT, HASH_ALGO_SCRYPT, HASH_ALGO_ARGON2]
ADVANCED_HASHING_VALID_SIMPLE_ALGOS = {HASH_ALGO_SHA224: SHA224, HASH_ALGO_SHA256: SHA256, HASH_ALGO_SHA384: SHA384, HASH_ALGO_SHA512: SHA512, HASH_ALGO_SHA3_224: SHA3_224, HASH_ALGO_SHA3_256: SHA3_256, HASH_ALGO_SHA3_384: SHA3_384, HASH_ALGO_SHA3_512: SHA3_512, HASH_ALGO_BLAKE2S: BLAKE2s, HASH_ALGO_BLAKE2B: BLAKE2b}
ADVANCED_HASHING_VALID_SALT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./+="

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


@cache
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

@cache
def __BasicHashToBytes(stringToHash: str | bytes, hashSize: int = 16, *, useSha512ForSecurity: bool = False) -> bytes:
    """
    This function is a function that is there to be able to ensure the backward compatibility of the "BasicHashToBytes()" function.
    """
    return __BasicHashToStr(stringToHash, hashSize=hashSize, useSha512ForSecurity=useSha512ForSecurity).encode("utf-8")

@cache
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


def AdvancedHashWithRandomSalt(stringToHash: bytes | str, hashAlgo: Literal["random", "basic", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2s", "blake2b", "bcrypt", "scrypt", "argon2"], randomSaltSize: list[int, int] = None, *, hashSize: int = 64, costFactor: int = 14, blockSize: int = 8, parallelism: int = 1, memoryCost: int = 64000) -> str:
    if randomSaltSize is None:
        randomSaltSize = [22, 35]
    if hashAlgo not in ADVANCED_HASHING_VALID_ALGOS:
        raise ValueError(f'hashAlgo should be a valid algo in "{ADVANCED_HASHING_VALID_ALGOS}".')
    if not isinstance(stringToHash, bytes):
        stringToHash: bytes = stringToHash.encode("utf-8")
    if hashAlgo == HASH_ALGO_RANDOM:
        return AdvancedHashWithRandomSalt(stringToHash, random.choice(ADVANCED_HASHING_VALID_ALGOS), randomSaltSize=randomSaltSize)
    randomSalt = "".join(random.choices(ADVANCED_HASHING_VALID_SALT_CHARS, k=random.randint(*randomSaltSize)))
    randomSaltBytes = randomSalt.encode("utf-8")
    if hashAlgo == HASH_ALGO_BASIC_HASH:
        return f"${ADVANCED_HASHING_CODES[HASH_ALGO_BASIC_HASH][0]}${randomSalt}${BasicHashToStr(stringToHash+randomSaltBytes, hashSize)}"
    elif hashAlgo in ADVANCED_HASHING_VALID_SIMPLE_ALGOS.keys():
        hashingAlgo = ADVANCED_HASHING_VALID_SIMPLE_ALGOS[hashAlgo].new()
        hashingAlgo.update(stringToHash+randomSaltBytes)
        return f"${ADVANCED_HASHING_CODES[hashAlgo][0]}${randomSalt}${hashingAlgo.hexdigest()}"
    elif hashAlgo == HASH_ALGO_BCRYPT:
        stringHashed = SHA3_512.new(stringToHash).digest()
        stringHashed = bcrypt(stringHashed, costFactor).decode("utf-8")
        stringHashed = stringHashed.split("$")[1:]
        return f"${stringHashed[0]}${stringHashed[2][:22]}${stringHashed[2][22:]}${stringHashed[1]}"
    elif hashAlgo == HASH_ALGO_SCRYPT:
        factorCost = 2**(costFactor+4)
        stringHashed = scrypt(stringToHash.decode("utf-8"), randomSalt, key_len=64, N=factorCost, r=blockSize, p=parallelism, num_keys=1).hex()
        return f"${ADVANCED_HASHING_CODES[HASH_ALGO_SCRYPT][0]}${randomSalt}${stringHashed}${costFactor}${blockSize}${parallelism}"
    elif hashAlgo == HASH_ALGO_ARGON2:
        stringHashed = argon2.PasswordHasher(time_cost=costFactor, memory_cost=memoryCost, parallelism=parallelism, hash_len=64)
        stringHashed = stringHashed.hash(stringToHash, salt=randomSaltBytes)
        stringHashed = stringHashed.split("$")[1:]
        # Format : "$hash algo$salt$hash$version$memory cost$time cost$parallelism
        version = stringHashed[1].split("v=")[1]
        return f"${stringHashed[0]}${stringHashed[3]}${stringHashed[4]}${version}${memoryCost}${costFactor}${parallelism}"

def AdvancedHashVerification(hashedString: str, stringToTest: str or bytes) -> bool:
    if not isinstance(hashedString, str):
        raise TypeError("hashedString should be of type string.")
    if not isinstance(stringToTest, bytes):
        stringToTest: bytes = stringToTest.encode("utf-8")
    hashedString = hashedString.split("$")[1:]
    hashedStringPrefix = hashedString[0]
    hashedStringSalt = hashedString[1].encode("utf-8")
    hashedStringHash = hashedString[2]
    if hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_BASIC_HASH]:
        return hashedStringHash == BasicHashToStr(stringToTest+hashedStringSalt, 64)
    elif hashedStringPrefix in ["".join(ADVANCED_HASHING_CODES[simpleHashAlgo]) for simpleHashAlgo in ADVANCED_HASHING_VALID_SIMPLE_ALGOS]:
        hashingCodesReverse = {"".join(v): k for k, v in ADVANCED_HASHING_CODES.items()}
        hashingAlgo = ADVANCED_HASHING_VALID_SIMPLE_ALGOS[hashingCodesReverse[hashedStringPrefix]].new()
        hashingAlgo.update(stringToTest+hashedStringSalt)
        return hashedStringHash == hashingAlgo.hexdigest()
    elif hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_BCRYPT]:
        stringHash = f"${hashedStringPrefix}${hashedString[3]}${hashedString[1]+hashedStringHash}"
        try:
            bcrypt_check(SHA3_512.new(stringToTest).digest(), stringHash)
            return True
        except ValueError:
            return False
    elif hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_SCRYPT]:
        factorCost = 2**(int(hashedString[3])+4)
        blockSize = int(hashedString[4])
        parallelism = int(hashedString[5])
        hashedStringSalt = hashedStringSalt.decode("utf-8")
        return hashedStringHash == scrypt(stringToTest.decode("utf-8"), hashedStringSalt, key_len=64, N=factorCost, r=blockSize, p=parallelism, num_keys=1).hex()
    elif hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_ARGON2]:
        # Format : "$hash algo$salt$hash$version$memory cost$time cost$parallelism
        stringHash = f"${hashedStringPrefix}$v={hashedString[3]}$m={hashedString[4]},t={hashedString[5]},p={hashedString[6]}${hashedString[1]}${hashedString[2]}"
        stringHasher = argon2.PasswordHasher(time_cost=int(hashedString[5]), memory_cost=int(hashedString[4]), parallelism=int(hashedString[6]), hash_len=64)
        try:
            stringHasher.verify(stringHash, stringToTest)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
    return False
