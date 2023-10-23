import random

from .__BasicHashing import *

ADVANCED_HASHING_CODES = {HASH_ALGO_BASIC_HASH: ["b0"], HASH_ALGO_SHA224: ["224"], HASH_ALGO_SHA256: ["256"], HASH_ALGO_SHA384: ["384"], HASH_ALGO_SHA512: ["512"], HASH_ALGO_SHA512_224: ["512/224"], HASH_ALGO_SHA512_256: ["512/256"], HASH_ALGO_SHA3_224: ["3224"], HASH_ALGO_SHA3_256: ["3256"], HASH_ALGO_SHA3_384: ["3384"], HASH_ALGO_SHA3_512: ["3512"], HASH_ALGO_BLAKE2S: ["b2s"], HASH_ALGO_BLAKE2B: ["b2b"], HASH_ALGO_BCRYPT: ["2a", "2b", "2y"], HASH_ALGO_SCRYPT: ["scrypt"], HASH_ALGO_ARGON2: ["argon2id"]}
ADVANCED_HASHING_ALGOS = [HASH_ALGO_RANDOM, HASH_ALGO_BASIC_HASH, HASH_ALGO_SHA224, HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512, HASH_ALGO_SHA3_224, HASH_ALGO_SHA3_256, HASH_ALGO_SHA3_384, HASH_ALGO_SHA3_512, HASH_ALGO_SHA512_224, HASH_ALGO_SHA3_256, HASH_ALGO_BLAKE2S, HASH_ALGO_BLAKE2B, HASH_ALGO_BCRYPT, HASH_ALGO_SCRYPT, HASH_ALGO_ARGON2]
ADVANCED_HASHING_SIMPLE_ALGOS = {HASH_ALGO_SHA224: SHA224, HASH_ALGO_SHA256: SHA256, HASH_ALGO_SHA384: SHA384, HASH_ALGO_SHA512: SHA512, HASH_ALGO_SHA3_224: SHA3_224, HASH_ALGO_SHA3_256: SHA3_256, HASH_ALGO_SHA3_384: SHA3_384, HASH_ALGO_SHA3_512: SHA3_512, HASH_ALGO_BLAKE2S: BLAKE2s, HASH_ALGO_BLAKE2B: BLAKE2b}
ADVANCED_HASHING_SALT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./+="

def AdvancedHash(stringToHash: bytes | str, hashAlgo: Literal["random", "basic", "sha224", "sha256", "sha384", "sha512", "sha512/224", "sha512/256", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2s", "blake2b", "bcrypt", "scrypt", "argon2"], randomSaltSize: list[int, int] = None, *, hashSize: int = 64, costFactor: int = 14, blockSize: int = 8, parallelism: int = 1, memoryCost: int = 64000) -> str:
    """
    Compute the hash of a string or bytes using various advanced hashing algorithms.

    :param stringToHash: The string or bytes to be hashed.
    :type stringToHash: bytes | str
    :param hashAlgo: The hashing algorithm to use.
    :type hashAlgo: Literal["random", "basic", "sha224", "sha256", "sha384", "sha512",
                          "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2s",
                          "blake2b", "bcrypt", "scrypt", "argon2"]
    :param randomSaltSize: The minimum and maximum size of random salt. Defaults to [22, 35].
    :type randomSaltSize: list[int, int]
    :param hashSize: The size of the hash in characters. Defaults to 64.
    :type hashSize: int
    :param costFactor: The cost factor used for certain algorithms (bcrypt, scrypt, argon2). Defaults to 14.
    :type costFactor: int
    :param blockSize: The block size used for some the scrypt algorithm. Defaults to 8.
    :type blockSize: int
    :param parallelism: The level of parallelism used for some algorithms (scrypt, argon2). Defaults to 1.
    :type parallelism: int
    :param memoryCost: The memory cost used for the argon2 algorithm. Defaults to 64000.
    :type memoryCost: int

    :return: The resulting hash as a string.
    :rtype: str

    :raises ValueError: If the specified hashing algorithm is not valid.

    :examples:

    # Example usage with the BCRYPT hashing algorithm
    >>> hash_result = AdvancedHash("my_password", HASH_ALGO_BCRYPT)
    >>> print(hash_result)

    # Example usage with a random hashing algorithm
    >>> hash_result = AdvancedHash("my_password", HASH_ALGO_RANDOM)
    >>> print(hash_result)
    """
    if randomSaltSize is None:
        randomSaltSize = [22, 35]
    if hashAlgo not in ADVANCED_HASHING_ALGOS:
        raise ValueError(f'hashAlgo should be a valid algo in "{ADVANCED_HASHING_ALGOS}".')
    if not isinstance(stringToHash, bytes):
        stringToHash: bytes = stringToHash.encode("utf-8")
    if hashAlgo == HASH_ALGO_RANDOM:
        return AdvancedHash(stringToHash, random.choice(ADVANCED_HASHING_ALGOS), randomSaltSize=randomSaltSize)
    randomSalt = "".join(random.choices(ADVANCED_HASHING_SALT_CHARS, k=random.randint(*randomSaltSize)))
    randomSaltBytes = randomSalt.encode("utf-8")
    if hashAlgo == HASH_ALGO_BASIC_HASH:
        return f"${ADVANCED_HASHING_CODES[HASH_ALGO_BASIC_HASH][0]}${randomSalt}${BasicHashToStr(stringToHash+randomSaltBytes, hashSize)}"
    elif hashAlgo in ADVANCED_HASHING_SIMPLE_ALGOS.keys():
        hashingAlgo = ADVANCED_HASHING_SIMPLE_ALGOS[hashAlgo].new()
        hashingAlgo.update(stringToHash + randomSaltBytes)
        return f"${ADVANCED_HASHING_CODES[hashAlgo][0]}${randomSalt}${hashingAlgo.hexdigest()}"
    elif hashAlgo == HASH_ALGO_SHA512_224:
        hashingAlgo = SHA512.new(truncate="224")
        hashingAlgo.update(stringToHash + randomSaltBytes)
        return f"${ADVANCED_HASHING_CODES[hashAlgo][0]}${randomSalt}${hashingAlgo.hexdigest()}"
    elif hashAlgo == HASH_ALGO_SHA512_256:
        hashingAlgo = SHA512.new(truncate="256")
        hashingAlgo.update(stringToHash + randomSaltBytes)
        return f"${ADVANCED_HASHING_CODES[hashAlgo][0]}${randomSalt}${hashingAlgo.hexdigest()}"
    elif hashAlgo == HASH_ALGO_BCRYPT:
        stringHashed = SHA3_512.new(stringToHash).digest()
        stringHashed = bcrypt(stringHashed, costFactor).decode("utf-8")
        stringHashed = stringHashed.split("$")[1:]
        return f"${stringHashed[0]}${stringHashed[2][:22]}${stringHashed[2][22:]}${stringHashed[1]}"
    elif hashAlgo == HASH_ALGO_SCRYPT:
        factorCost = 2**(costFactor+4)
        stringHashed = scrypt(stringToHash.decode("utf-8"), randomSalt, key_len=int(hashSize/2), N=factorCost, r=blockSize, p=parallelism, num_keys=1).hex()
        return f"${ADVANCED_HASHING_CODES[HASH_ALGO_SCRYPT][0]}${randomSalt}${stringHashed}${costFactor}${blockSize}${parallelism}"
    elif hashAlgo == HASH_ALGO_ARGON2:
        stringHashed = argon2.PasswordHasher(time_cost=costFactor, memory_cost=memoryCost, parallelism=parallelism, hash_len=64)
        stringHashed = stringHashed.hash(stringToHash, salt=randomSaltBytes)
        stringHashed = stringHashed.split("$")[1:]
        # Format : "$hash algo$salt$hash$version$memory cost$time cost$parallelism
        version = stringHashed[1].split("v=")[1]
        return f"${stringHashed[0]}${stringHashed[3]}${stringHashed[4]}${version}${memoryCost}${costFactor}${parallelism}"

def AdvancedHashVerification(hashedString: str, stringToTest: str | bytes) -> bool:
    """
    Verify the integrity of a hashed string by comparing it with a test string.

    :param hashedString: The hashed string to be verified.
    :type hashedString: str
    :param stringToTest: The string or bytes to test against the hashed string.
    :type stringToTest: str | bytes

    :return: True if the hashed string matches the test string, False otherwise.
    :rtype: bool

    :raises TypeError: If hashedString is not of type string.
    :raises ValueError: If the format of hashedString is not correct for the specified hashing algorithm.

    :examples:

    # Example usage with a hashed string and a test string
    >>> result = AdvancedHashVerification("$2a$l/yqQfsp64/ffV6l26XwFe$QiwQzTA1ZIVVhWz0xDvofj9ARAFdiDe$14", "my_password")
    >>> print(result)  # True if the hash matches, False otherwise
    """
    if not isinstance(hashedString, str):
        raise TypeError("hashedString should be of type string.")
    if not isinstance(stringToTest, bytes):
        stringToTest: bytes = stringToTest.encode("utf-8")
    hashedString = hashedString.split("$")[1:]
    if len(hashedString) < 3:
        raise ValueError("The value of hashedString is not correct.")
    hashedStringPrefix = hashedString[0]
    hashedStringSalt = hashedString[1].encode("utf-8")
    hashedStringHash = hashedString[2]
    if hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_BASIC_HASH]:
        return hashedStringHash == BasicHashToStr(stringToTest+hashedStringSalt, len(hashedStringHash))
    elif hashedStringPrefix in ["".join(ADVANCED_HASHING_CODES[simpleHashAlgo]) for simpleHashAlgo in ADVANCED_HASHING_SIMPLE_ALGOS]:
        hashingCodesReverse = {"".join(v): k for k, v in ADVANCED_HASHING_CODES.items()}
        hashingAlgo = ADVANCED_HASHING_SIMPLE_ALGOS[hashingCodesReverse[hashedStringPrefix]].new()
        hashingAlgo.update(stringToTest+hashedStringSalt)
        return hashedStringHash == hashingAlgo.hexdigest()
    elif hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_SHA512_224]:
        hashingAlgo = SHA512.new(truncate="224")
        hashingAlgo.update(stringToTest + hashedStringSalt)
        return hashedStringHash == hashingAlgo.hexdigest()
    elif hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_SHA512_256]:
        hashingAlgo = SHA512.new(truncate="256")
        hashingAlgo.update(stringToTest + hashedStringSalt)
        return hashedStringHash == hashingAlgo.hexdigest()
    elif hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_BCRYPT]:
        if len(hashedString) < 4:
            raise ValueError("The value of hashedString is not correct.")
        stringHash = f"${hashedStringPrefix}${hashedString[3]}${hashedString[1]+hashedStringHash}"
        try:
            bcrypt_check(SHA3_512.new(stringToTest).digest(), stringHash)
            return True
        except ValueError:
            return False
    elif hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_SCRYPT]:
        if len(hashedString) < 6:
            raise ValueError("The value of hashedString is not correct.")
        factorCost = 2**(int(hashedString[3])+4)
        blockSize = int(hashedString[4])
        parallelism = int(hashedString[5])
        hashedStringSalt = hashedStringSalt.decode("utf-8")
        return hashedStringHash == scrypt(stringToTest.decode("utf-8"), hashedStringSalt, key_len=len(hashedString[2]), N=factorCost, r=blockSize, p=parallelism, num_keys=1).hex()
    elif hashedStringPrefix in ADVANCED_HASHING_CODES[HASH_ALGO_ARGON2]:
        if len(hashedString) < 7:
            raise ValueError("The value of hashedString is not correct.")
        # Format : "$hash algo$salt$hash$version$memory cost$time cost$parallelism
        stringHash = f"${hashedStringPrefix}$v={hashedString[3]}$m={hashedString[4]},t={hashedString[5]},p={hashedString[6]}${hashedString[1]}${hashedString[2]}"
        stringHasher = argon2.PasswordHasher(time_cost=int(hashedString[5]), memory_cost=int(hashedString[4]), parallelism=int(hashedString[6]), hash_len=64)
        try:
            stringHasher.verify(stringHash, stringToTest)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
    return False
