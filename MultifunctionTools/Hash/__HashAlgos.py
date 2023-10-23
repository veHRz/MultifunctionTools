from typing import Literal

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

HASH_ALGO_DEFAULT_SAFER: Literal["bcrypt"] = "bcrypt"
HASH_ALGO_DEFAULT_FASTER: Literal["sha512"] = "sha512"
HASH_ALGO_RANDOM: Literal["random"] = "random"
HASH_ALGO_BASIC_HASH: Literal["basic"] = "basic"
HASH_ALGO_SHA224: Literal["sha224"] = "sha224"
HASH_ALGO_SHA256: Literal["sha256"] = "sha256"
HASH_ALGO_SHA384: Literal["sha384"] = "sha384"
HASH_ALGO_SHA512: Literal["sha512"] = "sha512"
HASH_ALGO_SHA512_224: Literal["sha512/224"] = "sha512/224"
HASH_ALGO_SHA512_256: Literal["sha512/256"] = "sha512/256"
HASH_ALGO_SHA3_224: Literal["sha3_224"] = "sha3_224"
HASH_ALGO_SHA3_256: Literal["sha3_256"] = "sha3_256"
HASH_ALGO_SHA3_384: Literal["sha3_384"] = "sha3_384"
HASH_ALGO_SHA3_512: Literal["sha3_512"] = "sha3_512"
HASH_ALGO_BLAKE2S: Literal["blake2s"] = "blake2s"
HASH_ALGO_BLAKE2B: Literal["blake2b"] = "blake2b"
HASH_ALGO_BCRYPT: Literal["bcrypt"] = "bcrypt"
HASH_ALGO_SCRYPT: Literal["scrypt"] = "scrypt"
HASH_ALGO_ARGON2: Literal["argon2"] = "argon2"

