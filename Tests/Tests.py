from MultifunctionTools.Cipher import *
from MultifunctionTools.Hash import *
from MultifunctionTools.Convert import *

def TestBasicHash(text: str = "Some random txt", hashLen : int = 32, textBytes: bytes = "Some random txt".encode("utf-8")):
    print(f"String text to be hash : {text}")
    print(f"Bytes text to be hash : {textBytes}")
    print("==================================")
    print(f"Hashed Str in {hashLen} Hex long and no sha512 : {BasicHashToHex(text, hashSize=hashLen, useSha512ForSecurity=False)}")
    print(f"Hashed Str in {hashLen} Hex long and sha512 : {BasicHashToHex(text, hashSize=hashLen, useSha512ForSecurity=True)}")
    print(f"Hashed Bytes in {hashLen} Hex long and no sha512 : {BasicHashToHex(textBytes, hashSize=hashLen, useSha512ForSecurity=False)}")
    print(f"Hashed Bytes in {hashLen} Hex long and sha512 : {BasicHashToHex(textBytes, hashSize=hashLen, useSha512ForSecurity=True)}")
    print("==================================")
    print(f"Hashed Str in {hashLen} Bytes long and no sha512 : {BasicHashToBytes(text, hashSize=hashLen, useSha512ForSecurity=False)}")
    print(f"Hashed Str in {hashLen} Bytes long and sha512 : {BasicHashToBytes(text, hashSize=hashLen, useSha512ForSecurity=True)}")
    print(f"Hashed Bytes in {hashLen} Bytes long and no sha512 : {BasicHashToBytes(textBytes, hashSize=hashLen, useSha512ForSecurity=False)}")
    print(f"Hashed Bytes in {hashLen} Bytes long and sha512 : {BasicHashToBytes(textBytes, hashSize=hashLen, useSha512ForSecurity=True)}")
    print("==================================")
    print(f"Hashed Str in {hashLen} Str long and no sha512 : {BasicHashToStr(text, hashSize=hashLen, useSha512ForSecurity=False)}")
    print(f"Hashed Str in {hashLen} Str long and sha512 : {BasicHashToStr(text, hashSize=hashLen, useSha512ForSecurity=True)}")
    print(f"Hashed Bytes in {hashLen} Str long and no sha512 : {BasicHashToStr(textBytes, hashSize=hashLen, useSha512ForSecurity=False)}")
    print(f"Hashed Bytes in {hashLen} Str long and sha512 : {BasicHashToStr(textBytes, hashSize=hashLen, useSha512ForSecurity=True)}")

def TestBasicHashCollissionRate(charsToTest: str = "abcdefghijklmnopqrstuvwxyz", stringLen: int = 8, hashSizeToTest: int = 4):
    originalText = "".join(random.choices(charsToTest, k=stringLen))
    hashToFind = BasicHashToStr(originalText, hashSizeToTest)
    count = 0
    alreadyTested = {originalText}
    randomText = "".join(random.choices(charsToTest, k=stringLen))
    hashToTest = BasicHashToStr(randomText, hashSizeToTest)
    while hashToTest != hashToFind:
        randomText = "".join(random.choices(charsToTest, k=stringLen))
        count += 1
        while randomText in alreadyTested:
            randomText = "".join(random.choices(charsToTest, k=stringLen))
        hashToTest = BasicHashToStr(randomText, hashSizeToTest)
        alreadyTested.add(randomText)
        if (count % 10000) == 0:
            print(f"Tries : {count}, base hash {hashToFind}, current txt : {randomText}, current hash : {hashToTest}")
    print(f"Found two same hash in {count} tries. Hash : {hashToFind} , {originalText = } , {randomText = }")

def TestBasicCipher(text: str = "Some random txt", textBytes: str = "Some random txt".encode("utf-8"), passwordToCipher = "Very  ğÖ0ð p@sswøřď"):
    print(f"String text to cipher : {text}")
    print(f"Bytes text to cipher : {textBytes}")
    print(f"Password to cipher : {passwordToCipher}")
    print("==================================")
    print(f"Ciphered string text to bytes : {BasicCipherToBytes(text, passwordToCipher)}")
    print(f"Ciphered bytes text to bytes : {BasicCipherToBytes(textBytes, passwordToCipher)}")
    print(f"Ciphered string text to hex : {BasicCipherToHex(text, passwordToCipher)}")
    print(f"Ciphered bytes text to hex : {BasicCipherToHex(textBytes, passwordToCipher)}")

def TestBasicDeCipher(textToFind: str = "Some random txt", passwordToDecipher: str = "Very  ğÖ0ð p@sswøřď"):
    print(f"Text to find : {textToFind}")
    print(f"Password to decipher : {passwordToDecipher}")
    print("==================================")
    print(f"Deciphered bytes : {BasicDecipherBytes(BasicCipherToBytes(textToFind, passwordToDecipher), passwordToDecipher)}")
    print(f"Deciphered hex : {BasicDecipherHex(BasicCipherToHex(textToFind, passwordToDecipher), passwordToDecipher)}")

def TestAdvancedCipherAndDecipher(passwordToCipher: str = "supersecret", saltPasswordToCipher: str = "supersecret", messageToCipher: bytes = b"This is a secret message.", customSeparator: str = "separator"):
    ciphertext = AdvancedCipher(messageToCipher, passwordToCipher, saltPassword=saltPasswordToCipher, ReturnTheEncryptTextAndTagAsASingleValue=True, useThisCustomSeparatorBetweenCipherTextAndTag=customSeparator)
    decrypted_message = AdvancedDecipher(ciphertext, passwordToCipher, saltPassword=saltPasswordToCipher, tagIfTagNotWithCipherText=None, customSeparatorBetweenCipherTextAndTag=customSeparator)
    if isinstance(decrypted_message, bytes):
        decrypted_message = decrypted_message.decode()
    print("Original message :", messageToCipher.decode())
    print(f"{ciphertext = } .")
    print("Message decipher :", decrypted_message)

def TestConvert(pathToImageWithoutExtension: str = r"image", imageExtension: str = ".jpg", size: tuple[int, int] = (256, 256)):
    ConvertImageToIco(pathToImageWithoutExtension+imageExtension, pathToImageWithoutExtension+".ico", size)
    ConvertImageToPng(pathToImageWithoutExtension+imageExtension, pathToImageWithoutExtension+".png", size)
    ConvertImageToPpm(pathToImageWithoutExtension+imageExtension, pathToImageWithoutExtension+".ppm", size)
    ConvertImageToTiff(pathToImageWithoutExtension+imageExtension, pathToImageWithoutExtension+".tiff", size)
    ConvertImageToWebp(pathToImageWithoutExtension+imageExtension, pathToImageWithoutExtension+".webp", size)
    ConvertImageToPdf(pathToImageWithoutExtension+imageExtension, pathToImageWithoutExtension+".pdf", size)

def TestAdvancedHash(stringToHash: bytes | str | list[bytes | str] | tuple[bytes | str] | set[bytes | str] = ("test", "test2"), stringToVerify: bytes | str | list[bytes | str] | tuple[bytes | str] | set[bytes | str] = ("test", "test2"), randomSaltSize: list[int, int] | tuple[int, int] = (30 ,32)):
    print("================= Random =================")
    hashAlgo = HASH_ALGO_RANDOM
    hashStr = AdvancedHash(stringToHash=stringToHash, hashAlgo=hashAlgo, randomSaltSize=randomSaltSize)
    print(f"String hashed : {hashStr}")
    print(f"String verify : {stringToVerify} ; result : {AdvancedHashVerification(hashStr, stringToVerify)}")

    print("================= TupleHash128 or TupleHash256 =================")
    hashAlgo = random.choice([HASH_ALGO_TUPLEHASH128, HASH_ALGO_TUPLEHASH256])
    hashStr = AdvancedHash(stringToHash=stringToHash, hashAlgo=hashAlgo, randomSaltSize=randomSaltSize)
    print(f"String hashed : {hashStr}")
    print(f"String verify : {stringToVerify} ; result : {AdvancedHashVerification(hashStr, stringToVerify)}")

    print("================= BLAKE2s or BLAKE2b =================")
    hashAlgo = random.choice([HASH_ALGO_BLAKE2S, HASH_ALGO_BLAKE2B])
    hashStr = AdvancedHash(stringToHash=stringToHash, hashAlgo=hashAlgo, randomSaltSize=randomSaltSize)
    print(f"String hashed : {hashStr}")
    print(f"String verify : {stringToVerify} ; result : {AdvancedHashVerification(hashStr, stringToVerify)}")

    print("================= Bcrypt =================")
    hashAlgo = HASH_ALGO_BCRYPT
    hashStr = AdvancedHash(stringToHash=stringToHash, hashAlgo=hashAlgo, randomSaltSize=randomSaltSize)
    print(f"String hashed : {hashStr}")
    print(f"String verify : {stringToVerify} ; result : {AdvancedHashVerification(hashStr, stringToVerify)}")

    print("================= Scrypt =================")
    hashAlgo = HASH_ALGO_SCRYPT
    hashStr = AdvancedHash(stringToHash=stringToHash, hashAlgo=hashAlgo, randomSaltSize=randomSaltSize)
    print(f"String hashed : {hashStr}")
    print(f"String verify : {stringToVerify} ; result : {AdvancedHashVerification(hashStr, stringToVerify)}")

    print("================= Argon2 =================")
    hashAlgo = HASH_ALGO_ARGON2
    hashStr = AdvancedHash(stringToHash=stringToHash, hashAlgo=hashAlgo, randomSaltSize=randomSaltSize)
    print(f"String hashed : {hashStr}")
    print(f"String verify : {stringToVerify} ; result : {AdvancedHashVerification(hashStr, stringToVerify)}")

if __name__ == "__main__":
    TestAdvancedHash()
