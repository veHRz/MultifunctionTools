# MultifunctionTools Python Library

The `MultifunctionTools` library is a comprehensive collection of handy utilities and tools designed to enhance your Python coding experience. Whether you're a beginner or an experienced developer, `MultifunctionTools` provides a set of functionalities to simplify and streamline various aspects of Python programming.

## Features

### 1. Ciphering Text

Can help you cipher text easily with multiple function choices.

```python
from MultifunctionTools import Cipher

password = "superPassword"
saltPassword = "superPasswordNumber2"
message = b"This is a secret message."

# Cipher text with two passwords
cipherText = Cipher.AdvancedCipherWithSaltPassword(message, password, saltPassword=saltPassword)
print("Ciphered text :", cipherText)

# Decipher text with two passwords
decipherText = Cipher.AdvancedDecipherWithSaltPassword(cipherText, password, saltPassword=saltPassword)
print("Deciphered text :", decipherText)
```

### 2. Hashing Text

Tools that allow you to hide text to prevent it from being retrieved. Ideal for storing passwords.

```python
from MultifunctionTools import Hash

textToHash = "Some text to hash"
hashLength = 32

# Hashing Str and return hex string
hashedString: str = Hash.BasicHashStrToHex(textToHash, hashSize=hashLength)
print("Hashed string :", hashedString)

hashAlgo = Hash.HASH_ALGO_BCRYPT
hashedString: str = Hash.AdvancedHashWithRandomSalt(textToHash, hashAlgo, randomSaltSize=[22, 35], costFactor=14, blockSize=8, parallelism=1, memoryCost=64000)
print("Hashed string :", hashedString)
textToVerify = "Some text to verify"
isGoodPassword = Hash.AdvancedHashVerification(hashedString, textToVerify)
print(f"{textToVerify = } == {hashedString = } : {isGoodPassword}")

```

### 3. Converting

A range of tools that allow you to easily convert files, values ​​and many other things.

```python
from MultifunctionTools import Convert

baseImageFilePath = "some/path/to/image.jpg"
newImageFilePath = "some/path/to/image.png"

# Converting base image to a new png image
Convert.ConvertImageToPng(baseImageFilePath, newImageFilePath)
```

## Installation

You can easily install `MultifunctionTools` using pip:

```bash
pip install MultifunctionTools
```

## Usage

Import the desired modules from `MultifunctionTools` and start using its powerful features in your Python projects.

```python
from MultifunctionTools.Cipher import *
from MultifunctionTools.Hash import *
from MultifunctionTools.Convert import *

# Now you're ready to use the various tools from MultifunctionTools!
```

## Contribution

Contributions to the `MultifunctionTools` library are welcome! If you have an idea for a new tool or want to enhance existing functionalities, feel free to submit a pull request on our [GitHub repository](https://github.com/veHRz/MultifunctionTools).

## License

This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License. - see the [LICENSE](https://github.com/veHRz/MultifunctionTools/blob/master/LICENSE.md) file for details.

---

Give `MultifunctionTools` a try and make your Python coding journey more efficient and enjoyable. Happy coding!
