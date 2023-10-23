from .__BasicCiphering import *

def AdvancedCipher(message: str | bytes, password: str | bytes, saltPassword: str | bytes = b'salt_', *, ReturnTheEncryptTextAndTagAsASingleValue: bool = True, useThisCustomSeparatorBetweenCipherTextAndTag: bytes | str | None = None) -> bytes | tuple[bytes, bytes]:
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
    >>> ciphered_data = AdvancedCipher('Hello, world!', 'my_secure_password', 'additional_salt')
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
    iv = BasicHashToBytes(password, 32, useSha512ForSecurity=True)
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

def AdvancedDecipher(cipherMessage: bytes, password: str | bytes, saltPassword: str | bytes = b'salt_', *, tagIfTagNotWithCipherText: bytes | None = None, customSeparatorBetweenCipherTextAndTag: bytes | str | None = None) -> bytes | str:
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
    >>> ciphered_data = AdvancedCipher('Hello, world!', 'my_secure_password', 'additional_salt')
    >>> deciphered_data = AdvancedDecipher(ciphered_data, 'my_secure_password', 'additional_salt')
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
    iv: bytes = BasicHashToBytes(password, 32, useSha512ForSecurity=True)
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
