def ConvertToBytes(stringToConvert: bytes | str | list[bytes | str] | tuple[bytes | str] | set[bytes | str]) -> bytes:
    if isinstance(stringToConvert, str):
        stringToConvert: bytes = stringToConvert.encode("utf-8")
    elif isinstance(stringToConvert, list) or isinstance(stringToConvert, tuple) or isinstance(stringToConvert, set):
        stringToConvert: bytes = b"".join([ConvertToBytes(char)+b" " for char in stringToConvert])
        stringToConvert: bytes = stringToConvert.strip(b" ")
    return stringToConvert
