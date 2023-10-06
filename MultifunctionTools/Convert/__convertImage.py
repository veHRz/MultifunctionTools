import PIL
from PIL import Image
import os

__CONVERT_IMAGE_FULLY_SUPPORTED_IMAGE_FORMAT = [".bmp", ".dds", ".dib", ".eps", ".gif", ".icns", ".ico", ".jpeg", ".jpg", ".msp", ".pcx", ".png", ".ppm", ".sgi", ".tga", ".tiff", ".webp", ".xbm"]
__CONVERT_IMAGE_READ_ONLY_SUPPORTED_IMAGE_FORMAT = [".blp", ".cur", ".dcx", ".fli", ".flc", ".fpx", ".gbr", ".imt", ".mic", ".mpo", ".pcd", ".psd", ".wal", ".wmf", ".xpm"]
__CONVERT_IMAGE_WRITE_ONLY_SUPPORTED_IMAGE_FORMAT = [".palm", ".pdf"]
CONVERT_IMAGE_FULLY_SUPPORTED_IMAGE_FORMAT = __CONVERT_IMAGE_FULLY_SUPPORTED_IMAGE_FORMAT.copy()
CONVERT_IMAGE_READ_ONLY_SUPPORTED_IMAGE_FORMAT = __CONVERT_IMAGE_READ_ONLY_SUPPORTED_IMAGE_FORMAT.copy()
CONVERT_IMAGE_WRITE_ONLY_SUPPORTED_IMAGE_FORMAT = __CONVERT_IMAGE_WRITE_ONLY_SUPPORTED_IMAGE_FORMAT.copy()

def __isStringToSearchAtTheEndOfString(string: str, stringToSearch: str) -> bool:
    """
    Check if a string occurs at the end of another string (case-sensitive).

    This function checks if the stringToSearch occurs at the end of the input string.

    :param string: The input string to search.
    :type string: str
    :param stringToSearch: The string to search for at the end of the input string.
    :type stringToSearch: str

    :return: True if the stringToSearch is found at the end of the input string, otherwise False.

    :raises TypeError: If string or stringToSearch is not of the correct type.

    :examples:

    # Example usage to check if 'world' occurs at the end of 'Hello, world'
    >>> __isStringToSearchAtTheEndOfString('Hello, world', 'world')
    True

    # Example usage to check if 'Python' occurs at the end of 'Hello, world'
    >>> __isStringToSearchAtTheEndOfString('Hello, world', 'Python')
    False
    """
    if not isinstance(string, str):
        raise TypeError('"string" should be of type str.')
    if not isinstance(stringToSearch, str):
        raise TypeError('"stringToSearch" should be of type str.')
    string = string[::-1]
    stringToSearch = stringToSearch[::-1]
    if len(string) < len(stringToSearch):
        return False
    return string[:len(stringToSearch)] == stringToSearch

def ConvertImageToAnotherImage(baseImagePath: str, newImagePath: str, newImageExtension: str, *, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image from one format to another and optionally resize it.

    This function takes an image in one format, converts it to another format, and optionally resizes it. It supports various image formats for both input and output.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted image.
    :type newImagePath: str
    :param newImageExtension: The extension of the converted image file, including the dot (e.g., '.png', '.jpg').
    :type newImageExtension: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath, newImagePath, or newImageExtension is not of the correct type, or if customSizeForNewImage is not a valid type.
    :raises FileExistsError: If the source image file does not exist.
    :raises ValueError: If the baseImagePath does not contain a valid image, if the newImageExtension is less than 3 characters long, if newImageExtension does not start with a dot, or if it's not a supported image format.

    :examples:

    # Example usage to convert an image without resizing
    >>> ConvertImageToAnotherImage('input.png', 'output.jpg', '.jpg')

    # Example usage to convert and resize an image
    >>> ConvertImageToAnotherImage('input.png', 'output.jpg', '.jpg', customSizeForNewImage=[200, 150])
    """
    if not isinstance(baseImagePath, str):
        raise TypeError('"baseImagepath" should be of type str.')
    if not isinstance(newImagePath, str):
        raise TypeError('"newImagePath" should be of type str.')
    if not isinstance(newImageExtension, str):
        raise TypeError('"newImageExtension" should be of type str.')
    if not os.path.isfile(baseImagePath):
        raise FileExistsError(f'''The file "{baseImagePath}" doesn't exist.''')
    try:
        baseImage = Image.open(baseImagePath)
    except PIL.UnidentifiedImageError:
        raise ValueError(f'The path of "baseImagePath" is not a valid image. Supported image formats for base image : {__CONVERT_IMAGE_FULLY_SUPPORTED_IMAGE_FORMAT + __CONVERT_IMAGE_READ_ONLY_SUPPORTED_IMAGE_FORMAT}')
    if len(newImageExtension) < 3 :
        raise ValueError('Image extension are atleast 3 caracters long.')
    if newImageExtension[0] != '.':
        newImageExtension = "." + newImageExtension
    if newImageExtension not in __CONVERT_IMAGE_FULLY_SUPPORTED_IMAGE_FORMAT + __CONVERT_IMAGE_WRITE_ONLY_SUPPORTED_IMAGE_FORMAT:
        raise ValueError(f'"newImageExtension" should be one of the supported format for new image : {__CONVERT_IMAGE_FULLY_SUPPORTED_IMAGE_FORMAT + __CONVERT_IMAGE_WRITE_ONLY_SUPPORTED_IMAGE_FORMAT}')
    if not __isStringToSearchAtTheEndOfString(newImagePath, newImageExtension):
        newImagePath += newImageExtension
    if customSizeForNewImage is None:
        baseImage.save(newImagePath)
    else:
        if isinstance(customSizeForNewImage, list):
            tuple(customSizeForNewImage)
        elif not isinstance(customSizeForNewImage, tuple):
            raise TypeError('"customSizeForTheNewImage" should be a list or a tuple or None.')
        if len(customSizeForNewImage) != 2:
            raise ValueError('"customSizeForTheNewImage" should have two elements.')
        if (not isinstance(customSizeForNewImage[0], int)) or (not isinstance(customSizeForNewImage[1], int)):
            raise TypeError('Atleast one of two elements of "customSizeForTheNewImage" is not an integer.')
        baseImage = baseImage.resize(size=customSizeForNewImage)
        baseImage.save(newImagePath)

def ConvertImageToIco(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the ICO (icon) format, optionally resizing it.

    This function takes an image and converts it to the ICO (icon) format. Optionally, you can resize the image before converting it. The ICO format is commonly used for icons in Windows applications.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted ICO image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to ICO format without resizing
    >>> ConvertImageToIco('input.png', 'output.ico')

    # Example usage to convert and resize an image to ICO format
    >>> ConvertImageToIco('input.png', 'output.ico', customSizeForNewImage=[32, 32])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".ico", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPng(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the PNG format, optionally resizing it.

    This function takes an image and converts it to the PNG format. Optionally, you can resize the image before converting it. The PNG format is a widely used lossless image format that supports transparency.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted PNG image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to PNG format without resizing
    >>> ConvertImageToPng('input.jpg', 'output.png')

    # Example usage to convert and resize an image to PNG format
    >>> ConvertImageToPng('input.jpg', 'output.png', customSizeForNewImage=[400, 300])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".png", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToJpg(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the JPEG format, optionally resizing it.

    This function takes an image and converts it to the JPEG format. Optionally, you can resize the image before converting it. The JPEG format is a widely used image format that supports high compression with minimal loss of quality.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted JPEG image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to JPEG format without resizing
    >>> ConvertImageToJpg('input.png', 'output.jpg')

    # Example usage to convert and resize an image to JPEG format
    >>> ConvertImageToJpg('input.png', 'output.jpg', customSizeForNewImage=[800, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".jpg", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToJpeg(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the JPEG format, optionally resizing it.

    This function takes an image and converts it to the JPEG format. Optionally, you can resize the image before converting it. The JPEG format is a widely used image format that supports high compression with minimal loss of quality.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted JPEG image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to JPEG format without resizing
    >>> ConvertImageToJpeg('input.png', 'output.jpeg')

    # Example usage to convert and resize an image to JPEG format
    >>> ConvertImageToJpeg('input.png', 'output.jpeg', customSizeForNewImage=[800, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".jpeg", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToGif(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the GIF format, optionally resizing it.

    This function takes an image and converts it to the GIF format. Optionally, you can resize the image before converting it. The GIF format is a widely used image format that supports animations and is suitable for images with a limited color palette.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted GIF image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to GIF format without resizing
    >>> ConvertImageToGif('input.png', 'output.gif')

    # Example usage to convert and resize an image to GIF format
    >>> ConvertImageToGif('input.png', 'output.gif', customSizeForNewImage=[400, 300])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".gif", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToTiff(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the TIFF format, optionally resizing it.

    This function takes an image and converts it to the TIFF format. Optionally, you can resize the image before converting it. The TIFF format is a high-quality image format that supports lossless compression and is suitable for images that require preservation of detail and quality.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted TIFF image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to TIFF format without resizing
    >>> ConvertImageToTiff('input.png', 'output.tiff')

    # Example usage to convert and resize an image to TIFF format
    >>> ConvertImageToTiff('input.png', 'output.tiff', customSizeForNewImage=[1200, 800])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".tiff", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToWebp(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the WebP format, optionally resizing it.

    This function takes an image and converts it to the WebP format. Optionally, you can resize the image before converting it. The WebP format is a modern image format that provides high compression efficiency and good quality, making it suitable for web images.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted WebP image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to WebP format without resizing
    >>> ConvertImageToWebp('input.png', 'output.webp')

    # Example usage to convert and resize an image to WebP format
    >>> ConvertImageToWebp('input.png', 'output.webp', customSizeForNewImage=[800, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".webp", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToBmp(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the BMP format, optionally resizing it.

    This function takes an image and converts it to the BMP format. Optionally, you can resize the image before converting it. The BMP format is a simple raster image format that stores image data without compression and is suitable for applications that require lossless image quality.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted BMP image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to BMP format without resizing
    >>> ConvertImageToBmp('input.png', 'output.bmp')

    # Example usage to convert and resize an image to BMP format
    >>> ConvertImageToBmp('input.png', 'output.bmp', customSizeForNewImage=[800, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".bmp", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPpm(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the PPM format, optionally resizing it.

    This function takes an image and converts it to the PPM format. Optionally, you can resize the image before converting it. The PPM format is a simple, uncompressed image format suitable for storing raw image data without any loss in quality.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted PPM image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to PPM format without resizing
    >>> ConvertImageToPpm('input.png', 'output.ppm')

    # Example usage to convert and resize an image to PPM format
    >>> ConvertImageToPpm('input.png', 'output.ppm', customSizeForNewImage=[800, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".ppm", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToDds(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the DDS format, optionally resizing it.

    This function takes an image and converts it to the DDS format. Optionally, you can resize the image before converting it. The DDS (DirectDraw Surface) format is commonly used for storing compressed and uncompressed textures in computer graphics applications and games.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted DDS image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to DDS format without resizing
    >>> ConvertImageToDds('input.png', 'output.dds')

    # Example usage to convert and resize an image to DDS format
    >>> ConvertImageToDds('input.png', 'output.dds', customSizeForNewImage=[800, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".dds", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToDib(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the DIB format, optionally resizing it.

    This function takes an image and converts it to the DIB (Device-Independent Bitmap) format. Optionally, you can resize the image before converting it. The DIB format is a format for storing bitmap images in a device-independent way, and it is used in various applications and environments.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted DIB image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to DIB format without resizing
    >>> ConvertImageToDib('input.png', 'output.dib')

    # Example usage to convert and resize an image to DIB format
    >>> ConvertImageToDib('input.png', 'output.dib', customSizeForNewImage=[800, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".dib", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToEps(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the EPS (Encapsulated PostScript) format, optionally resizing it.

    This function takes an image and converts it to the EPS (Encapsulated PostScript) format. Optionally, you can resize the image before converting it. The EPS format is a widely used standard for high-quality vector graphics, often used in the printing and publishing industry.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted EPS image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to EPS format without resizing
    >>> ConvertImageToEps('input.png', 'output.eps')

    # Example usage to convert and resize an image to EPS format
    >>> ConvertImageToEps('input.png', 'output.eps', customSizeForNewImage=[800, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".eps", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToIcns(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the ICNS (Apple Icon Image) format, optionally resizing it.

    This function takes an image and converts it to the ICNS (Apple Icon Image) format, which is commonly used for macOS application icons. Optionally, you can resize the image before converting it.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted ICNS image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to ICNS format without resizing
    >>> ConvertImageToIcns('input.png', 'output.icns')

    # Example usage to convert and resize an image to ICNS format
    >>> ConvertImageToIcns('input.png', 'output.icns', customSizeForNewImage=[128, 128])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".icns", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToMsp(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the MSP (Microsoft Paint) format, optionally resizing it.

    This function takes an image and converts it to the MSP (Microsoft Paint) format, which is commonly used for Microsoft Paint application. Optionally, you can resize the image before converting it.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted MSP image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to MSP format without resizing
    >>> ConvertImageToMsp('input.png', 'output.msp')

    # Example usage to convert and resize an image to MSP format
    >>> ConvertImageToMsp('input.png', 'output.msp', customSizeForNewImage=[128, 128])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".msp", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPcx(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the PCX format, optionally resizing it.

    This function takes an image and converts it to the PCX format, which is a common image format. Optionally, you can resize the image before converting it.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted PCX image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to PCX format without resizing
    >>> ConvertImageToPcx('input.png', 'output.pcx')

    # Example usage to convert and resize an image to PCX format
    >>> ConvertImageToPcx('input.png', 'output.pcx', customSizeForNewImage=[128, 128])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".pcx", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToSgi(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the SGI format, optionally resizing it.

    This function takes an image and converts it to the SGI format, which is a common image format. Optionally, you can resize the image before converting it.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted SGI image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to SGI format without resizing
    >>> ConvertImageToSgi('input.png', 'output.sgi')

    # Example usage to convert and resize an image to SGI format
    >>> ConvertImageToSgi('input.png', 'output.sgi', customSizeForNewImage=[128, 128])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".sgi", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToTga(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the TGA format, optionally resizing it.

    This function takes an image and converts it to the TGA format, which is a common image format. Optionally, you can resize the image before converting it.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted TGA image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to TGA format without resizing
    >>> ConvertImageToTga('input.png', 'output.tga')

    # Example usage to convert and resize an image to TGA format
    >>> ConvertImageToTga('input.png', 'output.tga', customSizeForNewImage=[128, 128])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".tga", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToXbm(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the X Bitmap (XBM) format, optionally resizing it.

    This function takes an image and converts it to the X Bitmap (XBM) format, which is a monochrome image format commonly used for icons and cursors in X Window System. Optionally, you can resize the image before converting it.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted XBM image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to XBM format without resizing
    >>> ConvertImageToXbm('input.png', 'output.xbm')

    # Example usage to convert and resize an image to XBM format
    >>> ConvertImageToXbm('input.png', 'output.xbm', customSizeForNewImage=[64, 64])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".xbm", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPalm(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to the Palm Image format (Palm PDB), optionally resizing it.

    This function takes an image and converts it to the Palm Image format (Palm PDB), which is a format used for images on Palm OS devices. Optionally, you can resize the image before converting it.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted Palm Image.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to Palm format without resizing
    >>> ConvertImageToPalm('input.png', 'output.palm')

    # Example usage to convert and resize an image to Palm format
    >>> ConvertImageToPalm('input.png', 'output.palm', customSizeForNewImage=[160, 160])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".palm", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPdf(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    """
    Convert an image to PDF format, optionally resizing it.

    This function takes an image and converts it to PDF format. Optionally, you can resize the image before converting it.

    :param baseImagePath: The path to the source image.
    :type baseImagePath: str
    :param newImagePath: The path to the converted PDF.
    :type newImagePath: str
    :param customSizeForNewImage: Optional. A tuple or list containing the desired width and height of the converted image. Defaults to None (no resizing).
    :type customSizeForNewImage: tuple[int, int] | list[int, int] | None

    :return: None

    :raises TypeError: If baseImagePath or newImagePath is not of the correct type, or if customSizeForNewImage is not a valid type.

    :examples:

    # Example usage to convert an image to PDF format without resizing
    >>> ConvertImageToPdf('input.png', 'output.pdf')

    # Example usage to convert and resize an image to PDF format
    >>> ConvertImageToPdf('input.png', 'output.pdf', customSizeForNewImage=[400, 600])
    """
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".pdf", customSizeForNewImage=customSizeForNewImage)
