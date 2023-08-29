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
    if not isinstance(string, str):
        raise TypeError('"filePath" should be of type str.')
    if not isinstance(stringToSearch, str):
        raise TypeError('"extension" should be of type str.')
    string = string[::-1]
    stringToSearch = stringToSearch[::-1]
    if len(string) < len(stringToSearch):
        return False
    return string[:len(stringToSearch)] == stringToSearch

def ConvertImageToAnotherImage(baseImagePath: str, newImagePath: str, newImageExtension: str, *, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
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
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".ico", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPng(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".png", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToJpg(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".jpg", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToJpeg(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".jpeg", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToGif(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".gif", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToTiff(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".tiff", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToWebp(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".webp", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToBmp(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".bmp", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPpm(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".ppm", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToDds(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".dds", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToDib(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".dib", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToEps(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".eps", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToIcns(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".icns", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToMsp(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".msp", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPcx(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".pcx", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToSgi(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".sgi", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToTga(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".tga", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToXbm(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".xbm", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPalm(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".palm", customSizeForNewImage=customSizeForNewImage)

def ConvertImageToPdf(baseImagePath: str, newImagePath: str, customSizeForNewImage: tuple[int, int] | list[int, int] | None = None) -> None:
    ConvertImageToAnotherImage(baseImagePath, newImagePath, ".pdf", customSizeForNewImage=customSizeForNewImage)

