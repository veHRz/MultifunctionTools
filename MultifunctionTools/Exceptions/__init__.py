class SeparatorError(Exception):
    def __init__(self, errorMessage: str):
        super().__init__(errorMessage)
class BadSeparator(SeparatorError):
    ...

class PasswordError(Exception):
    def __init__(self, errorMessage: str):
        super().__init__(errorMessage)
class BadPassword(PasswordError):
    ...
