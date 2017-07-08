

class Resp(object):
    SUCCESS = "\x90\x00"
    SUCCESS_FILE_INFO_AVAILABLE = "\x61\x15"

    WRONG_LENGTH = "\x67\x00"
    FILE_NOT_FOUND = "\x6A\x82"
    FAILURE = "\x6A\xF0"
