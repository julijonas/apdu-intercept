import logging

from virtualsmartcard.VirtualSmartcard import SmartcardOS

from resp_codes import Resp
from util import from_hex
from .crypto import GemaltoCrypto

logger = logging.getLogger(__name__)


class GemaltoOS(SmartcardOS):
    def __init__(self):
        self.file = None
        self.data_tag = None
        self.crypto = GemaltoCrypto()
        self.crypto.card_challenge = from_hex("00 11 22 33 44 55 66 77")
        self.crypto.card_nonce = "".join(chr(i) for i in range(32))

    def powerDown(self):
        pass

    def reset(self):
        pass

    def powerUp(self):
        pass

    def execute(self, msg):
        # SELECT FILE AID
        if msg == from_hex("00 A4 04 00 0C A0 00 00 00 18 0E 00 00 01 63 42 00"):
            return Resp.FILE_NOT_FOUND
        if msg == from_hex("00 A4 04 00 0C A0 00 00 00 18 0C 00 00 01 63 42 00"):
            return Resp.SUCCESS

        # GET DATA
        if msg == from_hex("00 CA 9F 7F 2D"):
            return from_hex("""
            9F 7F 2A 47 90 50 81 12 91 11 02 02 01 22 34 00
            00 AF 04 E3 A9 40 82 30 23 12 93 30 23 20 05 30
            23 00 00 00 14 00 00 00 00 00 00 00 00 90 00
            """)
        if msg == from_hex("00 CA DF 30"):
            return from_hex("6C 08")
        if msg == from_hex("00 CA DF 30 08"):
            return from_hex("DF 30 05 76 33 2E 30 33 90 00")

        # SELECT FILE
        if msg == from_hex("00 A4 08 0C 02 2F 00"):
            self.file = from_hex("2F 00")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 02 2F 00"):
            self.file = from_hex("2F 00")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("2F 00") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 00 17 82 01 01 83 02 2F 00 8A 01 05
            8C 03 03 FF 00 90 00
            """)

        if msg == from_hex("00 A4 08 0C 04 50 00 50 31"):
            self.file = from_hex("50 00 50 31")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 04 50 00 50 31"):
            self.file = from_hex("50 00 50 31")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("50 00 50 31") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 00 54 82 01 01 83 02 50 31 8A 01 05
            8C 03 03 FF 00 90 00
            """)

        if msg == from_hex("00 A4 08 0C 04 50 00 50 06"):
            self.file = from_hex("50 00 50 06")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 04 50 00 50 06"):
            self.file = from_hex("50 00 50 06")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("50 00 50 06") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 00 C0 82 01 01 83 02 50 06 8A 01 05
            8C 03 03 13 00 90 00
            """)


        if msg == from_hex("00 A4 08 0C 04 50 00 50 32"):
            self.file = from_hex("50 00 50 32")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 04 50 00 50 32"):
            self.file = from_hex("50 00 50 32")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("50 00 50 32") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 00 2B 82 01 01 83 02 50 32 8A 01 05
            8C 03 03 D2 00 90 00
            """)

        if msg == from_hex("00 A4 08 0C 04 50 00 50 33"):
            self.file = from_hex("50 00 50 33")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 04 50 00 50 33"):
            self.file = from_hex("50 00 50 33")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("50 00 50 33") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 06 00 82 01 01 83 02 50 33 8A 01 05
            8C 03 03 C1 00 90 00
            """)

        if msg == from_hex("00 A4 08 0C 02 00 01"):
            self.file = from_hex("00 01")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 02 00 01"):
            self.file = from_hex("00 02 00 01")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("00 02 00 01") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 00 08 82 01 01 83 02 00 01 8A 01 05
            8C 03 03 FF 00 90 00
            """)

        if msg == from_hex("00 A4 08 0C 02 00 02"):
            self.file = from_hex("00 02")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 02 00 02"):
            self.file = from_hex("00 02")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("00 02") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 00 20 82 01 01 83 02 00 02 8A 01 05
            8C 03 03 00 00 90 00
            """)

        if msg == from_hex("00 A4 02 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"):
            return Resp.WRONG_LENGTH

        if msg == from_hex("00 A4 08 0C 04 50 00 50 34"):
            self.file = from_hex("50 00 50 34")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 04 50 00 50 34"):
            self.file = from_hex("50 00 50 34")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("50 00 50 34") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 03 A4 82 01 01 83 02 50 34 8A 01 05
            8C 03 03 FF 00 90 00
            """)

        if msg == from_hex("00 A4 08 0C 04 50 00 50 02"):
            self.file = from_hex("50 00 50 02")
            return Resp.SUCCESS
        if msg == from_hex("00 A4 08 00 04 50 00 50 02"):
            self.file = from_hex("50 00 50 02")
            return Resp.SUCCESS_FILE_INFO_AVAILABLE
        if self.file == from_hex("50 00 50 02") and msg == from_hex("00 C0 00 00 15"):
            return from_hex("""
            6F 13 81 02 06 00 82 01 01 83 02 50 02 8A 01 05
            8C 03 03 C1 00 90 00
            """)


        # READ BINARY
        if msg == from_hex("00 B0 00 00 08") and self.file == from_hex("00 01"):
            return from_hex("30 40 00 1A 66 83 29 71 90 00")

        if msg == from_hex("00 B0 00 00 20") and self.file == from_hex("00 02"):
            return magic("30 30 30 5A 00 30 30 30 30 30 30 30 30")
            return magic("35 34 36 5A 00 32 39 31 39 32 34 32 39")
            return magic("33 31 32 5A 00 30 33 31 36 32 32 33 39")
            return magic("35 35 34 5A 00 30 33 31 35 31 33 31 30")
            return magic("33 39 31 5A 00 33 30 31 33 32 33 30 31")

        if msg == from_hex("00 B0 00 00 17") and self.file == from_hex("2F 00"):
            return from_hex("""
            61 15 4F 0D E8 28 BD 08 0F 01 47 65 6D 20 50 31
            35 51 04 3F 00 50 00 90 00
            """)

        if msg == from_hex("00 B0 00 00 54") and self.file == from_hex("50 00 50 31"):
            return from_hex("""
            A8 0A 30 08 04 06 3F 00 50 00 50 06 A0 0A 30 08 
            04 06 3F 00 50 00 50 01 A1 0A 30 08 04 06 3F 00 
            50 00 50 02 A4 0A 30 08 04 06 3F 00 50 00 50 03 
            A7 0A 30 08 04 06 3F 00 50 00 50 04 A7 0A 30 08 
            04 06 3F 00 50 00 50 05 A3 0A 30 08 04 06 3F 00 
            50 00 50 07 90 00                               
            """)

        if msg == from_hex("00 B0 00 00 C0") and self.file == from_hex("50 00 50 06"):
            return from_hex('''
            30 31 30 11 0C 08 55 73 65 72 20 50 49 4E 03 02
            06 C0 04 01 82 30 03 04 01 81 A1 17 30 15 03 03
            04 8C 10 0A 01 02 02 01 06 02 01 10 80 02 00 81
            04 01 00 30 2C 30 0C 0C 06 53 4F 20 50 49 4E 03
            02 06 C0 30 03 04 01 82 A1 17 30 15 03 03 04 9D
            10 0A 01 02 02 01 06 02 01 10 80 02 00 82 04 01
            00 02 00 82 04 01 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            90 00
            ''')

        if msg == from_hex("00 B0 00 00 2B") and self.file == from_hex("50 00 50 32"):
            return from_hex('''
            30 29 02 01 01 04 08 30 40 00 1A 66 83 29 71 0C
            0C 47 65 6D 61 6C 74 6F 20 53 2E 41 2E 80 08 47
            65 6D 50 31 35 2D 31 03 02 05 60 90 00
            ''')

        if self.file == from_hex("50 00 50 33"):
            if msg == from_hex("00 B0 00 00 EE"):
                return from_hex("""
                30 11 30 0F 04 06 3F 00 50 00 50 40 02 01 00 80
                02 75 30 30 14 30 0F 04 06 3F 00 50 00 50 50 02
                01 00 80 02 0F A0 04 01 81 30 0A 30 02 04 00 04
                01 81 02 01 07 30 0A 30 02 04 00 04 01 81 02 01
                08 30 0A 30 02 04 00 04 01 81 02 01 0D 30 0A 30
                02 04 00 04 01 81 02 01 0E 30 0A 30 02 04 00 04
                01 81 02 01 09 30 0A 30 02 04 00 04 01 81 02 01
                0A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 00
                """)

            """
            30 11 30 0F 04 06 3F 00 50 00 50 40 02 01 00 80
            02 75 30 30 14 30 0F 04 06 3F 00 50 00 50 50 02
            01 00 80 02 0F A0 04 01 81 30 0A 30 02 04 00 04
            01 81 02 01 03 30 0A 30 02 04 00 04 01 81 02 01
            04 30 0A 30 02 04 00 04 01 81 02 01 05 30 0A 30
            02 04 00 04 01 81 02 01 07 30 0A 30 02 04 00 04
            01 81 02 01 08 30 0A 30 02 04 00 04 01 81 02 01
            09 30 0A 30 02 04 00 04 01 81 02 01 0D 30 0A 30
            02 04 00 04 01 81 02 01 0E 30 0A 30 02 04 00 04
            01 81 02 01 0A 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 00
            """
            if msg in [from_hex(x) for x in ["00 B0 00 EE EE",
                                             "00 B0 01 DC EE",
                                             "00 B0 02 CA EE",
                                             "00 B0 03 B8 EE",
                                             "00 B0 04 A6 EE"]]:
                return from_hex("""
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 00
                """)
            if msg == from_hex("00 B0 05 94 6C"):
                return from_hex('''
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 90 00
                ''')

        if self.file == from_hex("50 00 50 34"):
            contents = [
                '''
                00 B0 00 00 EE
                ''',
                '''
                30 4B 30 23 0C 1A 52 53 41 20 50 72 69 76 61 74
                65 20 31 2D 32 30 34 38 2D 44 65 63 2D 53 69 67
                03 02 06 C0 04 01 81 30 16 04 09 52 53 41 20 70
                72 6B 20 31 03 02 02 74 03 02 04 B0 02 01 03 A0
                00 A1 0A 30 08 30 02 04 00 02 02 08 00 30 4B 30
                23 0C 1A 52 53 41 20 50 72 69 76 61 74 65 20 32
                2D 32 30 34 38 2D 44 65 63 2D 53 69 67 03 02 06
                C0 04 01 81 30 16 04 09 52 53 41 20 70 72 6B 20
                32 03 02 02 74 03 02 04 B0 02 01 04 A0 00 A1 0A
                30 08 30 02 04 00 02 02 08 00 30 4B 30 23 0C 1A
                52 53 41 20 50 72 69 76 61 74 65 20 33 2D 32 30
                34 38 2D 44 65 63 2D 53 69 67 03 02 06 C0 04 01
                81 30 16 04 09 52 53 41 20 70 72 6B 20 33 03 02
                02 74 03 02 04 B0 02 01 05 A0 00 A1 0A 30 08 30
                02 04 00 02 02 08 00 30 4B 30 23 0C 1A 52 90 00
                ''',
                '''
                00 B0 00 EE EE
                ''',
                '''
                53 41 20 50 72 69 76 61 74 65 20 34 2D 32 30 34
                38 2D 44 65 63 2D 53 69 67 03 02 06 C0 04 01 81
                30 16 04 09 52 53 41 20 70 72 6B 20 34 03 02 02
                74 03 02 04 B0 02 01 06 A0 00 A1 0A 30 08 30 02
                04 00 02 02 08 00 30 4B 30 22 0C 16 52 53 41 20
                50 72 69 76 61 74 65 20 35 2D 32 30 34 38 2D 53
                69 67 03 02 06 C0 04 01 81 02 01 01 30 17 04 09
                52 53 41 20 70 72 6B 20 35 03 03 06 30 40 03 02
                04 B0 02 01 07 A0 00 A1 0A 30 08 30 02 04 00 02
                02 08 00 30 4B 30 22 0C 16 52 53 41 20 50 72 69
                76 61 74 65 20 36 2D 32 30 34 38 2D 53 69 67 03
                02 06 C0 04 01 81 02 01 01 30 17 04 09 52 53 41
                20 70 72 6B 20 36 03 03 06 30 40 03 02 04 B0 02
                01 08 A0 00 A1 0A 30 08 30 02 04 00 02 02 08 00
                30 4B 30 23 0C 1A 52 53 41 20 50 72 69 76 90 00
                ''',
                '''
                00 B0 01 DC EE
                ''',
                '''
                61 74 65 20 37 2D 31 30 32 34 2D 44 65 63 2D 53
                69 67 03 02 06 C0 04 01 81 30 16 04 09 52 53 41
                20 70 72 6B 20 37 03 02 02 74 03 02 04 B0 02 01
                09 A0 00 A1 0A 30 08 30 02 04 00 02 02 04 00 30
                4B 30 23 0C 1A 52 53 41 20 50 72 69 76 61 74 65
                20 38 2D 31 30 32 34 2D 44 65 63 2D 53 69 67 03
                02 06 C0 04 01 81 30 16 04 09 52 53 41 20 70 72
                6B 20 38 03 02 02 74 03 02 04 B0 02 01 0A A0 00
                A1 0A 30 08 30 02 04 00 02 02 04 00 30 4B 30 23
                0C 1A 52 53 41 20 50 72 69 76 61 74 65 20 39 2D
                31 30 32 34 2D 44 65 63 2D 53 69 67 03 02 06 C0
                04 01 81 30 16 04 09 52 53 41 20 70 72 6B 20 39
                03 02 02 74 03 02 04 B0 02 01 0B A0 00 A1 0A 30
                08 30 02 04 00 02 02 04 00 30 4D 30 24 0C 1B 52
                53 41 20 50 72 69 76 61 74 65 20 31 30 2D 90 00
                ''',
                '''
                00 B0 02 CA DA
                ''',
                '''
                31 30 32 34 2D 44 65 63 2D 53 69 67 03 02 06 C0
                04 01 81 30 17 04 0A 52 53 41 20 70 72 6B 20 31
                30 03 02 02 74 03 02 04 B0 02 01 0C A0 00 A1 0A
                30 08 30 02 04 00 02 02 04 00 30 4D 30 23 0C 17
                52 53 41 20 50 72 69 76 61 74 65 20 31 31 2D 31
                30 32 34 2D 53 69 67 03 02 06 C0 04 01 81 02 01
                01 30 18 04 0A 52 53 41 20 70 72 6B 20 31 31 03
                03 06 30 40 03 02 04 B0 02 01 0D A0 00 A1 0A 30
                08 30 02 04 00 02 02 04 00 30 4D 30 23 0C 17 52
                53 41 20 50 72 69 76 61 74 65 20 31 32 2D 31 30
                32 34 2D 53 69 67 03 02 06 C0 04 01 81 02 01 01
                30 18 04 0A 52 53 41 20 70 72 6B 20 31 32 03 03
                06 30 40 03 02 04 B0 02 01 0E A0 00 A1 0A 30 08
                30 02 04 00 02 02 04 00 00 00 90 00
                ''',
            ]
            contents = [from_hex(x) for x in contents]
            contents = dict(zip(contents[::2], contents[1::2]))
            if msg in contents.keys():
                return contents[msg]

        if msg == from_hex("00 B0 00 00 EE") and self.file == from_hex("50 00 50 02"):
            return from_hex('''
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 00
            ''')

        # VERIFY
        if msg == from_hex("00 20 00 81 00"):
            return from_hex("63 C3")
        if msg == from_hex("00 20 00 82 00"):
            return from_hex("63 C3")
        if msg == from_hex("00 20 00 81 10 31 32 33 34 35 36 00 00 00 00 00 00 00 00 00 00"):
            return Resp.SUCCESS

        # MANAGE SECURITY ENVIRONMENT
        if msg == from_hex("00 22 41 A4 06 83 01 01 95 01 80"):
            return Resp.SUCCESS

        # Sending challenge
        if msg == from_hex("80 84 00 00 08"):
            return self.crypto.make_card_challenge()

        # Responding to challenge
        if msg.startswith(from_hex("80 82 00 00 48")):
            self.crypto.parse_lib_challenge(msg)
            self.crypto.calc_mac_params()
            return from_hex("61 48")

        if self.crypto.lib_nonce and msg == from_hex("80 C0 00 00 48"):
            return self.crypto.make_card_ch_response()

        # MAC verification for class 0C
        if msg[0] == "\x0C":
            self.crypto.check_message_mac(msg)

        if self.file == from_hex("00 02"):
            if msg.startswith(from_hex("0C D6 00 00 2C")):
                return from_hex("61 0E")
            if msg == from_hex("0C C0 00 00 0E"):
                return self.crypto.make_response(from_hex("99 02 90 00"), Resp.SUCCESS)

        if self.file == from_hex("50 00 50 02"):
            if msg.startswith(from_hex("0C D6 00 00 30")):  # UPDATE BINARY
                return from_hex("61 0E")
            if msg == from_hex("0C C0 00 00 0E"):
                return self.crypto.make_response(from_hex("99 02 90 00"), Resp.SUCCESS)

        # if msg.startswith(from_hex("0C CB 00 FF 16 81 0A B6 03 83 01")): #  0C 7F 49 02 81 00 8E 08 30 29 18 19 0A 2B 32 B4
        #     self.data_tag == msg[11] + msg[15]
        #     if msg[15] == '\x81':
        #         return from_hex("61 9B")
        #     if msg[15] == '\x82':
        #         return from_hex("61 11")
        # if self.data_tag and msg == from_hex("00 C0 00 00 8E"):
        #     return from_hex('''
        #     81 81 8E B6 03 83 01 ''' + self.data_tag[0] + ''' 7F 49 82 00 84 81 82 00
        #     80 93 FE 70 51 AE DE F6 E4 AC 52 36 B7 B6 F1 3F
        #     90 4C 2B 9B EA 81 2C 32 67 E3 DF 6E F6 A3 BF 87
        #     F9 CD E4 27 C8 01 61 CC 61 A6 CB 2F 21 67 5E B8
        #     46 BB 98 F9 54 06 B4 05 4B 2A 2C C1 F3 3E 1D A2
        #     38 BB 0B E9 A6 38 46 CE D0 1B 01 B9 3C 53 37 10
        #     79 42 3B 9D 66 B7 00 0E F2 AB 8A 0A 04 DD 72 3D
        #     B1 86 4C 64 CE 96 18 8B 68 E7 66 A6 1A 3E 96 C7
        #     DC 08 71 EA 09 D6 73 73 3E D2 A9 F2 2E 03 A9 76
        #     1F 8E 08 E1 47 93 FF D8 18 E2 27 90 00
        #     ''')
        # if self.data_tag and msg == from_hex("00 ")







        # yolo
        return from_hex("DEADDEADDEADDEAD")






    def getATR(self):
        return from_hex("3B7D00000080318065B08300000083009000")


def magic(value):
    return from_hex("""
            2E """+value+""" 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            90 00
            """)
