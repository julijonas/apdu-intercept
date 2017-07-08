import logging
import sys

from util import from_hex, to_hex_blocks
from .crypto import GemaltoCrypto, mac_cr, decrypt_cr


def test_challenge_response():
    challenge = from_hex('53 30 77 04 FB 36 DD 39')

    lib_msg = from_hex('''
    80 82 00 00 48 74 91 3E 6A 34 54 3F 85 05 D0 A6
    FE E6 F3 52 1B 02 FB 4F 5B 9A B4 63 42 EF 04 13
    B7 3D 94 9A F6 A3 99 E2 E0 0D 6B 06 6B DD E0 B0
    AD 5A AE 9F 9F 65 44 F7 37 2D 33 41 E2 32 1E 0E
    CD 0D 54 78 87 EE 39 DC 4D AC 29 3D 7B
    ''')

    card_msg = from_hex('''
    14 F5 06 49 D8 3B 86 CC 16 97 53 87 45 AC 2A C7
    DC 6A 54 84 26 77 FF 31 0A B2 51 3E 39 CB 59 CA
    0E 9B D3 4F 60 55 3B 93 0D 48 8C 50 04 28 5A F9
    6B C4 B8 B2 7B 3D 00 EB CB A7 23 25 63 B1 93 B9
    34 92 28 9D 81 01 78 E6 90 00
    ''')

    lib_encr = lib_msg[5:-8]
    lib_mac = lib_msg[-8:]
    card_encr = card_msg[:-10]
    card_mac = card_msg[-10:-2]

    lib_decr = decrypt_cr(lib_encr)
    card_decr = decrypt_cr(card_encr)

    logger.info("lib decr\n%s", to_hex_blocks(lib_decr))
    logger.info("card decr\n%s", to_hex_blocks(card_decr))

    lib_mac_calc = mac_cr(lib_encr)
    card_mac_calc = mac_cr(card_encr)

    assert challenge == lib_decr[16:24]
    assert challenge == card_decr[:8]
    assert lib_mac == lib_mac_calc
    assert card_mac == card_mac_calc


def test_mac_message():
    c = GemaltoCrypto()
    c.card_challenge = from_hex("""
    00 11 22 33 44 55 66 77
    """)
    c.card_nonce = from_hex("""
    00 01 02 03 04 05 06 07
    08 09 0A 0B 0C 0D 0E 0F
    10 11 12 13 14 15 16 17
    18 19 1A 1B 1C 1D 1E 1F
    """)
    c.lib_random = from_hex("""
    CE D9 89 9E 95 A7 BA 4B
    0F 07 C7 0C 49 A0 55 46
    """)
    c.lib_constant = from_hex("""
    22 34 00 00 AF 04 E3 A9
    """)
    c.lib_nonce = from_hex("""
    5A AF CC A9 F5 13 C3 F0
    D5 EF 41 3A FE 29 11 63
    9E C2 D4 F4 EE A2 B4 D9
    35 29 B0 87 DB 64 03 1F
    """)

    message = from_hex('''
    0C D6 00 00 2C 81 20 2E 35 37 38 5A 00 30 36 31
    31 32 37 33 30 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 8E 08 25 F0 9B ED D2 A6 07
    42
    ''')

    c.calc_mac_params()
    assert c.check_message_mac(message)


def test_second_mac_message():
    c = GemaltoCrypto()
    c.card_challenge = from_hex("""
    00 11 22 33 44 55 66 77
    """)
    c.card_nonce = from_hex("""
    00 01 02 03 04 05 06 07
    08 09 0A 0B 0C 0D 0E 0F
    10 11 12 13 14 15 16 17
    18 19 1A 1B 1C 1D 1E 1F
    """)
    c.lib_random = from_hex("""
    A3 BB 03 14 37 06 A0 DC
    3E 2D 8B CF 6C 2B F4 A1
    """)
    c.lib_constant = from_hex("""
    22 34 00 00 AF 04 E3 A9
    """)
    c.lib_nonce = from_hex("""
    4F 27 FB F2 8C E5 EC 1F
    44 2E D1 06 E0 F1 29 1D
    97 2F 0F E2 E7 1E 3B C1
    ED 1B 01 B3 74 9D 18 48
    """)

    message = from_hex('''
    0C D6 00 00 30 81 24 30 22 30 04 03 02 06 40 30
    0E 04 01 7B 03 02 00 8B 03 02 03 48 02 01 0A A1
    0A 30 08 30 02 04 00 02 02 04 00 8E 08 FC 13 48
    3C 8F 35 44 C7
    ''')

    c.calc_mac_params()
    c.mac_counter = 2
    assert c.check_message_mac(message)


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler(sys.stdout))
    logger.setLevel(logging.DEBUG)

    test_challenge_response()
    test_mac_message()
    test_second_mac_message()
