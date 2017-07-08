from __future__ import print_function
import logging
import sys

from util import from_hex
from gemalto.crypto import GemaltoCrypto


logging.basicConfig(level=logging.DEBUG, format=None, stream=sys.stdout)


crypto = GemaltoCrypto()

crypto.parse_card_challenge(from_hex('''
C9 93 6F E0 48 29 B5 43 90 00
'''))

print()


crypto.parse_lib_challenge(from_hex('''
80 82 00 00 48 10 49 F7 E3 08 0A 93 D1 B5 E6 20
AF 68 1A 7E 5E 78 5C 50 5D 52 BD 2C E9 2C CB 64
BE 8F DD 17 C2 EC 5B 70 59 6C 9E ED 01 84 67 B9
54 EA 68 1D 08 A2 0A D0 A0 FC 22 2E 9E 47 E8 FC
7C EF 9F CB 57 2F 5B 26 09 90 68 B8 9E
'''))

print()

crypto.parse_card_ch_response(from_hex('''
BD 23 61 C3 DE 90 C4 88 89 CD B0 99 BA 50 23 90
9D B5 A3 97 98 14 92 59 19 CC 91 BB 6A A0 7F C2
8A C3 78 99 6F DE FD 4B 4A B8 66 86 F9 FF 57 CC
F2 9D 30 C4 0B 42 5D 51 E7 FB 6D 74 95 D7 FA CF
1C DE 4C 98 19 8A 20 0A 90 00
'''))

print()

crypto.calc_mac_params()

print()

crypto.check_message_mac(from_hex('''
0C D6 00 00 2C 81 20 2E 32 30 37 5A 00 32 37 30
39 33 31 34 35 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 8E 08 30 CF B2 A8 4C 19 A2
AF
'''))

print()

crypto.check_message_mac(from_hex('''
0C C0 00 00 0E
'''))

print()

crypto.check_response_mac(from_hex('''
99 02 90 00 8E 08 EA 65 1F 43 05 A5 E0 D3 90 00
'''))

