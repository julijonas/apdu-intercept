from __future__ import print_function

from relay_os import RelayOS
from util import from_hex


def apdu(msg, description=None):
    if description:
        print(description)
    # print('>>', msg)
    resp = relay.execute(from_hex(msg))
    # print('<<', to_hex(resp))
    return resp

print('Interactive smart card')

relay = RelayOS(0)

apdu('00 A4 04 00 0C A0 00 00 00 18 0C 00 00 01 63 42 00',
     'Select DF by label AID')

apdu('00 20 00 81 10 31 32 33 34 35 36 00 00 00 00 00 00 00 00 00 00',
     'Verify PIN')

apdu('00 A4 08 0C 02 00 02')

apdu('00 B0 00 00 20')



# apdu('80 84 00 00 08')


# challenge = apdu('80 82 00 00 48'+('00'*72))
# challenge

# apdu('80 82 00 00 48 8D 8F 2B 68 A1 50 71 27 C6 16 8A'
#      '49 20 5E 86 4F 91 25 8E EB 58 0B A1 C2 7F 94 7E'
#      '8F F5 EE C8 C6 F6 E6 CB 2A CA 15 5C 0F 17 AF 91'
#      '9B FD 47 C1 F6 79 8E EE 12 76 95 1C 3A BB 8E 96'
#      '56 B6 B2 BB 31 14 4E D8 54 F9 32 2A 06')



# def get_something(item):
#     a = apdu('00 CB 00 FF 0A B6 03 83 01'+item+'7F 49 02 81 00')
#     #apdu('00 C0 00 00 0E')
#     b = apdu('00 CB 00 FF 0A B6 03 83 01'+item+'7F 49 02 82 00')
#     #apdu('00 C0 00 00 0D')
#     return a, b




# ls = []
# for x in range(256):
#     x = "%02X" % x
#     a, b = get_something(x)
#     print(x, a[-2] == '\x61', b[-2] == '\x61')
#     ls.append((a, b))


# apdu('00 A4 08 00 04 50 00 50 02',
#      'Select DF 50 00')
#
# apdu('00 C0 00 00 15',
#      'GET RESPONSE, details about file')
# apdu('00 B0 00 00 FF',
#      'READ BINARY')
# # exit()
# for x in range(10):
#     apdu('00 B0 0' + str(x) + ' 00 00',
#          'READ BINARY')


# apdu('00 CA df30 08')
# apdu('00 B0 00 00 80')
