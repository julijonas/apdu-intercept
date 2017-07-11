from __future__ import print_function
import logging
import sys
import os

from relay_os import RelayOS
from util import from_hex, to_hex, to_hex_blocks
from gemalto.crypto import GemaltoCrypto


logger = logging.getLogger()

logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))


def apdu(msg, description=None):
    if description:
        print('>>', description)
    # print('>>', msg)
    resp = relay.execute(from_hex(msg))
    # print('<<', to_hex(resp))
    return resp


print('Interactive smart card')

relay = RelayOS(0)


apdu('00 A4 04 00 0C A0 00 00 00 18 0C 00 00 01 63 42 00',
     'Select DF by label AID')
# apdu('00 CA 9F 7F 2D')
# apdu('00 A4 08 00 02 00 01')
# apdu('00 C0 00 00 15')


apdu('00 20 00 81 10 31 32 33 34 35 36 00 00 00 00 00 00 00 00 00 00',
     'Verify PIN')

c = GemaltoCrypto()
c.lib_nonce = os.urandom(32)
c.lib_random = os.urandom(16)
c.lib_constant = from_hex('22 34 00 00 AF 04 E3 A9')

apdu('00 22 41 A4 06 83 01 01 95 01 80', 'MSE')

card_challenge = apdu('80 84 00 00 08', 'get challenge')
print("!! parse card challenge")
c.parse_card_challenge(card_challenge)

print("!! make lib challenge")
lib_challenge = c.make_lib_challenge()
print("!! parse lib challenge")
c.parse_lib_challenge(lib_challenge)

ret = apdu(to_hex(lib_challenge), 'lib challenge')
assert ret == '\x61\x48'

card_ch_response = apdu('80 C0 00 00 48', 'get response')
print("!! parse card ch response")
c.parse_card_ch_response(card_ch_response)

print("!! calc mac params")
c.calc_mac_params()
