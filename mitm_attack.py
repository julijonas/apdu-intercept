import logging

from apdu_printer import APDUPrinter
from util import from_hex

logger = logging.getLogger()

RESPONSE_FAILURE = '6A F0'


class MITMAttack(object):
    def __init__(self, os):
        self.os = os
        self.printer = APDUPrinter()
        self.responding_generate_asymm = False

    def attacker_execute(self, msg):
        self.printer.show_command(msg, 'Attacker command')
        resp = self.os.execute(msg)
        self.printer.show_response(resp, 'Resp to attacker')
        return resp

    def user_execute(self, msg):
        self.printer.show_command(msg, 'User command')

        fake_resp = self.respond(msg)
        if fake_resp:
            fake_resp = from_hex(fake_resp)
            self.printer.show_response(fake_resp, 'Fake response')
            return fake_resp
        else:
            resp = self.os.execute(msg)
            self.printer.show_response(resp, 'Response')
            return resp

    def respond(self, msg):
        pass
