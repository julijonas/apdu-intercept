import logging

from apdu_printer import APDUPrinter

logger = logging.getLogger()


class InterceptAttack(object):
    def __init__(self, os):
        self.os = os
        self.printer = APDUPrinter()

    def attacker_execute(self, msg):
        self.printer.show_command(msg, 'Attacker command')
        resp = self.os.execute(msg)
        self.printer.show_response(resp, 'Resp to attacker')
        return resp

    def user_execute(self, msg):
        self.printer.show_command(msg, 'User command')

        fake_resp = self.respond_to_message(msg)
        if fake_resp:
            self.printer.show_response(fake_resp, 'Fake response')
            return fake_resp
        else:
            resp = self.os.execute(msg)
            self.printer.show_response(resp, 'Response')
            self.read_response(msg, resp)
            return resp

    def respond_to_message(self, msg):
        pass

    def read_response(self, msg, resp):
        pass
