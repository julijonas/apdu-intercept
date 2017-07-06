import logging
import binascii
import string


RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
LIGHT_PURPLE = '\033[94m'
PURPLE = '\033[95m'
BLUE = '\033[96m'
ENDC = '\033[0m'

COMMAND_COLORS = {
    'cla': RED,
    #'ins': YELLOW,
    'p1': LIGHT_PURPLE,
    'p2': LIGHT_PURPLE,
    'lc': GREEN,
    'le': BLUE,
}

RESPONSE_COLORS = {
    'E': RED,
    'W': YELLOW,
    'I': GREEN,
    'S': BLUE,
    '?': LIGHT_PURPLE,
}

_myprintable = " " + string.letters + string.digits + string.punctuation


logger = logging.getLogger()


def bin_to_hex(b):
    return binascii.b2a_hex(b).upper()


class APDUCommand(object):

    def __init__(self, msg, command_desc):
        self.msg = msg

        # header: CLA | INS | P1 | P2
        indexes = {
            'cla': 0,
            'ins': 1,
            'p1': 2,
            'p2': 3,
        }

        # body: [ LC | DATA ] | [ LE ]
        if len(msg) == 5:  # LE
            indexes['le'] = 4
        elif len(msg) > 5:  # LC | DATA | [ LE ]
            indexes['lc'] = 4
            indexes['data'] = 5
            data_size = ord(msg[indexes['lc']])
            data_end = 5 + data_size
            if len(msg) > data_end:  # LC | DATA | LE
                indexes['le'] = data_end

        self.indexes = indexes
        self.parts = {v: k for k, v in indexes.iteritems()}

        self.ins = bin_to_hex(self.msg[self.indexes['ins']])
        self.name, self.desc = command_desc.get(self.ins, (None, None))

    def color(self, data, offset):
        colored = []
        for index, elem in enumerate(data):
            addr = offset + index
            if addr in self.parts and self.parts[addr] in COMMAND_COLORS:
                colored.append(COMMAND_COLORS[self.parts[addr]] + elem + ENDC)
            else:
                colored.append(elem)
        return colored


class APDUResponse(object):

    def __init__(self, msg, response_desc):
        self.msg = msg

        sw1 = bin_to_hex(self.msg[-2])
        sw2 = bin_to_hex(self.msg[-1])

        probable = [
            (sw1, sw2),
            (sw1, sw2[0] + 'X'),
            (sw1, sw2[0] + '-'),
            (sw1, 'XX'),
            (sw1, '--'),
            (sw1[0] + 'X', 'XX'),
            (sw1[0] + '-', '--'),
        ]

        self.sw1 = sw1
        self.sw2 = sw2
        self.cat = None
        self.desc = None
        for p1, p2 in probable:
            if (p1, p2) in response_desc:
                self.cat, self.desc = response_desc[p1, p2]
                break

    def color(self, data, offset):
        if not self.cat:
            return data

        colored = []
        for index, elem in enumerate(data):
            addr = offset + index
            if addr >= len(self.msg) - 2:
                colored.append(RESPONSE_COLORS[self.cat] + elem + ENDC)
            else:
                colored.append(elem)
        return colored


class APDUPrinter(object):

    def __init__(self):
        self.command_desc = self.parse_command_desc("descriptions/commands.txt")
        self.response_desc = self.parse_response_desc("descriptions/responses.txt")

    def parse_command_desc(self, filename):
        command_desc = {}
        with open(filename, "r") as f:
            for line in f:
                name, desc, ins = line[:-1].split("\t")
                command_desc[ins] = name, desc
        return command_desc

    def parse_response_desc(self, filename):
        response_desc = {}
        with open(filename, "r") as f:
            for line in f:
                sw1, sw2, category, desc = line[:-1].split("\t")
                if category not in RESPONSE_COLORS.keys():
                    category = '?'
                response_desc[sw1, sw2] = category, desc
        return response_desc

    def hexdump(self, cmd, indent=0, short=False, linelen=16, offset=0):
        """Generates a nice hexdump of data and returns it. Consecutive lines will
        be indented with indent spaces. When short is true, will instead generate
        hexdump without adresses and on one line.

        Examples:
        hexdump('\x00\x41') -> \
        '0000:  00 41                                             .A              '
        hexdump('\x00\x41', short=True) -> '00 41 (.A)'"""

        def hexable(data, addr):
            elems = cmd.color([binascii.b2a_hex(a).upper() for a in data], addr)
            if not short:
                elems += ["  "] * (linelen - len(elems))
            return " ".join(elems)

        def printable(data, addr):
            return "".join(cmd.color([e in _myprintable and e or "." for e in data], addr))

        data = cmd.msg

        if short:
            return "%s (%s)" % (hexable(data, 0), printable(data, 0))

        format_string = "%04x:  %s  %s"
        result = ""
        (head, tail) = (data[:linelen], data[linelen:])
        pos = 0
        while len(head) > 0:
            if pos > 0:
                result += "\n%s" % (' ' * indent)
            addr = pos + offset
            result += format_string % (addr, hexable(head, addr), printable(head, addr))
            pos += len(head)
            (head, tail) = (tail[:linelen], tail[linelen:])
        return result

    def show_command(self, msg, name):
        cmd = APDUCommand(msg, self.command_desc)
        logger.info("\n%-16s %3d bytes: %-6s %-10s %s\n%s",
                    name, len(msg), cmd.ins, cmd.name, cmd.desc, self.hexdump(cmd))

    def show_response(self, msg, name):
        resp = APDUResponse(msg, self.response_desc)
        logger.info("\n%-16s %3d bytes: %-6s [%s] %s\n%s",
                    name, len(msg), resp.sw1 + " " + resp.sw2, resp.cat, resp.desc, self.hexdump(resp))
