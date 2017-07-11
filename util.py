import binascii
import string
import struct


def from_hex(line):
    return binascii.unhexlify(line.replace(' ', '').replace(':', '').replace('\n', '').replace('0x', ''))


def to_hex(msg):
    return ' '.join(binascii.b2a_hex(a).upper() for a in msg)


def to_hex_blocks(msg):
    return "\n".join(to_hex(msg[i:i + 8]) for i in range(0, len(msg), 8))


def sxor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


def str_to_int(s):
    return int(s.encode('hex'), 16)


def str8_to_int(s):
    return struct.unpack('>Q', s)[0]


def int_to_str8(i):
    return struct.pack('>Q', i)


PRINTABLE_CHARS = " " + string.letters + string.digits + string.punctuation


def hexdump(self, data, indent=0, short=False, linelen=16, offset=0):
    """Generates a nice hexdump of data and returns it. Consecutive lines will
    be indented with indent spaces. When short is true, will instead generate
    hexdump without adresses and on one line.

    Examples:
    hexdump('\x00\x41') -> \
    '0000:  00 41                                             .A              '
    hexdump('\x00\x41', short=True) -> '00 41 (.A)'"""

    def hexable(data):
        elems = [binascii.b2a_hex(a).upper() for a in data]
        if not short:
            elems += ["  "] * (linelen - len(elems))
        return " ".join(elems)

    def printable(data):
        return "".join([e in PRINTABLE_CHARS and e or "." for e in data])

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
        result += format_string % (addr, hexable(head), printable(head))
        pos += len(head)
        (head, tail) = (tail[:linelen], tail[linelen:])
    return result
