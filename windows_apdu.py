import logging
import sys

from apdu_printer import APDUPrinter
from util import from_hex

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.DEBUG)


transmitted = 'transmitted:'
received = 'received:'


printer = APDUPrinter()


for line in open('windows_apdu.log'):
    line = line.strip()
    if line.startswith(transmitted):
        printer.show_command(from_hex(line[len(transmitted):]), 'Command')
    elif line.startswith(received):
        printer.show_response(from_hex(line[len(received):]), 'Response')
