import logging
import sys
import datetime
import re

from mitm_card import MITMCard


class ColorCodeRemovingFormatter(logging.Formatter):
    pattern = re.compile(r'\033\[\d{1,2}m')
    def format(self, record):
        s = super(ColorCodeRemovingFormatter, self).format(record)
        return self.pattern.sub('', s)

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler(sys.stdout))
current_date = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
file_handler = logging.FileHandler("logs/{}.log".format(current_date))
file_handler.setFormatter(ColorCodeRemovingFormatter())
logger.addHandler(file_handler)
logger.setLevel(logging.DEBUG)


mitm = MITMCard('localhost', 35963, 2)

try:
    mitm.run()
except KeyboardInterrupt:
    pass
