import logging
import sys
import datetime
import re
import argparse

from virtual_card import VirtualCard
from relay_os import RelayOS
from gemalto.gemalto_os import GemaltoOS
from intercept_attack import InterceptAttack
from gemalto.mitm_attack import GemaltoMITMAttack
from yubikey.mitm_attack import YubiKeyMITMAttack


logger = logging.getLogger()


class ColorCodeRemovingFormatter(logging.Formatter):
    pattern = re.compile(r'\033\[\d{1,2}m')

    def format(self, record):
        s = super(ColorCodeRemovingFormatter, self).format(record)
        return self.pattern.sub('', s)


if __name__ == '__main__':
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    parser = argparse.ArgumentParser("Launch an intercept or MITM attack.")
    parser.add_argument('-o', '--os', choices=['relay', 'gemalto'], default='relay',
                        help="whether to relay messages to reader or simulate a card (default relay)")
    parser.add_argument('-r', '--reader', metavar='N', type=int, default=0,
                        help="reader number to relay messages to, use with os relay (default 0)")
    parser.add_argument('-a', '--attack', choices=['intercept', 'gemalto', 'yubikey'], default='intercept',
                        help="attack to execute before relaying messages (default intercept)")

    args = parser.parse_args()

    if args.os == 'relay':
        current_date = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        file_handler = logging.FileHandler("logs/{}.log".format(current_date))
        file_handler.setFormatter(ColorCodeRemovingFormatter())
        logger.addHandler(file_handler)

    logger.info("Launched virtual smart card os=%s attack=%s", args.os, args.attack)

    os = None
    if args.os == 'relay':
        os = RelayOS(args.reader)
    elif args.os == 'gemalto':
        os = GemaltoOS()

    attack = None
    if args.attack == 'intercept':
        attack = InterceptAttack(os)
    elif args.attack == 'gemalto':
        attack = GemaltoMITMAttack(os)
    elif args.attack == 'yubikey':
        attack = YubiKeyMITMAttack(os)

    card = VirtualCard('localhost', 35963, os, attack)

    try:
        card.run()
    except KeyboardInterrupt:
        pass
