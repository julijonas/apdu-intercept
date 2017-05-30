import logging
import sys
import atexit
import datetime
import socket
import struct
import errno
import re

from relay_os import RelayOS
from apdu_printer import APDUPrinter



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


_Csizeof_short = len(struct.pack('h', 0))

VPCD_CTRL_LEN = 1
VPCD_CTRL_OFF = 0
VPCD_CTRL_ON = 1
VPCD_CTRL_RESET = 2
VPCD_CTRL_ATR = 4


class MITM(object):
    """
    This class is responsible for maintaining the communication of the virtual
    PCD and the emulated smartcard. vpicc and vpcd communicate via a socket.
    The vpcd sends command APDUs (which it receives from an application) to the
    vicc. The vicc passes these CAPDUs on to an emulated smartcard, which
    produces a response APDU. This RAPDU is then passed back by the vicc to
    the vpcd, which forwards it to the application.
    """

    def __init__(self, host, port, readernum):

        self.os = RelayOS(readernum)

        # Connect to the VPCD
        self.host = host
        self.port = port

        try:
            self.sock = self.connectToPort(host, port)
            self.sock.settimeout(None)
            self.server_sock = None
        except socket.error as e:
            logging.error("Failed to open socket: %s", str(e))
            logging.error("Is pcscd running at %s? Is vpcd loaded? Is a \
                          firewall blocking port %u?", host, port)
            sys.exit()

        logging.info("Connected to virtual PCD at %s:%u", host, port)

        atexit.register(self.stop)

    @staticmethod
    def connectToPort(host, port):
        """
        Open a connection to a given host on a given port.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock

    @staticmethod
    def openPort(port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', port))
        server_socket.listen(0)
        logging.info("Waiting for vpcd on port " + str(port))
        (client_socket, address) = server_socket.accept()
        return (client_socket, server_socket, address[0])

    def __sendToVPICC(self, msg):
        """ Send a message to the vpcd """
        self.sock.sendall(struct.pack('!H', len(msg)) + msg)

    def __recvFromVPICC(self):
        """ Receive a message from the vpcd """
        # receive message size
        while True:
            try:
                sizestr = self.sock.recv(_Csizeof_short)
            except socket.error as e:
                if e.errno == errno.EINTR:
                    continue
            break
        if len(sizestr) == 0:
            logging.info("Virtual PCD shut down")
            raise socket.error
        size = struct.unpack('!H', sizestr)[0]

        # receive and return message
        if size:
            while True:
                try:
                    msg = self.sock.recv(size)
                except socket.error as e:
                    if e.errno == errno.EINTR:
                        continue
                break
            if len(msg) == 0:
                logging.info("Virtual PCD shut down")
                raise socket.error
        else:
            msg = None

        return size, msg

    def run(self):
        """
        Main loop of the vpicc. Receives command APDUs via a socket from the
        vpcd, dispatches them to the emulated smartcard and sends the resulting
        respsonse APDU back to the vpcd.
        """
        printer = APDUPrinter()

        while True:
            try:
                (size, msg) = self.__recvFromVPICC()
            except socket.error as e:
                if not self.host:
                    logging.info("Waiting for vpcd on port " + str(self.port))
                    (self.sock, address) = self.server_sock.accept()
                    continue
                else:
                    sys.exit()

            if not size:
                logging.warning("Error in communication protocol (missing \
                                size parameter)")
            elif size == VPCD_CTRL_LEN:
                if msg == chr(VPCD_CTRL_OFF):
                    logging.info("Power Down")
                    self.os.powerDown()
                elif msg == chr(VPCD_CTRL_ON):
                    logging.info("Power Up")
                    self.os.powerUp()
                elif msg == chr(VPCD_CTRL_RESET):
                    logging.info("Reset")
                    self.os.reset()
                elif msg == chr(VPCD_CTRL_ATR):
                    #logging.info("ATR")
                    msg = self.os.getATR()
                    #logging.info("\nATR (%d bytes):\n%s", len(msg), hexdump(msg))
                    self.__sendToVPICC(msg)
                else:
                    logging.warning("unknown control command")
            else:
                if size != len(msg):
                    logging.warning("Expected %u bytes, but received only %u",
                                    size, len(msg))

                printer.show_command(msg)
                answer = self.os.execute(msg)
                printer.show_response(answer)
                self.__sendToVPICC(answer)

    def stop(self):
        self.sock.close()
        if self.server_sock:
            self.server_sock.close()


mitm = MITM('localhost', 35963, 2)

try:
    mitm.run()
except KeyboardInterrupt:
    pass
