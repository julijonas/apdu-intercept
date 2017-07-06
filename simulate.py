import socket
import sys
import logging
import atexit
import struct
import errno

from gemalto.gemalto_os import GemaltoOS
from apdu_printer import APDUPrinter


_Csizeof_short = len(struct.pack('h', 0))

VPCD_CTRL_LEN = 1
VPCD_CTRL_OFF = 0
VPCD_CTRL_ON = 1
VPCD_CTRL_RESET = 2
VPCD_CTRL_ATR = 4



class SimulatedGemaltoCard(object):
    def __init__(self, host, port):

        self.os = GemaltoOS()
        self.printer = APDUPrinter()

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
                    logging.info("-" * 70)
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

                self.printer.show_command(msg, 'User command')
                answer = self.os.execute(msg)
                self.printer.show_response(answer, 'Response')
                self.__sendToVPICC(answer)

    def stop(self):
        self.sock.close()
        if self.server_sock:
            self.server_sock.close()


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler(sys.stdout))
    logger.setLevel(logging.DEBUG)


    card = SimulatedGemaltoCard('localhost', 35963)
    card.run()
