from __future__ import print_function
import logging

from Crypto.Cipher import AES, DES, DES3
from Crypto.Hash import SHA

from util import from_hex, to_hex_blocks, sxor, str8_to_int, int_to_str8


logger = logging.getLogger(__name__)


AES_KEY = "Yy32echR8gWImxqKKqxmIWg8Rhce23yY"

AES_CIPHERTEXT = from_hex("""
58 dc e2 03 c6 63 d1 ac
42 a0 e9 8e 70 32 a9 18
71 47 79 06 c5 6f 8b 76
41 f6 b8 be d1 20 f4 6a
""")

AES_IV = from_hex("""
c2 fd fa 6b 6f b4 87 38
07 89 10 40 6e d7 fa 2a
""")


CR_MAC_SEED = '\x00' * 8
CR_DES3_IV = '\x00' * 8


def pad(blocks):
    last_len = len(blocks) % 8
    blocks += "\x80" + "\x00" * (7 - last_len)
    return blocks


def des_cbc_mac(key, seed, data, header=''):
    cipher = DES.new(key[:8], DES.MODE_ECB)

    if header:
        header = pad(header)
    data = header + pad(data)

    xor = seed
    for i in range(0, len(data), 8):
        ciphertext = cipher.encrypt(xor)
        block = data[i:i + 8]
        xor = sxor(ciphertext, block)

    cipher = DES3.new(key[:16], DES3.MODE_ECB)
    return cipher.encrypt(xor)


class GemaltoCrypto(object):
    def __init__(self):
        self.static_key = None
        self.card_identifier = None

        self.cr_des3_key = None
        self.cr_mac_key = None
        
        self.card_challenge = None
        self.card_nonce = None

        self.lib_random = None
        self.lib_constant = None
        self.lib_nonce = None

        self.xor_nonce = None
        self.digest = None

        self.mac_counter = 0

        self.initialize_static_key()
        
    def initialize_static_key(self):
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        self.static_key = cipher.decrypt(AES_CIPHERTEXT)[:16]
        
    def parse_card_identifier(self, resp):
        self.card_identifier = resp[:-2]
        self.calc_cr_params()

    def make_card_identifier(self):
        return self.card_identifier + "\x90\x00"

    def calc_cr_params(self):
        card_identifier_rev = self.card_identifier[::-1]

        cipher1 = DES3.new(self.static_key, DES3.MODE_ECB)
        cipher2 = DES3.new(self.static_key[8:16] + self.static_key[:8], DES3.MODE_ECB)

        self.cr_des3_key = cipher1.encrypt(self.card_identifier) + cipher2.encrypt(self.card_identifier)
        self.cr_mac_key = cipher1.encrypt(card_identifier_rev) + cipher2.encrypt(card_identifier_rev)

        logger.info("cr des3 key\n%s", to_hex_blocks(self.cr_des3_key))
        logger.info("cr mac key\n%s", to_hex_blocks(self.cr_mac_key))

    def mac_cr(self, message):
        return des_cbc_mac(self.cr_mac_key, CR_MAC_SEED, message)

    def encrypt_cr(self, plaintext):
        return DES3.new(self.cr_des3_key, DES3.MODE_CBC, CR_DES3_IV).encrypt(plaintext)

    def decrypt_cr(self, ciphertext):
        return DES3.new(self.cr_des3_key, DES3.MODE_CBC, CR_DES3_IV).decrypt(ciphertext)

    def parse_card_challenge(self, resp):
        self.card_challenge = resp[:-2]

        logger.info("card challenge\n%s", to_hex_blocks(self.card_challenge))

    def make_card_challenge(self):
        return self.card_challenge + "\x90\x00"

    def parse_lib_challenge(self, msg):
        ciphertext = msg[5:-8]
        mac = msg[-8:]

        mac_valid = self.mac_cr(ciphertext) == mac
        logger.info("MAC valid: %s", mac_valid)

        msg_data = self.decrypt_cr(ciphertext)

        self.lib_random = msg_data[:16]
        challenge = msg_data[16:24]
        self.lib_constant = msg_data[24:32]
        self.lib_nonce = msg_data[32:64]

        logger.info("Challenge valid: %s", challenge == self.card_challenge)

        logger.info("lib random\n%s", to_hex_blocks(self.lib_random))
        logger.info("lib constant\n%s", to_hex_blocks(self.lib_constant))
        logger.info("lib nonce\n%s", to_hex_blocks(self.lib_nonce))

    def make_lib_challenge(self):
        data = self.lib_random + self.card_challenge + \
               self.lib_constant + self.lib_nonce
        ciphertext = self.encrypt_cr(data)
        return "\x80\x82\x00\x00\x48" + ciphertext + self.mac_cr(ciphertext)

    def parse_card_ch_response(self, msg):
        ciphertext = msg[:-10]
        mac = msg[-10:-2]

        mac_valid = self.mac_cr(ciphertext) == mac
        logger.info("MAC valid: %s", mac_valid)

        msg_data = self.decrypt_cr(ciphertext)

        params_valid = msg_data[:32] == self.card_challenge + \
                                        self.lib_constant + self.lib_random
        logger.info("Parameters valid: %s", params_valid)

        self.card_nonce = msg_data[32:64]
        logger.info("card nonce\n%s", to_hex_blocks(self.card_nonce))

    def make_card_ch_response(self):
        data = self.card_challenge + self.lib_constant + \
               self.lib_random + self.card_nonce
        ciphertext = self.encrypt_cr(data)
        return ciphertext + self.mac_cr(ciphertext) + "\x90\x00"

    def calc_mac_params(self):
        self.xor_nonce = sxor(self.card_nonce, self.lib_nonce) + "\x00\x00\x00\x02"
        self.digest = SHA.new(self.xor_nonce).digest()

        logger.info("xor nonce\n%s", to_hex_blocks(self.xor_nonce))
        logger.info("digest\n%s", to_hex_blocks(self.digest))

        self.mac_counter = 0

    def mac_data(self, data, header=''):
        init = self.card_challenge[4:8] + self.lib_random[4:8]
        seed = int_to_str8(str8_to_int(init) + self.mac_counter)
        return des_cbc_mac(self.digest, seed, data, header)

    def check_message_mac(self, msg):
        self.mac_counter += 1
        logger.info("MAC counter: %d", self.mac_counter)

        if len(msg) <= 5:
            return True

        header = msg[:4]
        data = msg[5:-10]
        mac = msg[-8:]

        calc_mac = self.mac_data(data, header)
        logger.info("Message MAC valid: %s", calc_mac == mac)
        return calc_mac == mac

    def check_response_mac(self, resp):
        if len(resp) <= 2:
            return True

        data = resp[:-12]
        mac = resp[-10:-2]

        calc_mac = self.mac_data(data)
        logger.info("Response MAC valid: %s", calc_mac == mac)
        return calc_mac == mac

    def make_message(self, data, header):
        self.mac_counter += 1
        logger.info("MAC counter: %d", self.mac_counter)

        rest = data + "\x8E\x08" + self.mac_data(data, header)
        return header + chr(len(rest)) + rest

    def make_response(self, data, ret):
        return data + "\x8E\x08" + self.mac_data(data) + ret
