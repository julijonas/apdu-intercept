import binascii

from PyKCS11 import *
from PyKCS11.LowLevel import *

#pkcs11_module = '/usr/lib/ClassicClient/libgclib.so'
pkcs11_module = '/usr/lib/ClassicClient/libgck2015x.so'

pkcs11_pin = '123456'

pkcs11 = PyKCS11Lib()
pkcs11.load(pkcs11_module)

slot = pkcs11.getSlotList()[0]
session = pkcs11.openSession(slot, CKF_RW_SESSION)
session.login(pkcs11_pin)

# with open('/home/julijonas/yubikey/files/private01.pem', 'rb') as f:
#     private = f.read()
#
# objectTemplate = [
#     (CKA_CLASS, CKO_PRIVATE_KEY),
#     (CKA_KEY_TYPE, CKK_RSA),
#     (CKA_WRAP, CK_TRUE),
#     (CKA_MODULUS, private)
# ]
#
#
# handle = session.createObject(objectTemplate)

public_keys = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY)])
private_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY)])

secret_pub = public_keys[0]
secret_priv = private_keys[0]

wrapper_pub = public_keys[1]
wrapper_priv = private_keys[1]

print(type(wrapper_pub))


data = session.wrapKey(wrapper_pub, secret_priv)

print(''.join(chr(i) for i in data))



# key_label = 'wrapper'
# key_id = 0x02
#
# pubTemplate = [
#     (CKA_CLASS, CKO_PUBLIC_KEY),
#     (CKA_TOKEN, CK_TRUE),
#     (CKA_PRIVATE, CK_FALSE),
#     (CKA_MODULUS_BITS, 1024),
#     (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
#     (CKA_ENCRYPT, CK_TRUE),
#     (CKA_VERIFY, CK_TRUE),
#     (CKA_VERIFY_RECOVER, CK_TRUE),
#     (CKA_WRAP, CK_TRUE),
#     (CKA_LABEL, key_label),
#     (CKA_ID, (key_id,))
# ]
#
# privTemplate = [
#     (CKA_CLASS, CKO_PRIVATE_KEY),
#     (CKA_TOKEN, CK_TRUE),
#     (CKA_PRIVATE, CK_TRUE),
#     (CKA_DECRYPT, CK_TRUE),
#     (CKA_SIGN, CK_TRUE),
#     (CKA_SIGN_RECOVER, CK_TRUE),
#     (CKA_UNWRAP, CK_TRUE),
#     (CKA_LABEL, key_label),
#     (CKA_ID, (key_id,))
# ]
#
# (pubKey, privKey) = session.generateKeyPair(pubTemplate, privTemplate)


#
# message = 'Hello, world'
#
# enc = 'c04b9d636152c29764237ae4b49a9ef475640bcd6cc9488978a2dfc0a3dde36583c008ca2626e508c0fea5f2dce79061c901de3e2e85ba50f73b337c3a71cb5b2c0666978dbfcbb0451d5d6750f54230cf24e8a55626f96c88fc12f4673f344b25fb1153b426abf4b4dc0d4f8b31179f674b234ad1bf42327310470f876e88f250cf6f748418f641b04dc17584ca8edbbd8cb2b16d6fde38847e02ad084960a585032029fa4953d38c6ce12ceef47713b10f2452321477c666f1825cf4df7d0caec277a43358f9cab4b3e04e9bd57de81db4399677b57e82e5cebb49235a1f7de713f5bb1e5cac3e72c8934e28f3c54d8d067c77b29f7bb9c6770c191b707c42'.decode('hex')
#
# # enc = session.encrypt(pubKey, message)
# dec = session.decrypt(privKey, enc)
#
# print("\nmessage: " + message)
# # print("\nencrypted: " + bytearray(enc))
# # print(binascii.hexlify(bytearray(enc)))
# print("\ndecrypted: " + bytearray(dec))
# print(binascii.hexlify(bytearray(dec)))


session.logout()
session.closeSession()

