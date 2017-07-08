import PyKCS11.LowLevel
import binascii


PKCS11_MODULE = '/usr/lib/opensc-pkcs11.so'
PIN = "123456"
SLOT = 0

a = PyKCS11.LowLevel.CPKCS11Lib()
info = PyKCS11.LowLevel.CK_INFO()
slotInfo = PyKCS11.LowLevel.CK_SLOT_INFO()
session = PyKCS11.LowLevel.CK_SESSION_HANDLE()
sessionInfo = PyKCS11.LowLevel.CK_SESSION_INFO()
tokenInfo = PyKCS11.LowLevel.CK_TOKEN_INFO()
slotList = PyKCS11.LowLevel.ckintlist()

print(a.Load(PKCS11_MODULE))

a.C_GetSlotList(0, slotList)
slot = slotList[SLOT]


print("\tC_OpenSession(): " + hex(a.C_OpenSession(slot, PyKCS11.LowLevel.CKF_SERIAL_SESSION | PyKCS11.LowLevel.CKF_RW_SESSION, session)))
print("\t\tSession:" + str(session))
print("\tC_GetSessionInfo(): " + hex(a.C_GetSessionInfo(session, sessionInfo)))
print("\t\tSessionInfo: state=" + hex(sessionInfo.state) + ", flags=" + hex(sessionInfo.flags))

print("\tC_GetTokenInfo(): " + hex(a.C_GetTokenInfo(slot, tokenInfo)))
print("\t\tTokenInfo: Label=" + str(tokenInfo.GetLabel()) + ", ManufacturerID=" + str(tokenInfo.GetManufacturerID()))
print("\t\tTokenInfo: flags=" + hex(tokenInfo.flags) + ", Model=" + str(tokenInfo.GetModel()))

print("\tC_Login(): " + hex(a.C_Login(session, PyKCS11.LowLevel.CKU_USER, PIN)))

SearchResult = PyKCS11.LowLevel.ckobjlist(10)
SearchTemplate = PyKCS11.LowLevel.ckattrlist(1)
SearchTemplate[0].SetNum(PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY)
# SearchTemplate[1].SetBool(PyKCS11.LowLevel.CKA_TOKEN, True)

print("C_FindObjectsInit: " + hex(a.C_FindObjectsInit(session, SearchTemplate)))
print("C_FindObjects: " + hex(a.C_FindObjects(session, SearchResult)))
print("C_FindObjectsFinal: " + hex(a.C_FindObjectsFinal(session)))

key = SearchResult[0]

valTemplate = PyKCS11.LowLevel.ckattrlist(1)
valTemplate[0].SetType(PyKCS11.LowLevel.CKA_SENSITIVE)
print("C_GetAttributeValue(): " + hex(a.C_GetAttributeValue(session, key, valTemplate)))
print("CKA_ISSUER Len: ", valTemplate[0].GetLen())
print("C_GetAttributeValue(): " + hex(a.C_GetAttributeValue(session, key, valTemplate)))

binval = list(valTemplate[0].GetBin())
binval[0] = 0
valTemplate[0].SetBin(PyKCS11.LowLevel.CKA_SENSITIVE, binval)
binval = valTemplate[0].GetBin()
print("binval[0]=", binval[0])
print("C_SetAttributeValue(): " + hex(a.C_SetAttributeValue(session, key, valTemplate)))



valTemplate = PyKCS11.LowLevel.ckattrlist(1)
valTemplate[0].SetType(PyKCS11.LowLevel.CKA_SENSITIVE)
print("C_GetAttributeValue(): " + hex(a.C_GetAttributeValue(session, key, valTemplate)))
print("CKA_ISSUER Len: ", valTemplate[0].GetLen())
print("C_GetAttributeValue(): " + hex(a.C_GetAttributeValue(session, key, valTemplate)))

binval = list(valTemplate[0].GetBin())
print("binval[0]=", binval[0])




for x in SearchResult:
    print("object " + hex(x.value()))
    # valTemplate = PyKCS11.LowLevel.ckattrlist(1)
    # valTemplate[0].SetType(PyKCS11.LowLevel.CKA_ISSUER)
    # # valTemplate[0].Reserve(128)
    # print("C_GetAttributeValue(): " + hex(a.C_GetAttributeValue(session, x, valTemplate)))
    # print("CKA_ISSUER Len: ", valTemplate[0].GetLen())
    # print("C_GetAttributeValue(): " + hex(a.C_GetAttributeValue(session, x, valTemplate)))
    # binval = list(valTemplate[0].GetBin())
    # print("binval=", binval)
    # binval[0] = 0
    # valTemplate[0].SetBin(PyKCS11.LowLevel.CKA_ISSUER, binval)
    # binval = valTemplate[0].GetBin()  # list(valTemplate[0].GetBin())
    # print("binval[0]=", binval[0])
    # #binval[0] = 0
    #
    # print("C_SetAttributeValue(): " + hex(a.C_SetAttributeValue(session, x, valTemplate)))


print("\tC_Logout(): " + hex(a.C_Logout(session)))
print("\tC_CloseSession(): " + hex(a.C_CloseSession(session)))


print("C_Finalize(): " + hex(a.C_Finalize()))

print(a.Unload())

# pkcs11.load(pkcs11dll_filename=PKCS11_MODULE)
#
# slot = pkcs11.getSlotList()[0]
#
# session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
# session.login("123456")
#
# # "Hello world" in hex
# message = "48656c6c6f20776f726c640d0a"
#
# objects = session.findObjects()
#
# print("Found %d objects: %s" % (len(objects), [x.value() for x in objects]))
#
# obj = objects[0]
#
# session.__setattr__()
#
# print(obj.setAttribute)
#
# all_attributes = list(PyKCS11.CKA.keys())
#
# print(all_attributes)
#
# # get first public and private keys
# # pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY)])[0]
# # privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY)])[0]
# # enc = session.encrypt(pubKey, binascii.unhexlify(message))
# # dec = session.decrypt(privKey, enc)
# #
# # print("\nmessage: " + message)
# # print("\nencrypted: " + binascii.hexlify(bytearray(enc)))
# # print("\ndecrypted: " + bytearray(dec))
#
# # logout
# session.logout()
# session.closeSession()
