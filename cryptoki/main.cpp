#include <iostream>
#include <cassert>
#include <pkcs11/cryptoki.h>
using namespace std;

void print(CK_RV ret) {
    cout << ret << '\n';
}

int main(int argc, char **argv) {
    CK_RV rv;

    cout << "Initialize\n";

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    cout << "OpenSession\n";

    CK_SESSION_HANDLE hSession;
    C_OpenSession(1, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
    assert(rv == CKR_OK);

    CK_UTF8CHAR userPIN[] = {"123456"};

    cout << "Login\n";

    rv = C_Login(hSession, CKU_USER, userPIN, sizeof(userPIN)-1);
    assert(rv == CKR_OK);

    /*
    cout << "FindObjects\n";

    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount;

    rv = C_FindObjectsInit(hSession, NULL_PTR, 0);
    assert(rv == CKR_OK);
    while (1) {
        rv = C_FindObjects(hSession, &hObject, 1, &ulObjectCount);
        if (rv != CKR_OK || ulObjectCount == 0)
            break;
        cout << "object " << hObject << "\n";
    }

    rv = C_FindObjectsFinal(hSession);
    assert(rv == CKR_OK);
    */

    cout << "GenerateKeyPair\n";

    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_ULONG modulusBits = 1024;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
    CK_BYTE id[] = { 123 };
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;

    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass)},
        {CKA_TOKEN, &val_true, sizeof(val_true)},
        {CKA_PRIVATE, &val_false, sizeof(val_false)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
        {CKA_ENCRYPT, &val_true, sizeof(val_true)},
        {CKA_VERIFY, &val_true, sizeof(val_true)},
        {CKA_VERIFY_RECOVER, &val_true, sizeof(val_true)},
        {CKA_WRAP, &val_true, sizeof(val_true)},
        {CKA_ID, id, sizeof(id)},
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass)},
        {CKA_TOKEN, &val_true, sizeof(val_true)},
        {CKA_PRIVATE, &val_true, sizeof(val_true)},
        {CKA_DECRYPT, &val_true, sizeof(val_true)},
        {CKA_SIGN, &val_true, sizeof(val_true)},
        {CKA_SIGN_RECOVER, &val_true, sizeof(val_true)},
        {CKA_UNWRAP, &val_true, sizeof(val_true)},
        {CKA_ID, id, sizeof(id)},
    };

    rv = C_GenerateKeyPair(hSession, &mechanism, publicKeyTemplate, 10,
        privateKeyTemplate, 8, &hPublicKey, &hPrivateKey);
    print(rv);
    assert(rv == CKR_OK);

    /*
    CK_OBJECT_HANDLE hWrappingKey = 4;
    CK_OBJECT_HANDLE hKey = 3;
    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS, NULL_PTR, 0
    };
    CK_BYTE wrappedKey[8];
    CK_ULONG ulWrappedKeyLen;

    ulWrappedKeyLen = sizeof(wrappedKey);
    rv = C_WrapKey(
        hSession, &mechanism,
        hWrappingKey, hKey,
        wrappedKey, &ulWrappedKeyLen);
    print(rv);
    assert(rv == CKR_OK);
    */

    cout << "Logout\n";

    rv = C_Logout(hSession);
    assert(rv == CKR_OK);

    cout << "CloseSession\n";

    rv = C_CloseSession(hSession);
    assert(rv == CKR_OK);

    cout << "Finalize\n";

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

    return 0;
}
