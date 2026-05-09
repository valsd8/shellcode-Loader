#include "aes.hpp"

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

std::vector<BYTE> AESDecrypt(std::vector<BYTE> cipherText, std::vector<BYTE> key, std::vector<BYTE> iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData = 0, cbKeyObject = 0, cbBlockLen = 0;
    PBYTE pbKeyObject = NULL;
    std::vector<BYTE> plainText;

    // 1. Open Algorithm Provider (AES)
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);

    // 2. Set Chaining Mode (CBC)
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    // 3. Calculate/Allocate Key Object
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);

    // 4. Generate the Key from raw bytes
    BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key.data(), (ULONG)key.size(), 0);

    // 5. Determine the size of the decrypted buffer
    ULONG cbPlainText = 0;
    BCryptDecrypt(hKey, cipherText.data(), (ULONG)cipherText.size(), NULL, iv.data(), (ULONG)iv.size(), NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);

    plainText.resize(cbPlainText);

    // 6. Perform actual Decryption
    if (!NT_SUCCESS(BCryptDecrypt(hKey, cipherText.data(), (ULONG)cipherText.size(), NULL, iv.data(), (ULONG)iv.size(), plainText.data(), (ULONG)plainText.size(), &cbData, BCRYPT_BLOCK_PADDING))) {
        std::cerr << "Decryption failed\n";
    }

    // Cleanup
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);

    return plainText;
}